// hubchecker_api.h
// Drop-in header to report HubChecker scan progress to the dashboard.
// Include this in HubChecker_merged.cpp and call the functions below.
//
// Requires: winhttp.lib (already linked in the merged file)

#pragma once
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <sstream>

// ── CONFIGURE THESE ──────────────────────────────────────────────────────────
// The URL of your running Flask dashboard (no trailing slash)
static const std::string DASHBOARD_URL = "https://hub-checker.vercel.app";

// Global scan key — populated by DashboardStart(), used by all other calls.
static std::string g_dashScanKey;
// ─────────────────────────────────────────────────────────────────────────────

// Internal HTTP POST helper (plain JSON, no auth header needed for scanner API)
static bool _DashPost(const std::string& path, const std::string& json) {
    // Parse host from DASHBOARD_URL
    std::string host = DASHBOARD_URL;
    bool useHttps = false;
    if (host.substr(0, 8) == "https://") { useHttps = true; host = host.substr(8); }
    else if (host.substr(0, 7) == "http://") host = host.substr(7);

    INTERNET_PORT port = useHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    size_t colonPos = host.find(':');
    if (colonPos != std::string::npos) {
        port = (INTERNET_PORT)std::stoi(host.substr(colonPos + 1));
        host = host.substr(0, colonPos);
    }

    std::wstring wHost(host.begin(), host.end());
    std::wstring wPath(path.begin(), path.end());

    HINTERNET hSession = WinHttpOpen(L"HubChecker/1.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME,
                                      WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    DWORD flags = useHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(),
                                             NULL, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    WinHttpAddRequestHeaders(hRequest,
        L"Content-Type: application/json\r\n",
        (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    bool ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                  (LPVOID)json.c_str(), (DWORD)json.size(),
                                  (DWORD)json.size(), 0) &&
              WinHttpReceiveResponse(hRequest, NULL);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok;
}

// Simple JSON string escaper
static std::string _JEsc(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out += c;
    }
    return out;
}

// ── PUBLIC API ────────────────────────────────────────────────────────────────

/**
 * Call ONCE at the very start of main() to register the scan with the dashboard.
 * Populates g_dashScanKey which is used by all subsequent calls.
 *
 *   DashboardStart("JOHNS-PC", "JOHN", "Windows 10 22H2");
 */
static void DashboardStart(const std::string& desktopName,
                            const std::string& hostname,
                            const std::string& username,
                            const std::string& osVersion = "") {
    // Generate a random key if not provided
    char buf[17]; srand((unsigned)GetTickCount64());
    for (int i = 0; i < 16; i++)
        buf[i] = "0123456789abcdef"[rand() % 16];
    buf[16] = '\0';
    g_dashScanKey = buf;

    std::string json =
        "{\"scan_key\":\"" + g_dashScanKey + "\","
        "\"desktop_name\":\"" + _JEsc(desktopName) + "\","
        "\"hostname\":\"" + _JEsc(hostname) + "\","
        "\"username\":\"" + _JEsc(username) + "\","
        "\"os_version\":\"" + _JEsc(osVersion) + "\"}";

    _DashPost("/api/scanner/start", json);
}

/**
 * Report scan phase progress. Call this whenever a new scan phase begins.
 *
 *   DashboardProgress(3, "Prefetch Scan", 15, "Scanning C:\\Windows\\Prefetch");
 */
static void DashboardProgress(int phaseIndex,
                               const std::string& phaseName,
                               int pct,
                               const std::string& message = "") {
    if (g_dashScanKey.empty()) return;
    std::string json =
        "{\"scan_key\":\"" + g_dashScanKey + "\","
        "\"phase_index\":" + std::to_string(phaseIndex) + ","
        "\"phase_name\":\"" + _JEsc(phaseName) + "\","
        "\"pct\":" + std::to_string(pct) + ","
        "\"message\":\"" + _JEsc(message) + "\"}";
    _DashPost("/api/scanner/progress", json);
}

/**
 * Report a suspicious finding.
 * severity: "info" | "warn" | "alert"
 *
 *   DashboardFinding("Signature Alert", "alert",
 *       "[Prefetch] xeno.exe — Cheat Signature, Path: C:\\Users\\...");
 */
static void DashboardFinding(const std::string& category,
                              const std::string& severity,
                              const std::string& detail) {
    if (g_dashScanKey.empty()) return;
    std::string json =
        "{\"scan_key\":\"" + g_dashScanKey + "\","
        "\"category\":\"" + _JEsc(category) + "\","
        "\"severity\":\"" + _JEsc(severity) + "\","
        "\"detail\":\"" + _JEsc(detail) + "\"}";
    _DashPost("/api/scanner/finding", json);
}

/**
 * Call ONCE when the scan is fully done.
 *
 *   DashboardComplete();
 */
static void DashboardComplete() {
    if (g_dashScanKey.empty()) return;
    std::string json = "{\"scan_key\":\"" + g_dashScanKey + "\"}";
    _DashPost("/api/scanner/complete", json);
}

// ── USAGE EXAMPLE (add these calls into HubChecker_merged.cpp main()) ────────
//
//  int main() {
//      // ... existing init code ...
//
//      DashboardStart(WtoS(desktopName.c_str()), WtoS(hostname.c_str()),
//                     WtoS(username.c_str()), WtoS(osVersion.c_str()));
//
//      // Phase 0 — Initializing
//      DashboardProgress(0, "Initializing", 2);
//
//      // ... after USN journal scan starts:
//      DashboardProgress(1, "USN Journal Scan", 8);
//
//      // ... when a cheat file is found:
//      DashboardFinding("Signature Alert", "alert",
//                       "[USN] xeno.exe — Cheat Signature | Path: " + foundPath);
//
//      // ... each subsequent phase uses DashboardProgress(phaseIndex, phaseName, pct)
//      // with phaseIndex matching the SCAN_PHASES array in app.py
//
//      // At the very end:
//      DashboardComplete();
//  }
