import os
import re
import sys
import json
import struct
import ctypes
import winreg
import hashlib
import zipfile
import threading
import subprocess
from datetime import datetime, timedelta

import psutil
import requests
import customtkinter as ctk
from PIL import Image

# ════════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

# ── Colours ───────────────────────────────────────────────────────────────────
TRINITY              = "#FFFFFF"
TRINITY_DARK         = "#0D0D0D"
TRINITY_SURFACE      = "#1A1A1A"
TRINITY_CARD         = "#222222"
TRINITY_BORDER       = "#2E2E2E"
TRINITY_ACCENT       = "#5865F2"
TRINITY_ACCENT_HOVER = "#4752C4"
TRINITY_TEXT         = "#FFFFFF"
TRINITY_TEXT_SECONDARY = "#A0A0A0"
TRINITY_MUTED        = "#555555"

# ── External ──────────────────────────────────────────────────────────────────
TRINITY_API_URL  = ""
TRINITY_DISCORD  = ""
DISCORD_EPOCH    = 1420070400000

# ── Cheat keywords ────────────────────────────────────────────────────────────
CHEAT_KEYWORDS = [
    "synapse", "krnl", "fluxus", "scriptware", "hydrogen",
    "wave", "oxygen", "arceus", "hydroxide", "celery",
    "trigon", "comet", "electron", "delta", "vega",
    "macsploit", "xeno", "evon", "codex", "calamari",
    "executor", "inject", "robloxplayerexecutor",
    "dansploit", "coco", "sirhurt", "proxo", "jjsploit",
    "exploit", "cheat", "hack",
]
CHEAT_KEYWORDS_LOWER = [k.lower() for k in CHEAT_KEYWORDS]
CHEAT_KEYWORDS_SET   = set(CHEAT_KEYWORDS_LOWER)
CHEAT_FILE_EXTENSIONS = [".dll", ".exe", ".lua", ".luac"]
CHEAT_SHA1_HASHES    = []

# ── Lua bytecode magic bytes ──────────────────────────────────────────────────
LUA_BYTECODE_SIGS = [
    b"LuaQ",       # Lua 5.1
    b"LuaR",       # Lua 5.2
    b"LuaS",       # Lua 5.3
    b"LuaT",       # Lua 5.4
    b"luaCxV8U8",
]

# ── Executor-exclusive API strings ────────────────────────────────────────────
EXECUTOR_API_STRINGS = [
    "hookfunction", "getrawmetatable", "newcclosure", "checkcaller",
    "getnamecallmethod", "setreadonly", "isexecutorclosure", "getgenv",
    "getrenv", "getsenv", "getinstances", "gethui", "decompile",
    "getscripts", "getloadedmodules", "firetouchinterest",
    "fireproximityprompt", "getcallingscript",
]

# ── URL patterns ──────────────────────────────────────────────────────────────
DISCORD_URL_REGEX = (
    r"https?://cdn\.discordapp\.com/attachments/\d+/\d+/"
    r"[^\s\"'<>)\]\x00-\x1f]+"
)
SUSPICIOUS_URL_REGEX = (
    r"https?://(?:pastebin\.com|hastebin\.com|raw\.githubusercontent\.com"
    r"|cdn\.discordapp\.com|media\.discordapp\.net|paste\.ee|ghostbin\.com"
    r"|rentry\.co|raw\.github\.com|gist\.githubusercontent\.com)"
    r"[^\s\"'<>\x00-\x1f]+"
)

# ── Paths ─────────────────────────────────────────────────────────────────────
PREFETCH_DIR          = r"C:\Windows\Prefetch"
AMCACHE_HIVE          = r"C:\Windows\AppCompat\Programs\Amcache.hve"
SHIMCACHE_SYSTEM_HIVE = r"C:\Windows\System32\config\SYSTEM"
DEFENDER_FILENAME     = r"Microsoft-Windows-Windows Defender%4Operational.evtx"
SRUM_DATABASE_PATH    = r"C:\Windows\System32\sru\SRUDB.dat"

TEMP              = os.getenv("TEMP", os.getenv("TMP", "C:\\Temp"))
AMCACHE_CSV_DIR   = os.path.join(TEMP, "AmcacheCSV")
SHIMCACHE_CSV_DIR = os.path.join(TEMP, "ShimcacheCSV")
SRUM_CSV_DIR      = os.path.join(TEMP, "SrumCSV")

AMCACHE_ZIP_URL   = "https://download.ericzimmermanstools.com/AmcacheParser.zip"
SHIMCACHE_ZIP_URL = "https://download.ericzimmermanstools.com/AppCompatCacheParser.zip"
SRUM_ZIP_URL      = "https://download.ericzimmermanstools.com/SrumECmd.zip"

TARGET_AMCACHE_FILES = [
    "amcache_UnassociatedFileEntries.csv",
    "amcache_AssociatedFileEntries.csv",
    "amcache_ShortCuts.csv",
]
TARGET_SHIMCACHE_FILES = ["shimcache.csv"]
TARGET_SRUM_FILES = [
    "SrumECmd_AppResourceUseInfo_Output.csv",
    "SrumECmd_AppTimelineProvider_Output.csv",
]

# ════════════════════════════════════════════════════════════════════════════════
#  DETECTION RESULT STRUCTURE  (detections.py)
# ════════════════════════════════════════════════════════════════════════════════

class CliDetectionResult:
    def __init__(self):
        self.cheat_scan = {
            "robloxMemory":    None,
            "injectedModules": None,
            "prefetchModules": None,
            "robloxLogs":      None,
            "robloxFlags":     None,
            "discordMemory":   None,
            "robloxAccounts":  None,
            "discordAccounts": None,
        }
        self.advanced_scan = {
            "amcache":            None,
            "shimcache":          None,
            "srum":               None,
            "prefetchIntegrity":  None,
            "amcacheIntegrity":   None,
            "shimcacheIntegrity": None,
            "srumIntegrity":      None,
            "defender":           None,
            "auditPolicy":        None,
            "registryActivity":   None,
            "recentItems":        None,
            "shellbags":          None,
            "userassist":         None,
            "bamDetection":       None,
            "customDetections":   None,
            "deletedCheats":      None,
            "deletedPrefetch":    None,
            "usnActivity":        None,
            "mftActivity":        None,
        }
        self.discord_variants      = []
        self.discord_names         = []
        self.discord_content       = []
        self.appcompat_detections  = []
        self.cache_detections      = []
        self.ua_detections         = []
        self.cheat_hits            = []
        self.cheat_entries         = []
        self.found_cheats          = []
        self.deleted_cheat_hits    = []
        self.deleted_prefetch_hits = []
        self.injected              = []
        self.injection_crash       = False
        self.lua_bytecode          = False
        self.roblox_flags          = []
        self.roblox_accounts       = []
        self.roblox_logs           = []
        self.discord_accounts      = []
        self.files_scanned         = 0
        self.matched_keywords      = []
        self.keywords_lower        = []

    def to_json(self):
        return json.dumps({
            "cheatScan":    self.cheat_scan,
            "advancedScan": self.advanced_scan,
        }, indent=2, default=str)


# ════════════════════════════════════════════════════════════════════════════════
#  SCANNER  (scanner.py)
# ════════════════════════════════════════════════════════════════════════════════

# ── Helpers ───────────────────────────────────────────────────────────────────
def _keyword_hit(text):
    t = text.lower()
    return any(kw in t for kw in CHEAT_KEYWORDS_LOWER)


def _download_and_extract(url, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    fname    = url.split("/")[-1]
    zip_path = os.path.join(dest_dir, fname)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    with open(zip_path, "wb") as f:
        f.write(r.content)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(dest_dir)


def download_and_extract_amcache():
    _download_and_extract(AMCACHE_ZIP_URL, AMCACHE_CSV_DIR)

def download_and_extract_shimcache():
    _download_and_extract(SHIMCACHE_ZIP_URL, SHIMCACHE_CSV_DIR)

def download_and_extract_srum():
    _download_and_extract(SRUM_ZIP_URL, SRUM_CSV_DIR)

def find_amcacheparser():
    exe = os.path.join(AMCACHE_CSV_DIR, "AmcacheParser.exe")
    if not os.path.exists(exe):
        download_and_extract_amcache()
    return exe

def find_shimcacheparser():
    exe = os.path.join(SHIMCACHE_CSV_DIR, "AppCompatCacheParser.exe")
    if not os.path.exists(exe):
        download_and_extract_shimcache()
    return exe

def find_srumparser():
    exe = os.path.join(SRUM_CSV_DIR, "SrumECmd.exe")
    if not os.path.exists(exe):
        download_and_extract_srum()
    return exe

def ensure_amcacheparser_exe():  return find_amcacheparser()
def ensure_shimcacheparser_exe(): return find_shimcacheparser()
def ensure_srumparser_exe():     return find_srumparser()

def cleanup_srum_csv_dir():
    import shutil
    if os.path.isdir(SRUM_CSV_DIR):
        shutil.rmtree(SRUM_CSV_DIR, ignore_errors=True)


# ── Registry helpers ──────────────────────────────────────────────────────────
def read_registry_keys(hive, path):
    result = {}
    try:
        key = winreg.OpenKey(hive, path)
        i = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(key, i)
                result[name]  = data
                i += 1
            except OSError:
                break
    except OSError:
        pass
    return result


def get_roblox_profile_urls_from_registry():
    """Get Roblox profile URLs from rbxRecentFiles registry keys (Roblox Studio)."""
    urls = []
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Roblox\RobloxStudio")
        i = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(key, i)
                if isinstance(data, str):
                    m = re.search(r"https://www\.roblox\.com/games/(\d+)", data)
                    if m:
                        urls.append(f"PlaceID: https://www.roblox.com/games/{m.group(1)}")
                i += 1
            except OSError:
                break
    except OSError:
        pass
    return urls


# ── Roblox helpers ────────────────────────────────────────────────────────────
def find_roblox_processes():
    """Return list of (pid, name) for all running RobloxPlayerBeta processes."""
    found = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if "robloxplayerbeta" in proc.info["name"].lower():
                found.append((proc.info["pid"], proc.info["name"]))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return found


def get_roblox_ids_from_local_storage():
    """Extract Roblox user IDs from GUAC keys in Roblox LocalStorage files."""
    ids = []
    path = os.path.join(os.getenv("LOCALAPPDATA", ""), "roblox", "LocalStorage")
    if not os.path.isdir(path):
        return ids
    for fname in os.listdir(path):
        try:
            with open(os.path.join(path, fname), "rb") as f:
                data = f.read().decode("utf-8", errors="ignore")
            for m in re.findall(r"https://www\.roblox\.com/users/(\d+)", data):
                if m not in ids:
                    ids.append(m)
        except Exception:
            pass
    return ids


def fetch_roblox_logs():
    """Fetch and return Roblox log file contents for cheat flag analysis."""
    log_dir = os.path.join(os.getenv("LOCALAPPDATA", ""), "roblox", "logs")
    results = []
    if not os.path.isdir(log_dir):
        return results

    def process_file(p):
        try:
            with open(p, "r", errors="ignore") as f:
                return f.read()
        except Exception:
            return ""

    log_files = sorted(
        [f for f in os.listdir(log_dir) if f.endswith("_last.log")],
        key=lambda f: os.path.getmtime(os.path.join(log_dir, f)),
        reverse=True,
    )
    for lf in log_files[:5]:
        c = process_file(os.path.join(log_dir, lf))
        if c:
            results.append(c)
    return results


def get_roblox_logs():
    try:
        return fetch_roblox_logs()
    except Exception as e:
        return [f"Roblox logs error: {e}"]


# ── Memory scanning ───────────────────────────────────────────────────────────
def scan_roblox_memory():
    """
    Scan RobloxPlayerBeta.exe memory for:
      - Executor-exclusive Lua API strings (hookfunction, getrawmetatable, etc.)
      - Lua bytecode signature (injected compiled scripts)
      - Suspicious download URLs (pastebin, raw.github, discord CDN)
      - Manually mapped PEs that never touch the module list at all
    """
    procs = find_roblox_processes()
    if not procs:
        return "Roblox Memory: No running Roblox process found"

    report_lines = []
    try:
        PROCESS_VM_READ    = 0x0010
        PROCESS_QUERY_INFO = 0x0400
        kernel32 = ctypes.windll.kernel32

        for pid, _ in procs:
            handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFO, False, pid)
            if not handle:
                continue
            try:
                addr = 0
                while addr < 0x7FFFFFFFFFFF:
                    mbi  = ctypes.create_string_buffer(48)
                    size = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr), mbi, 48)
                    if not size:
                        break
                    base    = struct.unpack_from("<Q", mbi, 0)[0]
                    reg_sz  = struct.unpack_from("<Q", mbi, 16)[0]
                    state   = struct.unpack_from("<I", mbi, 32)[0]
                    protect = struct.unpack_from("<I", mbi, 36)[0]
                    mtype   = struct.unpack_from("<I", mbi, 40)[0]

                    if state == 0x1000 and protect in (0x10, 0x20, 0x40, 0x80):
                        buf  = ctypes.create_string_buffer(min(reg_sz, 0x100000))
                        read = ctypes.c_size_t(0)
                        if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(base),
                                                       buf, len(buf), ctypes.byref(read)):
                            chunk = buf.raw[:read.value]
                            for sig in LUA_BYTECODE_SIGS:
                                if sig in chunk:
                                    report_lines.append(
                                        f"Lua bytecode signature found at 0x{base:X} "
                                        f"(PID {pid}): injected compiled script detected"
                                    )
                                    break
                            text = chunk.decode("utf-8", errors="ignore")
                            for api in EXECUTOR_API_STRINGS:
                                if api in text:
                                    report_lines.append(
                                        f"Executor API strings found in Roblox memory: {api} (PID {pid})"
                                    )
                            for url in re.findall(SUSPICIOUS_URL_REGEX, text):
                                report_lines.append(f"Suspicious URLs in Roblox memory: {url}")
                        if mtype == 0x20000:
                            report_lines.append(
                                f"Manually mapped PE in Roblox (PID {pid}) at 0x{base:X}"
                            )
                    addr = base + reg_sz
            finally:
                kernel32.CloseHandle(handle)
    except Exception as e:
        return f"Roblox memory scan error: {e}"

    return "\n".join(report_lines) if report_lines else "Roblox Memory: No cheat signatures found"


def check_roblox_injected_modules():
    """
    Check for injection anomalies in Roblox processes.
    Flags RobloxPlayerExecutor.dll, unsigned DLLs, suspicious path DLLs.
    """
    procs = find_roblox_processes()
    if not procs:
        return "Injected Modules: No running Roblox process found"

    injected = []
    for pid, _ in procs:
        try:
            proc = psutil.Process(pid)
            for mmap in proc.memory_maps(grouped=False):
                pl = mmap.path.lower()
                if "robloxplayerexecutor" in pl:
                    try:
                        ts = datetime.fromtimestamp(
                            os.path.getmtime(mmap.path)
                        ).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        ts = "unknown"
                    injected.append(
                        f"Found: RobloxPlayerExecutor.dll in prefetch | Modified: {ts}"
                    )
                if (pl.endswith(".dll")
                        and "roblox" not in pl
                        and "windows" not in pl
                        and "system32" not in pl):
                    injected.append(f"Unsigned DLL in Roblox (PID {pid}): {mmap.path}")
                if any(p in pl for p in ["\\temp\\", "\\downloads\\"]):
                    injected.append(f"Suspicious path DLL in Roblox (PID {pid}): {mmap.path}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            injected.append(f"Injection crash detected | {e}")

    return ("Injected Modules:\n" + "\n".join(injected)) if injected \
        else "Injected Modules: No suspicious DLLs found in Roblox"


# ── Discord memory scan ───────────────────────────────────────────────────────
def scan_discord_memory():
    """Scan Discord/browser memory for suspicious download URLs."""
    discord_exes = {"discord.exe", "discordcanary.exe", "discordptb.exe"}
    found_urls   = []
    kernel32     = ctypes.windll.kernel32

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"].lower() not in discord_exes:
                continue
            pid    = proc.info["pid"]
            handle = kernel32.OpenProcess(0x0010 | 0x0400, False, pid)
            if not handle:
                continue
            try:
                addr = 0
                while addr < 0x7FFFFFFFFFFF:
                    mbi  = ctypes.create_string_buffer(48)
                    size = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr), mbi, 48)
                    if not size:
                        break
                    base   = struct.unpack_from("<Q", mbi, 0)[0]
                    reg_sz = struct.unpack_from("<Q", mbi, 16)[0]
                    state  = struct.unpack_from("<I", mbi, 32)[0]
                    if state == 0x1000 and reg_sz < 0x500000:
                        buf  = ctypes.create_string_buffer(reg_sz)
                        read = ctypes.c_size_t(0)
                        if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(base),
                                                       buf, reg_sz, ctypes.byref(read)):
                            text = buf.raw[:read.value].decode("utf-8", errors="ignore")
                            for url in re.findall(SUSPICIOUS_URL_REGEX, text):
                                if url not in found_urls:
                                    found_urls.append(url)
                    addr = base + reg_sz
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            pass

    if not found_urls:
        return "No Discord or browser processes found"
    return "Suspicious URLs in Roblox memory:\n" + "\n".join(found_urls)


def get_discord_accounts_from_storage():
    """Scan local Discord storage for account tokens/IDs."""
    accounts = []
    appdata  = os.getenv("APPDATA", "")
    for variant in ["discord", "discordcanary", "discordptb"]:
        ldb = os.path.join(appdata, variant, "Local Storage", "leveldb")
        if os.path.isdir(ldb):
            accounts.append(f"{variant}: {ldb}")
    return accounts


# ── Prefetch ──────────────────────────────────────────────────────────────────
def _get_windows_install_date():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        val, _ = winreg.QueryValueEx(key, "InstallDate")
        return datetime.fromtimestamp(val).strftime("%Y-%m-%d")
    except Exception:
        return None


def check_prefetch_integrity():
    """Detect prefetch manipulation by checking .pf file count vs install date."""
    try:
        if not os.path.isdir(PREFETCH_DIR):
            return "Prefetch CLEARED: Prefetch directory does not exist"
        pf = [f for f in os.listdir(PREFETCH_DIR) if f.endswith(".pf")]
        if not pf:
            d = _get_windows_install_date()
            return f"Prefetch CLEARED: No .pf files found (Windows installed {d})"
        if len(pf) < 5:
            oldest = min(os.path.getmtime(os.path.join(PREFETCH_DIR, f)) for f in pf)
            ts     = datetime.fromtimestamp(oldest).strftime("%Y-%m-%d %H:%M:%S")
            return (f"Prefetch CLEARED: Only {len(pf)} .pf files found "
                    f"but oldest prefetch file is {ts}")
        return f"Prefetch OK: {len(pf)} files found"
    except PermissionError:
        return "Prefetch Integrity: Access denied (requires administrator)"
    except Exception as e:
        return f"Prefetch Integrity: Could not read prefetch directory ({e})"


def scan_roblox_prefetch_modules():
    """Scan for cheat-related entries in Roblox prefetch files."""
    hits = []
    if not os.path.isdir(PREFETCH_DIR):
        return hits
    for fname in os.listdir(PREFETCH_DIR):
        fl = fname.lower()
        if any(kw in fl for kw in CHEAT_KEYWORDS_LOWER):
            hits.append(fname)
        if "robloxplayerexecutor" in fl:
            try:
                ts = datetime.fromtimestamp(
                    os.path.getmtime(os.path.join(PREFETCH_DIR, fname))
                ).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                ts = "unknown"
            hits.append(f"Found: RobloxPlayerExecutor.dll in prefetch | Modified: {ts}")
    return hits


def run_pecmd_scan():
    """Run PECmd to parse prefetch and scan output for cheat keywords."""
    try:
        result = subprocess.run(
            ["PECmd.exe", "-d", PREFETCH_DIR, "--json", AMCACHE_CSV_DIR],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return "PECmd scan failed."
        return filter_prefetch_json_for_cheats(
            os.path.join(AMCACHE_CSV_DIR, "prefetch.json")
        )
    except Exception:
        return "PECmd scan failed."


def filter_prefetch_json_for_cheats(path):
    """Parse prefetch JSON and filter entries containing cheat keywords."""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        hits = [e for e in data if _keyword_hit(str(e))]
        return ("Prefetch Cheat Hits:\n" + "\n".join(str(h) for h in hits)) if hits \
            else "No Prefetch Cheat Hits Found."
    except Exception:
        return "No Prefetch Cheat Hits Found."


# ── AmCache ───────────────────────────────────────────────────────────────────
def run_amcache_scan():
    try:
        exe = ensure_amcacheparser_exe()
        subprocess.run([exe, "-f", AMCACHE_HIVE, "--csv", AMCACHE_CSV_DIR],
                       capture_output=True, timeout=120)
        return scan_all_amcache_csvs()
    except Exception as e:
        return f"AmCache CSV directory not found: {e}", False


def scan_all_amcache_csvs():
    if not os.path.isdir(AMCACHE_CSV_DIR):
        return "AmCache CSV directory not found.", False
    return scan_amcache_csv_for_keywords(AMCACHE_CSV_DIR)


def scan_amcache_csv_for_keywords(csv_dir):
    """Scan AmCache CSVs for cheat keywords. Returns (report_string, has_hits)."""
    hits = []
    for fname in TARGET_AMCACHE_FILES:
        fpath = os.path.join(csv_dir, fname)
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if _keyword_hit(line):
                        hits.append(line.strip())
        except Exception:
            pass
    if hits:
        return ("AppCompat Detection (Execution Evidence):\n"
                + "\n".join(hits)
                + f"\n{len(hits)} total keyword match(es) found across AmCache"), True
    return "OVERALL RESULT: No cheat keywords detected in any CSV files.", False


def format_amcache_hits(hits):
    return "Cache Detection (Recent Launch History):\n" + "\n".join(hits) if hits \
        else "No keyword matches found."


def check_amcache_integrity():
    """Check if amcache.hve was modified in the last 20 minutes."""
    if not os.path.exists(AMCACHE_HIVE):
        return "Amcache.hve not found"
    try:
        mtime = os.path.getmtime(AMCACHE_HIVE)
        size  = os.path.getsize(AMCACHE_HIVE)
        ts    = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        age_m = (datetime.now().timestamp() - mtime) / 60
        rep   = (f"Amcache Integrity Check:\n"
                 f"Amcache.hve last modified: {ts}\n"
                 f"Amcache.hve size: {size} bytes")
        if age_m < 20:
            rep += f"\nSUSPICIOUS: Amcache.hve modified {age_m:.1f} minutes ago"
        return rep
    except Exception as e:
        return f"Error checking amcache.hve: {e}"


# ── ShimCache ─────────────────────────────────────────────────────────────────
def run_shimcache_scan():
    try:
        exe = ensure_shimcacheparser_exe()
        subprocess.run([exe, "-f", SHIMCACHE_SYSTEM_HIVE, "--csv", SHIMCACHE_CSV_DIR],
                       capture_output=True, timeout=120)
        return scan_all_shimcache_csvs()
    except Exception as e:
        return f"Shimcache scan error: {e}", False


def scan_all_shimcache_csvs():
    if not os.path.isdir(SHIMCACHE_CSV_DIR):
        return "AmCache CSV directory not found.", False
    return scan_shimcache_csv_for_keywords(SHIMCACHE_CSV_DIR)


def scan_shimcache_csv_for_keywords(csv_dir):
    """Scan Shimcache CSVs for cheat keywords. Returns (report_string, has_hits)."""
    hits = []
    for fname in TARGET_SHIMCACHE_FILES:
        fpath = os.path.join(csv_dir, fname)
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if _keyword_hit(line):
                        hits.append(line.strip())
        except Exception:
            pass
    if hits:
        return "Cache Detection (Recent Launch History):\n" + "\n".join(hits), True
    return "OVERALL RESULT: No keyword matches detected.", False


def format_shimcache_hits(hits):
    return "\n".join(hits) if hits else "No keyword matches found."


def check_shimcache_integrity():
    """Check if the SYSTEM hive (contains shimcache) was recently modified."""
    if not os.path.exists(SHIMCACHE_SYSTEM_HIVE):
        return "Shimcache Integrity Check: SYSTEM hive not found"
    try:
        mtime = os.path.getmtime(SHIMCACHE_SYSTEM_HIVE)
        ts    = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        age_m = (datetime.now().timestamp() - mtime) / 60
        rep   = f"Shimcache Integrity Check:\nSYSTEM hive last modified: {ts}"
        if age_m < 30:
            rep += "\nRecent modification may indicate shimcache tampering!"
        return rep
    except Exception as e:
        return f"Shimcache Integrity Check: error ({e})"


# ── SRUM ──────────────────────────────────────────────────────────────────────
def run_srum_scan():
    try:
        exe = ensure_srumparser_exe()
        subprocess.run([exe, "-f", SRUM_DATABASE_PATH, "--csv", SRUM_CSV_DIR],
                       capture_output=True, timeout=120)
        return scan_srum_for_todays_files()
    except Exception as e:
        return f"SRUM scan error: {e}", False


def scan_srum_for_todays_files():
    """Scan SRUM AppResourceUseInfo CSV for cheat files executed today."""
    hits = []
    for fname in TARGET_SRUM_FILES:
        fpath = os.path.join(SRUM_CSV_DIR, fname)
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if _keyword_hit(line):
                        hits.append(line.strip())
        except Exception:
            pass
    if hits:
        return "SRUM Detection:\n" + "\n".join(hits), True
    return "OVERALL RESULT: No keyword matches detected.", False


def scan_srum_csv_for_keywords(csv_dir):
    """Scan resource usage data for cheat keywords. Returns (report_string, has_hits)."""
    hits = []
    for fname in TARGET_SRUM_FILES:
        fpath = os.path.join(csv_dir, fname)
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if _keyword_hit(line):
                        hits.append(line.strip())
        except Exception:
            pass
    return ("SRUM Detection:\n" + "\n".join(hits), True) if hits \
        else ("No keyword matches found.", False)


def format_srum_hits(hits):
    return "\n".join(hits) if hits else "No keyword matches found."


def check_srum_integrity():
    """
    Note: SRUM is actively written to by Windows, so recent modification is normal.
    """
    if not os.path.exists(SRUM_DATABASE_PATH):
        return "SRUM Integrity Check: SRUDB.dat not found"
    size  = os.path.getsize(SRUM_DATABASE_PATH)
    mtime = os.path.getmtime(SRUM_DATABASE_PATH)
    ts    = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    return f"SRUM Integrity Check:\nSRUDB.dat size: {size} bytes\nLast modified: {ts}"


def check_unsigned_srum_files():
    """Check SRUM files for unsigned/deleted status."""
    results = []
    for fname in TARGET_SRUM_FILES:
        p = os.path.join(SRUM_CSV_DIR, fname)
        if not os.path.exists(p):
            results.append(f"Missing: {p}")
    return results


# ── Windows Defender ──────────────────────────────────────────────────────────
def check_defender_integrity():
    """Check Windows Defender logs for suspicious activity."""
    report   = ["Defender Integrity:"]
    sysroot  = os.getenv("SYSTEMROOT", r"C:\Windows")
    log_path = os.path.join(sysroot, "System32", "winevt", "Logs", DEFENDER_FILENAME)

    def _query_events():
        try:
            result = subprocess.run(
                ["wevtutil", "qe",
                 "Microsoft-Windows-Windows Defender/Operational",
                 "/c:100", "/rd:true", "/f:xml"],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout if result.returncode == 0 else ""
        except Exception as e:
            return f"Event Log Scan Error: {e}"

    if not os.path.exists(log_path):
        report.append("Windows Defender log: File missing (directly deleted?)")
    elif os.path.getsize(log_path) < 70000:
        report.append(f"Windows Defender log: Near-empty ({os.path.getsize(log_path)} bytes)")
    else:
        xml = _query_events()
        if "Event Log Scan Error" in xml:
            report.append(xml)
        else:
            if "5007" in xml and "exclusion" in xml.lower():
                report.append("Defender: Exclusion added: (see event log)")
            if "5001" in xml:
                report.append("Defender: Real-time protection disabled | (see event log)")
            if not ("5007" in xml or "5001" in xml):
                report.append("Defender: Log present and normal")

    return "\n".join(report)


# ── UserAssist ────────────────────────────────────────────────────────────────
def _rot13(s):
    out = []
    for c in s:
        if 'a' <= c <= 'z':
            out.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            out.append(c)
    return ''.join(out)


def _extract_userassist_ts(data):
    """Extract last-execution FILETIME from a UserAssist binary value."""
    try:
        if len(data) >= 16:
            lo = struct.unpack_from("<I", data, 8)[0]
            hi = struct.unpack_from("<I", data, 12)[0]
            ft = (hi << 32) | lo
            if ft:
                epoch = (ft - 116444736000000000) // 10000000
                return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return None


def scan_userassist_for_keywords():
    """
    Scan UserAssist entries (ROT13-decoded) for cheat keywords across all user profiles.
    Other users: loads their NTUSER.DAT into HKU temporarily,
    yields (HKEY_USERS, "Trinity_<username>")
    """
    hits    = []
    ua_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    try:
        ua_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua_path)
        i = 0
        while True:
            try:
                guid     = winreg.EnumKey(ua_key, i)
                cnt_key  = winreg.OpenKey(ua_key, guid + r"\Count")
                j = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(cnt_key, j)
                        decoded = _rot13(name)
                        if _keyword_hit(decoded):
                            ts = _extract_userassist_ts(data) or "unknown"
                            hits.append(f"] Detected in UserAssist: {decoded} | ts: {ts}")
                        j += 1
                    except OSError:
                        break
                i += 1
            except OSError:
                break
    except OSError:
        pass
    return hits


def check_userassist_integrity():
    """Count UserAssist entries for each user profile."""
    try:
        ua_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        ua_key  = winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua_path)
        total   = 0
        cleared = False
        i = 0
        while True:
            try:
                guid = winreg.EnumKey(ua_key, i)
                try:
                    cnt_key = winreg.OpenKey(ua_key, guid + r"\Count")
                    j = 0
                    while True:
                        try:
                            winreg.EnumValue(cnt_key, j)
                            total += 1
                            j += 1
                        except OSError:
                            break
                except OSError:
                    cleared = True
                i += 1
            except OSError:
                break
        if cleared or total == 0:
            return "] UserAssist key missing (deleted or profile corruption)"
        if total < 10:
            return f"] UserAssist cleaned ({total} entries remain)"
        return f"UserAssist OK: {total} entries"
    except OSError:
        return "UserAssist was cleared."


def detect_unsigned_userassist_files():
    """Collect missing files referenced in UserAssist."""
    hits = []
    for entry in scan_userassist_for_keywords():
        m = re.search(r":\s(.+?)\s\|", entry)
        if m and not os.path.exists(m.group(1)):
            hits.append(f"Missing: {m.group(1)}")
    return hits


def get_userassist_bat_cmd_files():
    """Return script files found in UserAssist (bat, cmd, ps1, vbs)."""
    return [e for e in scan_userassist_for_keywords()
            if any(ext in e.lower() for ext in [".bat", ".cmd", ".ps1", ".vbs"])]


# ── Audit policy ──────────────────────────────────────────────────────────────
def check_audit_policy():
    """Check Windows audit policy for 'No Auditing' entries."""
    try:
        result  = subprocess.run(["auditpol.exe", "/get", "/category:*"],
                                  capture_output=True, text=True, timeout=15)
        no_aud  = [l.strip() for l in result.stdout.splitlines()
                   if re.search(r"No Auditing", l, re.IGNORECASE)]
        return ("Audit Policy: 'No Auditing':\n" + "\n".join(no_aud)) if no_aud \
            else "Audit Policy: OK"
    except Exception as e:
        return f"Audit Policy: Could not check ({e})"


# ── BAM ───────────────────────────────────────────────────────────────────────
def scan_bam_for_removable_drives():
    """
    Scan ALL BAM entries for .exe paths on non-C: drives.
    Detect if BAM has been disabled or cleared.
    """
    def parse_filetime(data):
        try:
            ft    = struct.unpack("<Q", data[:8])[0]
            epoch = (ft - 116444736000000000) // 10000000
            return datetime.fromtimestamp(epoch)
        except Exception:
            return None

    try:
        svc = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\bam")
        start_val, _ = winreg.QueryValueEx(svc, "Start")
        if start_val == 4:
            return "BAM DISABLED: BAM service is set to Disabled"
    except FileNotFoundError:
        return "BAM DISABLED: BAM service registry key does not exist (service deleted)"
    except OSError:
        return "BAM DISABLED: BAM registry keys not found (service disabled or deleted)"

    hits = []
    try:
        bam = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings")
        i = 0
        while True:
            try:
                sid     = winreg.EnumKey(bam, i)
                sid_key = winreg.OpenKey(bam, sid)
                j = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(sid_key, j)
                        if isinstance(name, str) and name.lower().endswith(".exe"):
                            drive  = name[:2].upper() if len(name) >= 2 else ""
                            ts_obj = parse_filetime(data) if isinstance(data, bytes) else None
                            ts_str = ts_obj.strftime("%Y-%m-%d %H:%M:%S") if ts_obj else "unknown"
                            if drive and drive != "C:":
                                hits.append(f"USB storage activity: {name} | ran at {ts_str}")
                            if _keyword_hit(name):
                                hits.append(f"BAM cheat keyword: {name} | ran at {ts_str}")
                        j += 1
                    except OSError:
                        break
                i += 1
            except OSError:
                break
    except OSError:
        return "BAM DISABLED: BAM registry keys not found (service disabled or deleted)"

    pf_count = len([f for f in os.listdir(PREFETCH_DIR) if f.endswith(".pf")]) \
        if os.path.isdir(PREFETCH_DIR) else 0
    if pf_count < 5 and not hits:
        return f"BAM CLEARED: Only {pf_count} .pf files in prefetch dir"
    return "\n".join(hits) if hits else "BAM: No removable drive or cheat activity detected"


# ── ShellBags ─────────────────────────────────────────────────────────────────
def run_sbecmd_scan():
    """Run SBECmd across all user profiles and filter for cheat keywords."""
    try:
        result = subprocess.run(
            ["SBECmd.exe", "-d", r"C:\Users", "--csv", AMCACHE_CSV_DIR],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            return f"SBECmd scan failed: {result.stderr}"
        return scan_shellbags_for_cheats()
    except FileNotFoundError:
        return "ShellBag scan failed (SBECmd error)"
    except Exception as e:
        return f"SBECmd scan failed: {e}"


def scan_shellbags_for_cheats():
    """
    Scan all shellbag CSV output for cheat keywords.
    Low count = cleaned. Newest timestamp is old = shellbag logging disabled.
    """
    csv_path = os.path.join(AMCACHE_CSV_DIR, "shellbags.csv")
    if not os.path.exists(csv_path):
        return "Shellbag Integrity: CSV not found"
    try:
        with open(csv_path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        if len(lines) < 3:
            return (f"Shellbag MANIPULATED: Only {len(lines)} entries found. "
                    f"shellbag logging may be disabled")
        hits = [l.strip() for l in lines if _keyword_hit(l)]
    except Exception:
        return "ShellBag scan failed (SBECmd error)"
    return ("ShellBag Detection:\n" + "\n".join(hits)) if hits else "ShellBags: Clean"


def check_shellbag_integrity():
    """Count total unique shellbag entries across all user profiles."""
    csv_path = os.path.join(AMCACHE_CSV_DIR, "shellbags.csv")
    if not os.path.exists(csv_path):
        return "Shellbag Integrity: CSV not found"
    try:
        with open(csv_path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        if not lines:
            return "Shellbag DISABLED: Most recent entry is (no entries)"
        return f"ShellBag: {len(lines)} total entries"
    except Exception:
        return "ShellBag scan failed (SBECmd error)"


# ── Recent Items ──────────────────────────────────────────────────────────────
def scan_recent_lnk_for_cheats():
    """
    Scan each user's Recent Items folder for .lnk files whose filename
    matches a cheat keyword. Windows creates a .lnk here when a file is run
    or accessed from Explorer, so this complements UserAssist keyword detection.
    """
    hits = []
    try:
        for username in os.listdir(r"C:\Users"):
            recent = os.path.join(r"C:\Users", username,
                                  "AppData", "Roaming",
                                  "Microsoft", "Windows", "Recent")
            if not os.path.isdir(recent):
                continue
            for f in os.listdir(recent):
                if _keyword_hit(f):
                    hits.append(f"] Cheat in Recent Items: {f}")
    except Exception:
        pass
    return hits


# ── USN / MFT ─────────────────────────────────────────────────────────────────
def parse_usn_for_cheat_activity():
    """Parse MFTECmd USN journal CSV for cheat file activity."""
    hits = []
    usn  = os.path.join(AMCACHE_CSV_DIR, "usn.csv")
    if not os.path.exists(usn):
        return hits
    try:
        with open(usn, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if _keyword_hit(line):
                    hits.append(line.strip())
    except Exception as e:
        return [f"Error parsing USN journal for cheat keywords: {e}"]
    return hits


def parse_usn_for_deleted_prefetch():
    """Parse MFTECmd USN journal CSV for deleted prefetch (.pf) files."""
    hits = []
    usn  = os.path.join(AMCACHE_CSV_DIR, "usn.csv")
    if not os.path.exists(usn):
        return hits
    try:
        with open(usn, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if ".pf" in line.lower() and "delete" in line.lower():
                    hits.append(f"Deleted Cheat Prefetch: {line.strip()}")
    except Exception as e:
        return [f"Error parsing USN journal for deleted prefetch: {e}"]
    return hits


def parse_mft_for_cheats():
    """Parse MFTECmd USN journal CSV for Roblox log activity (_last.log files)."""
    hits = []
    mft  = os.path.join(AMCACHE_CSV_DIR, "mft.csv")
    if not os.path.exists(mft):
        return hits
    try:
        with open(mft, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if _keyword_hit(line) or "_last.log" in line.lower():
                    hits.append(line.strip())
    except Exception:
        pass
    return hits


# ── Custom / deep scan ────────────────────────────────────────────────────────
def scan_custom_detections():
    """
    Scan all drives for cheat files.
    Flags deleted executables as 'Deleted' instead of skipping them.
    """
    hits   = []
    drives = []
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                drives.append(chr(65 + i) + ":\\")
    except Exception:
        drives = ["C:\\"]

    for drive in drives:
        try:
            for root, dirs, files in os.walk(drive, topdown=True):
                dirs[:] = [d for d in dirs
                           if d.lower() not in ("windows", "system32", "syswow64",
                                                 "$recycle.bin", "programdata")]
                for fname in files:
                    if _keyword_hit(fname):
                        full = os.path.join(root, fname)
                        tag  = "Cheat File" if os.path.exists(full) else "Cheat file deleted"
                        hits.append(f"{tag}: {full}")
        except Exception:
            pass

    return ("Deep File Scan:\n" + "\n".join(hits)) if hits else "Deep File Scan: No cheat files found."


def format_custom_detections(detections):
    return "\n".join(sorted(detections, key=str.lower)) if detections else "No cheat files found"


def check_for_cheats_in_registry():
    """Scan registry run keys and software lists for cheat software traces."""
    hits = []
    paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, path in paths:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    if _keyword_hit(f"{name} {data}"):
                        hits.append(f"Other Registry Detection: {path}\\{name} = {data}")
                    i += 1
                except OSError:
                    break
        except OSError:
            pass
    return "\n".join(hits) if hits else "Other Registry: Clean"


# ── Send to Discord ───────────────────────────────────────────────────────────
def send_file_to_discord(filepath, webhook_url=""):
    """Webhook sending disabled."""
    return "Webhook disabled."


def convert_discord_snowflake(snowflake_id):
    """Convert Discord snowflake ID to timestamp."""
    try:
        ts_ms = (int(snowflake_id) >> 22) + DISCORD_EPOCH
        return datetime.fromtimestamp(ts_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


# ── Advanced scans ────────────────────────────────────────────────────────────
def advancedscans():
    """Run all advanced forensic scans and collect results."""
    results = {}

    def _run_amcache():
        try: results["amcache"] = run_amcache_scan()
        except Exception as e: results["amcache"] = f"AmCache error: {e}", False

    def _run_shimcache():
        try: results["shimcache"] = run_shimcache_scan()
        except Exception as e: results["shimcache"] = f"Shimcache error: {e}", False

    def _run_srum():
        try: results["srum"] = run_srum_scan()
        except Exception as e: results["srum"] = f"SRUM error: {e}", False

    threads = [
        threading.Thread(target=_run_amcache),
        threading.Thread(target=_run_shimcache),
        threading.Thread(target=_run_srum),
    ]
    for t in threads: t.start()
    for t in threads: t.join()

    results["prefetchIntegrity"]   = check_prefetch_integrity()
    results["amcacheIntegrity"]    = check_amcache_integrity()
    results["shimcacheIntegrity"]  = check_shimcache_integrity()
    results["srumIntegrity"]       = check_srum_integrity()
    results["defender"]            = check_defender_integrity()
    results["auditPolicy"]         = check_audit_policy()
    results["bam"]                 = scan_bam_for_removable_drives()
    results["userassist"]          = scan_userassist_for_keywords()
    results["userassistIntegrity"] = check_userassist_integrity()
    results["shellbags"]           = run_sbecmd_scan()
    results["shellbagIntegrity"]   = check_shellbag_integrity()
    results["recentItems"]         = scan_recent_lnk_for_cheats()
    results["registry"]            = check_for_cheats_in_registry()
    results["usnCheats"]           = parse_usn_for_cheat_activity()
    results["usnDeletedPrefetch"]  = parse_usn_for_deleted_prefetch()
    results["mft"]                 = parse_mft_for_cheats()
    results["customDetections"]    = scan_custom_detections()
    return results


# ── Backend scan ──────────────────────────────────────────────────────────────
def run_backend_scan():
    """Run the backend scan and return results as a dictionary with keys 'cheatScan', 'advancedScan'."""
    results = {"cheatScan": {}, "advancedScan": {}}

    scans = {
        "robloxMemory":    scan_roblox_memory,
        "injectedModules": check_roblox_injected_modules,
        "prefetchModules": scan_roblox_prefetch_modules,
        "robloxLogs":      fetch_roblox_logs,
        "discordMemory":   scan_discord_memory,
        "robloxAccounts":  get_roblox_ids_from_local_storage,
        "discordAccounts": get_discord_accounts_from_storage,
    }
    for key, fn in scans.items():
        try:
            results["cheatScan"][key] = fn()
        except Exception as e:
            results["cheatScan"][key] = f"Scanner error: {e}"

    results["advancedScan"].update(advancedscans())
    return results


def get_system_info():
    return {
        "hostname":          os.environ.get("COMPUTERNAME", "unknown"),
        "username":          os.environ.get("USERNAME", "unknown"),
        "roblox_accounts":   get_roblox_ids_from_local_storage(),
        "discord_accounts":  get_discord_accounts_from_storage(),
        "roblox_profile_urls": get_roblox_profile_urls_from_registry(),
    }


def get_trash():
    """Scan Recycle Bin for deleted cheat files."""
    hits = []
    try:
        for root, dirs, files in os.walk(r"C:\$Recycle.Bin"):
            for f in files:
                if _keyword_hit(f):
                    hits.append(f"Cheat file deleted: {os.path.join(root, f)}")
    except Exception:
        pass
    return hits


def run_windows_scan():
    """Run the full Windows scan, collect results, and send to API/Discord."""
    results     = run_backend_scan()
    system_info = get_system_info()
    trash       = get_trash()
    roblox_logs = get_roblox_logs()

    payload = {
        "systemInfo":  system_info,
        "scanResults": results,
        "deletedFiles": trash,
        "robloxLogs":  roblox_logs,
        "timestamp":   datetime.now().isoformat(),
    }

    log_path = os.path.join(TEMP, "trinity.log")
    try:
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
    except Exception:
        pass

    try:
        pass  # webhook disabled
    except Exception:
        pass

    try:
        pass  # API post disabled
    except Exception:
        pass

    return results


# ════════════════════════════════════════════════════════════════════════════════
#  GUI  (trinitymemory.py)
# ════════════════════════════════════════════════════════════════════════════════

class TrinityApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Trinity")
        self.geometry("900x660")
        self.configure(fg_color=TRINITY_DARK)
        self.resizable(False, False)

        self._pages          = {}
        self._pin_entry      = None
        self._scan_btn       = None
        self._discord_btn    = None
        self._progress_label = None
        self._progress_bar   = None
        self._log_box        = None
        self._scan_results   = None
        self._scan_thread    = None
        self._userassist_ts  = None

        ctk.set_appearance_mode("dark")
        self._init_font_character_mapping()

        self._create_welcome_page()
        self._create_progress_page()
        self._show_page("welcome")

    def _init_font_character_mapping(self):
        """Call .init_font_character_mapping() at program start to load the correct character mapping."""
        try:
            ctk.FontManager.load_font(
                os.path.join(os.path.dirname(__file__),
                             "assets", "fonts", "CustomTkinter_shapes_font.otf")
            )
        except Exception:
            pass

    # ── Welcome ────────────────────────────────────────────────────────────────
    def _create_welcome_page(self):
        frame = ctk.CTkFrame(self, fg_color=TRINITY_DARK)
        self._pages["welcome"] = frame

        ctk.CTkLabel(frame, text="Trinity",
                     font=ctk.CTkFont(size=52, weight="bold"),
                     text_color=TRINITY_TEXT).pack(pady=(70, 4))

        ctk.CTkLabel(frame, text="Advanced Automated Scanning System",
                     font=ctk.CTkFont(size=13),
                     text_color=TRINITY_TEXT_SECONDARY).pack(pady=(0, 48))

        card = ctk.CTkFrame(frame, fg_color=TRINITY_CARD, corner_radius=12,
                            border_width=1, border_color=TRINITY_BORDER)
        card.pack(padx=60, pady=(0, 20), fill="x")

        ctk.CTkLabel(card,
                     text="By using Trinity, you acknowledge and agree to the following:",
                     font=ctk.CTkFont(size=11), text_color=TRINITY_TEXT_SECONDARY,
                     justify="left", wraplength=600).pack(padx=24, pady=(18, 4), anchor="w")

        ctk.CTkLabel(card,
                     text="- Joining the Trinity Discord server and creating a support ticket\n"
                          "- Messaging Discord user: cod.dll",
                     font=ctk.CTkFont(size=11), text_color=TRINITY_MUTED,
                     justify="left").pack(padx=36, pady=(0, 18), anchor="w")

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=10)

        self._scan_btn = ctk.CTkButton(
            btn_frame, text="START SCAN", width=200, height=46,
            fg_color=TRINITY_ACCENT, hover_color=TRINITY_ACCENT_HOVER,
            font=ctk.CTkFont(size=14, weight="bold"), corner_radius=8,
            command=lambda: self._show_terms())
        self._scan_btn.grid(row=0, column=0, padx=8)



        ctk.CTkLabel(frame,
                     text="Thank you for helping keep the community safe and fair.",
                     font=ctk.CTkFont(size=10),
                     text_color=TRINITY_MUTED).pack(pady=(16, 0))

    # ── PIN ────────────────────────────────────────────────────────────────────
    # ── Progress ───────────────────────────────────────────────────────────────
    def _create_progress_page(self):
        frame = ctk.CTkFrame(self, fg_color=TRINITY_DARK)
        self._pages["progress"] = frame

        ctk.CTkLabel(frame, text="Scanning System",
                     font=ctk.CTkFont(size=30, weight="bold"),
                     text_color=TRINITY_TEXT).pack(pady=(50, 6))

        self._progress_label = ctk.CTkLabel(
            frame, text="Initializing scan environment",
            font=ctk.CTkFont(size=13), text_color=TRINITY_TEXT_SECONDARY)
        self._progress_label.pack(pady=(0, 18))

        self._progress_bar = ctk.CTkProgressBar(
            frame, width=560, height=8,
            fg_color=TRINITY_SURFACE, progress_color=TRINITY_ACCENT, corner_radius=4)
        self._progress_bar.set(0)
        self._progress_bar.pack(pady=(0, 24))

        log_card = ctk.CTkFrame(frame, fg_color=TRINITY_CARD, corner_radius=10,
                                border_width=1, border_color=TRINITY_BORDER)
        log_card.pack(padx=40, pady=0, fill="both", expand=True)

        self._log_box = ctk.CTkTextbox(
            log_card, fg_color="transparent", text_color=TRINITY_TEXT,
            font=ctk.CTkFont(family="Courier New", size=11),
            wrap="word", state="normal")
        self._log_box.pack(fill="both", expand=True, padx=12, pady=12)

    # ── Navigation ─────────────────────────────────────────────────────────────
    def _show_page(self, name):
        for p in self._pages.values():
            p.pack_forget()
        self._pages[name].pack(fill="both", expand=True)

    def _show_terms(self):
        self._start_scan()

    # ── Scan ───────────────────────────────────────────────────────────────────
    def _start_scan(self):
        self._show_page("progress")
        self._scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self._scan_thread.start()

    def _run_scan(self):
        steps = [
            ("Initializing scan environment",    0.04),
            ("Scanning Roblox log files",         0.12),
            ("Scanning memory processes",         0.25),
            ("Analyzing registry entries",        0.42),
            ("Verifying system integrity",        0.60),
            ("Advanced Scan Continued",           0.78),
            ("Scanning all drives...",            0.90),
            ("Start of scan",                     0.93),
            ("Starting Roblox logs scan...",      0.95),
            ("Starting advanced scans...",        0.97),
            ("Scan complete",                     1.00),
        ]
        for label, progress in steps:
            self.after(0, self._update_progress, label, progress)
        try:
            results = run_windows_scan()
            self.after(0, self._scan_complete, results)
        except Exception as e:
            self.after(0, self._update_progress, f"Scanner error: {e}", 1.0)
            self.after(0, self._scan_complete, None)

    def _update_progress(self, label, value):
        if self._progress_label:
            self._progress_label.configure(text=f"[Scanning] {label}")
        if self._progress_bar:
            self._progress_bar.set(value)
        if self._log_box:
            self._log_box.configure(state="normal")
            self._log_box.insert("end", f"{label}\n")
            self._log_box.see("end")

    def _scan_complete(self, results):
        self._scan_results = results
        msg = "Scan completed successfully!" if results else "Scan Failed"
        log = "] Scan complete\n"          if results else "Scan Failed\n"
        if self._progress_label:
            self._progress_label.configure(text=msg)
        if self._log_box:
            self._log_box.configure(state="normal")
            self._log_box.insert("end", log)
            self._log_box.see("end")


# ════════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = TrinityApp()
    app.mainloop()