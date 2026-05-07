"""
Flask Backend for Secure Authentication Module
Bridges the Python web layer to the compiled C++ binary via subprocess.

Architecture:
  Browser → Flask API → subprocess → ./auth_module (C++ binary)

The C++ binary handles ALL cryptographic operations.
Flask only relays input/output — no auth logic lives here.
"""

from flask import Flask, request, jsonify, send_from_directory
import subprocess
import threading
import queue
import os
import time
import hashlib
import base64
from io import BytesIO
import qrcode
import pyotp

app = Flask(__name__, static_folder=".")

USERS_DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
db_lock = threading.Lock()

# Path to compiled C++ binary (must be relative for cross-platform/WSL compatibility)
BINARY = "./auth_module"

# ── Active login sessions ────────────────────────────────────────────────────
# Stores in-progress login state between the /login and /verify-otp calls.
# Key: session_id (username), Value: dict with subprocess + queues
active_logins: dict = {}
lock = threading.Lock()


def run_binary_interactive(username, password, result_q):
    """
    Spawns the C++ binary and drives the automated-test + PAM login flow.
    Sends username/password, waits for the OTP prompt, captures the OTP,
    then puts it into result_q for the Flask route to return to the browser.
    """
    cwd = os.path.abspath(os.path.dirname(__file__))
    
    # Debug logs
    print(f"[DEBUG] Current working directory: {cwd}")
    print(f"[DEBUG] Binary path to execute: {BINARY}")
    
    # Validate binary exists
    binary_full_path = os.path.join(cwd, BINARY.lstrip("./"))
    assert os.path.exists(binary_full_path), f"Binary not found at {binary_full_path}"

    try:
        proc = subprocess.Popen(
            [BINARY],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=cwd
        )

        # The binary first runs automated tests (no stdin needed for those).
        # Then it prints "login: " — send username.
        output = ""
        while True:
            ch = proc.stdout.read(1)
            if not ch:
                break
            output += ch
            if output.endswith("login: "):
                break

        proc.stdin.write(username + "\n")
        proc.stdin.flush()

        # Read until "Password: "
        segment = ""
        while True:
            ch = proc.stdout.read(1)
            if not ch:
                break
            segment += ch
            if segment.endswith("Password: "):
                break

        proc.stdin.write(password + "\n")
        proc.stdin.flush()

        # Read until OTP prompt or failure message
        segment2 = ""
        timeout = time.time() + 10
        while time.time() < timeout:
            ch = proc.stdout.read(1)
            if not ch:
                break
            segment2 += ch
            if "Enter TOTP:" in segment2:
                break
            if "Authentication failed" in segment2 or \
               "Account is locked" in segment2 or \
               "rejected" in segment2:
                break

        if "Enter TOTP:" in segment2:
            # Store proc so /verify-otp can send the OTP
            with lock:
                active_logins[username] = {
                    "proc": proc,
                }
            result_q.put({"status": "otp_required"})
        elif "Account is locked" in segment2:
            proc.kill()
            result_q.put({"status": "error", "message": "Account is locked."})
        else:
            stderr_out = proc.stderr.read() if proc.stderr else ""
            print(f"[ERROR] Authentication failed. stderr: {stderr_out}")
            proc.kill()
            result_q.put({"status": "error", "message": "Authentication failed."})

    except AssertionError as ae:
        print(f"[ERROR] Validation failed: {str(ae)}")
        result_q.put({"status": "error", "message": "Server configuration error: Binary missing."})
    except Exception as e:
        print(f"[ERROR] Subprocess execution failed: {str(e)}")
        result_q.put({"status": "error", "message": f"Server error: Could not run auth module ({type(e).__name__})."})


def get_user_secret(username):
    """Reads the TOTP secret for a user directly from the database file."""
    with db_lock:
        if os.path.exists(USERS_DB_PATH):
            with open(USERS_DB_PATH, "r") as f:
                for line in f:
                    if line.startswith(username + "|"):
                        parts = line.strip().split("|")
                        if len(parts) > 4:
                            return parts[4]  # totp_secret is field 4
    return None


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/api/register", methods=["POST"])
def register():
    data = request.json or {}
    username = (data.get("username") or "").strip()[:50]
    password = (data.get("password") or "").strip()[:128]

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required."}), 400

    if "|" in username or "|" in password:
        return jsonify({"status": "error", "message": "Invalid characters."}), 400

    with db_lock:
        if os.path.exists(USERS_DB_PATH):
            with open(USERS_DB_PATH, "r") as f:
                for line in f:
                    if line.startswith(username + "|"):
                        return jsonify({"status": "error", "message": "User already exists."}), 400

        # Generate cryptographic parameters
        salt_bytes = os.urandom(16)
        salt_hex = salt_bytes.hex()
        # PBKDF2 with 10000 iterations, exactly as in C++
        pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_hex.encode("utf-8"), 10000).hex()
        
        # Generate TOTP secret (base32)
        # Using 10 bytes gives exactly 16 base32 characters, which is standard for GA
        totp_secret = base64.b32encode(os.urandom(10)).decode("utf-8")
        
        # Write to db (format: username|salt|hash|role|totp|hw_secret|bio_hash|fails|lockout)
        with open(USERS_DB_PATH, "a") as f:
            f.write(f"{username}|{salt_hex}|{pw_hash}|USER|{totp_secret}|HWSECRET_USER|bio_hash_user|0|0\n")

    # Generate QR Code
    totp_uri = f"otpauth://totp/SecureAuthApp:{username}?secret={totp_secret}&issuer=SecureAuthApp"
    qr = qrcode.make(totp_uri)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    
    return jsonify({
        "status": "success",
        "qr_code": "data:image/png;base64," + qr_b64
    })


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    username = (data.get("username") or "").strip()[:50]   # enforce max length
    password = (data.get("password") or "").strip()[:128]

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required."}), 400

    # Clean up any stale session for this user
    with lock:
        old = active_logins.pop(username, None)
        if old:
            try:
                old["proc"].kill()
            except Exception:
                pass

    result_q: queue.Queue = queue.Queue()
    t = threading.Thread(target=run_binary_interactive,
                         args=(username, password, result_q), daemon=True)
    t.start()

    try:
        result = result_q.get(timeout=12)
    except queue.Empty:
        return jsonify({"status": "error", "message": "Binary timed out."}), 500

    return jsonify(result)


@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    data = request.json or {}
    username = (data.get("username") or "").strip()[:50]
    otp      = (data.get("otp") or "").strip()[:10]

    if not username or not otp:
        return jsonify({"status": "error", "message": "Username and OTP required."}), 400

    with lock:
        session = active_logins.get(username)

    if not session:
        # Fallback: Check if this is a registration verification (standalone TOTP check)
        secret = get_user_secret(username)
        if secret:
            totp_checker = pyotp.TOTP(secret)
            if totp_checker.verify(otp):
                return jsonify({"status": "success",
                                "message": "MFA setup verified! Your account is now fully protected."})
            else:
                return jsonify({"status": "error",
                                "message": "Invalid OTP. Please ensure your app is synced."})
        
        return jsonify({"status": "error",
                        "message": "No pending session or user found."}), 400

    proc = session["proc"]
    try:
        proc.stdin.write(otp + "\n")
        proc.stdin.flush()

        # Read remaining output (Access Granted / Denied)
        remaining = ""
        timeout = time.time() + 6
        while time.time() < timeout:
            ch = proc.stdout.read(1)
            if not ch:
                break
            remaining += ch
            if "Access Granted" in remaining or \
               "Access Denied" in remaining or \
               "failed" in remaining.lower():
                break

        proc.kill()
        with lock:
            active_logins.pop(username, None)

        if "Access Granted" in remaining:
            return jsonify({"status": "success",
                            "message": "Login successful! Secure session created."})
        else:
            return jsonify({"status": "error",
                            "message": "OTP incorrect or expired."})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    print("[Flask] Starting Secure Auth API on http://localhost:5000")
    print(f"[Flask] Using C++ binary: {BINARY}")
    app.run(debug=False, port=5000, threaded=True)