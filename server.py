import socket
import json
import threading
import base64
import os
import tempfile
import importlib
import time
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
from pyocd.core.helpers import ConnectHelper
import hashlib
import sqlite3
import subprocess
import re
import urllib.request
import secrets
import string
import ssl
from datetime import datetime
from collections import defaultdict
import bcrypt

# ============================================================
# SECURE CONFIGURATION
# ============================================================
class SecureConfig:
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB - Allow large files
    CHUNK_SIZE = 1024 * 1024          # 1MB
    TIMEOUT = 600                      # 10 minutes
    RATE_LIMIT = 100                   # Requests per minute
    MAX_CONNECTIONS = 10               # Per IP
    ENABLE_SSL = True                  # Enable SSL encryption
    CERT_FILE = "server.crt"
    KEY_FILE = "server.key"
    DB_FILE = "users_secure.db"
    
    # Allowed file types
    ALLOWED_EXTENSIONS = ['.bin', '.hex', '.elf']
    
    # File size warnings
    WARNING_SIZE = 2 * 1024 * 1024     # 2MB

# ============================================================
# SECURE DATABASE
# ============================================================
class SecureDatabase:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Users table with bcrypt
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    is_admin INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    login_attempts INTEGER DEFAULT 0,
                    locked INTEGER DEFAULT 0,
                    lock_until TIMESTAMP
                )
            ''')
            
            # Audit log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    username TEXT,
                    action TEXT,
                    ip TEXT,
                    details TEXT,
                    status TEXT
                )
            ''')
            
            # File operations log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    username TEXT,
                    filename TEXT,
                    file_size INTEGER,
                    action TEXT,
                    status TEXT,
                    ip TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[-] Database init error: {e}")
            return False
    
    def create_admin(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            count = cursor.fetchone()[0]
            
            if count == 0:
                password = "Admin@123#Secure"
                salt = bcrypt.gensalt()
                password_hash = bcrypt.hashpw(password.encode(), salt)
                
                cursor.execute(
                    "INSERT INTO users (username, password_hash, salt, is_admin) VALUES (?, ?, ?, ?)",
                    ("admin", password_hash, salt, 1)
                )
                conn.commit()
                print(f"[+] Admin created: admin / {password}")
                print("[!] CHANGE THIS PASSWORD IMMEDIATELY!")
            conn.close()
            return True
        except Exception as e:
            print(f"[-] Admin creation error: {e}")
            return False
    
    def authenticate_user(self, username, password, ip):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if user is locked
            cursor.execute(
                "SELECT locked, lock_until FROM users WHERE username=?",
                (username,)
            )
            result = cursor.fetchone()
            if result and result[0] == 1 and result[1]:
                lock_until = datetime.fromisoformat(result[1])
                if datetime.now() < lock_until:
                    conn.close()
                    self.log_audit(username, "LOGIN_ATTEMPT", ip, "Account locked", "FAILED")
                    return False, 0, "Account locked. Try later."
            
            cursor.execute(
                "SELECT password_hash, is_admin, login_attempts FROM users WHERE username=?",
                (username,)
            )
            result = cursor.fetchone()
            
            if not result:
                conn.close()
                self.log_audit(username, "LOGIN_ATTEMPT", ip, "User not found", "FAILED")
                return False, 0, "Invalid credentials"
            
            password_hash, is_admin, attempts = result
            
            # Check password with bcrypt
            if bcrypt.checkpw(password.encode(), password_hash):
                cursor.execute(
                    "UPDATE users SET login_attempts=0, last_login=CURRENT_TIMESTAMP WHERE username=?",
                    (username,)
                )
                conn.commit()
                conn.close()
                self.log_audit(username, "LOGIN", ip, "Login successful", "SUCCESS")
                return True, is_admin, "Login successful"
            else:
                new_attempts = attempts + 1
                if new_attempts >= 5:
                    lock_until = datetime.now().replace(second=0, microsecond=0)
                    lock_until = lock_until.replace(minute=lock_until.minute + 15)
                    cursor.execute(
                        "UPDATE users SET login_attempts=?, locked=1, lock_until=? WHERE username=?",
                        (new_attempts, lock_until.isoformat(), username)
                    )
                    conn.commit()
                    conn.close()
                    self.log_audit(username, "LOGIN_ATTEMPT", ip, "Account locked - too many attempts", "FAILED")
                    return False, 0, "Account locked due to too many failed attempts"
                else:
                    cursor.execute(
                        "UPDATE users SET login_attempts=? WHERE username=?",
                        (new_attempts, username)
                    )
                    conn.commit()
                    conn.close()
                    self.log_audit(username, "LOGIN_ATTEMPT", ip, "Invalid password", "FAILED")
                    return False, 0, "Invalid credentials"
            
        except Exception as e:
            self.log_audit(username, "LOGIN_ATTEMPT", ip, f"Error: {e}", "FAILED")
            return False, 0, "Error during authentication"
    
    def add_user(self, username, password, is_admin=False):
        try:
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password.encode(), salt)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt, is_admin) VALUES (?, ?, ?, ?)",
                (username, password_hash, salt, 1 if is_admin else 0)
            )
            conn.commit()
            conn.close()
            return True, "User added successfully"
        except sqlite3.IntegrityError:
            return False, "User already exists"
        except Exception as e:
            return False, str(e)
    
    def delete_user(self, username):
        try:
            if username == "admin":
                return False, "Cannot delete admin user"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE username=?", (username,))
            conn.commit()
            conn.close()
            return True, "User deleted successfully"
        except Exception as e:
            return False, str(e)
    
    def get_all_users(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, is_admin, created_at, last_login FROM users ORDER BY id"
            )
            results = cursor.fetchall()
            conn.close()
            return results
        except Exception as e:
            return []
    
    def log_audit(self, username, action, ip, details, status):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO audit_log (username, action, ip, details, status) VALUES (?, ?, ?, ?, ?)",
                (username, action, ip, details, status)
            )
            conn.commit()
            conn.close()
        except:
            pass
    
    def log_file_operation(self, username, filename, file_size, action, status, ip):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO file_operations (username, filename, file_size, action, status, ip) VALUES (?, ?, ?, ?, ?, ?)",
                (username, filename, file_size, action, status, ip)
            )
            conn.commit()
            conn.close()
        except:
            pass

# ============================================================
# Safe Dynamic Import for FileProgrammer
# ============================================================
FileProgrammer = None

import_paths = [
    "pyocd.flash.file_programmer",
    "pyocd.flash.loader",
    "pyocd.flash.flash",
    "pyocd.core.flash",
]

for module_name in import_paths:
    try:
        module = importlib.import_module(module_name)
        for attr_name in ["FileProgrammer", "FlashProgrammer", "Programmer", "FlashLoader"]:
            if hasattr(module, attr_name):
                FileProgrammer = getattr(module, attr_name)
                print(f"[+] Found FileProgrammer as {attr_name} in {module_name}")
                break
        if FileProgrammer is not None:
            break
    except (ImportError, AttributeError):
        continue

if FileProgrammer is None:
    try:
        from pyocd.flash.file_programmer import FileProgrammer
    except:
        pass

if FileProgrammer is None:
    print("[!] Warning: FileProgrammer not found. Flash will not work.")

# ============================================================
# SECURE SERVER
# ============================================================
class SecureSTM32Server:
    def __init__(self, host='0.0.0.0', port=65432, enable_ssl=True):
        self.host = host
        self.port = port
        self.enable_ssl = enable_ssl
        self.session = None
        self.target = None
        self.is_running = True
        self.authenticated_clients = set()
        self.log_callback = None
        self.flash_chunks = {}
        self.bore_process = None
        self.public_url = None
        self.server_socket = None
        self.config = SecureConfig()
        
        # Large file settings
        self.CHUNK_SIZE = 512 * 1024  # 512KB per chunk
        self.MAX_CHUNKS = 20           # Max 20 chunks (10MB)
        
        # Rate limiting
        self.rate_limiter = defaultdict(list)
        self.connection_limiter = defaultdict(int)
        
        # Database
        self.db = SecureDatabase(self.config.DB_FILE)
        self.db.create_admin()
        
        # SSL Context
        self.ssl_context = None
        if self.enable_ssl:
            self.setup_ssl()
    
    def setup_ssl(self):
        """Setup SSL/TLS encryption"""
        try:
            if not os.path.exists(self.config.CERT_FILE) or not os.path.exists(self.config.KEY_FILE):
                self.log("[!] SSL certificates not found. Generating self-signed certificates...")
                self.generate_ssl_certificates()
            
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(self.config.CERT_FILE, self.config.KEY_FILE)
            self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            self.log("[+] SSL/TLS encryption enabled")
        except Exception as e:
            self.log(f"[-] SSL setup failed: {e}")
            self.enable_ssl = False
    
    def generate_ssl_certificates(self):
        """Generate self-signed SSL certificates"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
            
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure STM32"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            ).sign(key, hashes.SHA256())
            
            with open(self.config.KEY_FILE, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(self.config.CERT_FILE, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            self.log("[+] Self-signed SSL certificates generated")
        except Exception as e:
            self.log(f"[-] Certificate generation failed: {e}")
    
    def get_db_path(self):
        if getattr(sys, 'frozen', False):
            return os.path.join(os.path.dirname(sys.executable), self.config.DB_FILE)
        else:
            return self.config.DB_FILE
    
    def get_bore_path(self):
        if getattr(sys, 'frozen', False):
            return os.path.join(os.path.dirname(sys.executable), "bore.exe")
        else:
            return "bore.exe"
    
    def get_url_file_path(self):
        if getattr(sys, 'frozen', False):
            return os.path.join(os.path.dirname(sys.executable), "server_url.txt")
        else:
            return "server_url.txt"
    
    def set_log_callback(self, callback):
        self.log_callback = callback

    def log(self, message):
        if self.log_callback:
            self.log_callback(message)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")
    
    def check_rate_limit(self, ip):
        """Rate limiting per IP"""
        now = time.time()
        minute_ago = now - 60
        
        self.rate_limiter[ip] = [t for t in self.rate_limiter[ip] if t > minute_ago]
        
        if len(self.rate_limiter[ip]) >= self.config.RATE_LIMIT:
            return False, "Rate limit exceeded"
        
        self.rate_limiter[ip].append(now)
        return True, "OK"
    
    def check_connection_limit(self, ip):
        """Connection limit per IP"""
        if self.connection_limiter[ip] >= self.config.MAX_CONNECTIONS:
            return False, "Too many connections"
        self.connection_limiter[ip] += 1
        return True, "OK"
    
    def validate_file(self, filename, file_data):
        """Validate file before flashing (NO SIZE CHECK)"""
        # Check extension
        ext = os.path.splitext(filename)[1].lower()
        if ext not in self.config.ALLOWED_EXTENSIONS:
            return False, f"Invalid file type! Allowed: {', '.join(self.config.ALLOWED_EXTENSIONS)}"
        
        # Check for malware signatures (basic)
        suspicious_patterns = [
            b'rm -rf', b'format', b'del /f',
            b'curl', b'wget', b'powershell',
            b'javascript:', b'data:',
        ]
        
        for pattern in suspicious_patterns:
            if pattern in file_data:
                return False, "Suspicious content detected!"
        
        # Check if file is valid firmware (basic)
        if ext == '.bin' and len(file_data) < 1024:
            return False, "File too small! Invalid firmware?"
        
        # NO FLASH SIZE CHECK - ALLOW LARGE FILES
        # This allows 638KB file to flash (if STM32 supports it)
        
        return True, "Valid file"
    
    def handle_login(self, username, password, ip):
        """Secure login with rate limiting"""
        ok, msg = self.check_rate_limit(ip)
        if not ok:
            return {"status": "error", "msg": f"Rate limit: {msg}"}
        
        authenticated, is_admin, msg = self.db.authenticate_user(username, password, ip)
        
        if authenticated:
            self.log(f"[+] User logged in: {username} (Admin: {is_admin}) from {ip}")
            return {
                "status": "success", 
                "msg": f"Welcome {username}!",
                "is_admin": is_admin,
                "session_id": secrets.token_hex(16)
            }
        else:
            self.log(f"[-] Failed login: {username} from {ip}")
            return {"status": "error", "msg": msg}

    # ============================================================
    # STM32 OPERATIONS
    # ============================================================
    
    def connect_device(self):
        try:
            self.log("[*] Attempting to connect to Hardware...")
            
            options = {
                "frequency": 4000000,
                "connect_mode": "connect-under-reset"
            }
            
            targets = [
                  "stm32f103rc",
                  "stm32f407vg",   
                  "stm32h750vbtx",
                  "stm32f103",
                  "stm32f051",
                  "cortex_m"
                    ]
            
            for target in targets:
                try:
                    self.log(f"[*] Trying {target}...")
                    self.session = ConnectHelper.session_with_chosen_probe(
                        target_override=target,
                        options=options
                    )
                    
                    if self.session:
                        self.session.open()
                        self.target = self.session.target
                        
                        if self.target is not None:
                            try:
                                self.target.halt()
                                self.log("[+] Target halted")
                            except Exception as e:
                                self.log(f"[!] Could not halt: {e}")
                            
                            if self.target is not None:
                                try:
                                    device_id = self.target.read32(0xE0042000)
                                    self.log(f"[+] Device ID: 0x{device_id:08X}")
                                except:
                                    pass
                            
                            self.log("[+] Successfully linked to Hardware!")
                            return {"status": "success", "msg": "Connected Successfully"}
                except Exception as e:
                    self.log(f"[!] {target} failed: {e}")
                    continue
            
            return {"status": "error", "msg": "No ST-Link probe found!"}
            
        except Exception as e:
            self.log(f"[-] Connection Error: {e}")
            return {"status": "error", "msg": str(e)}
    
    def read_ram(self, addr):
        try:
            if self.target is None:
                return {"status": "error", "msg": "Not Linked"}
            if not addr:
                return {"status": "error", "msg": "Address is empty"}
            
            addr_int = int(addr, 0)
            if addr_int < 0x20000000 or addr_int > 0x2001FFFF:
                return {"status": "error", "msg": "Invalid RAM address range"}
            
            val = self.target.read32(addr_int)
            return {"status": "success", "value": hex(val), "msg": "Read OK"}
        except Exception as e:
            return {"status": "error", "msg": str(e)}
    
    def write_ram(self, addr, val):
        try:
            if self.target is None:
                return {"status": "error", "msg": "Not Linked"}
            if not addr:
                return {"status": "error", "msg": "Address is empty"}
            if val is None or str(val).strip() == "":
                return {"status": "error", "msg": "Value is empty"}
            
            addr_int = int(addr, 0)
            if addr_int < 0x20000000 or addr_int > 0x2001FFFF:
                return {"status": "error", "msg": "Invalid RAM address range"}
            
            self.target.write32(addr_int, int(val, 0))
            return {"status": "success", "msg": "Write OK"}
        except Exception as e:
            return {"status": "error", "msg": str(e)}
    
    def reset_device(self):
        try:
            if self.target is None:
                return {"status": "error", "msg": "Not Linked"}
            
            self.target.reset_and_halt()
            time.sleep(0.1)
            self.target.resume()
            
            return {"status": "success", "msg": "MCU Force Reset OK"}
        except Exception as e:
            return {"status": "error", "msg": str(e)}
    
    def handle_flash_chunk(self, req, addr, username="", ip=""):
        """Secure chunked flash with progress tracking"""
        try:
            chunk_data = req.get("chunk")
            chunk_index = req.get("chunk_index")
            total_chunks = req.get("total_chunks")
            filename = req.get("filename", "firmware.bin")
            
            if not chunk_data:
                return {"status": "error", "msg": "No chunk data"}
            
            if total_chunks > self.MAX_CHUNKS:
                return {
                    "status": "error", 
                    "msg": f"Too many chunks! Max: {self.MAX_CHUNKS}"
                }
            
            key = f"{addr[0]}_{addr[1]}_{filename}"
            
            if key not in self.flash_chunks:
                estimated_size = len(chunk_data) * total_chunks / 1.33
                if estimated_size > self.config.MAX_FILE_SIZE:
                    return {
                        "status": "error", 
                        "msg": f"File too large! Max: {self.config.MAX_FILE_SIZE/1024/1024}MB"
                    }
                
                self.flash_chunks[key] = {
                    'chunks': {},
                    'total': total_chunks,
                    'filename': filename,
                    'received': 0,
                    'username': username,
                    'ip': ip,
                    'start_time': time.time()
                }
            
            try:
                chunk_bin = base64.b64decode(chunk_data)
            except Exception as e:
                return {"status": "error", "msg": f"Base64 error: {e}"}
            
            self.flash_chunks[key]['chunks'][chunk_index] = chunk_bin
            self.flash_chunks[key]['received'] += 1
            
            progress = (self.flash_chunks[key]['received'] / total_chunks) * 100
            elapsed = time.time() - self.flash_chunks[key]['start_time']
            eta = (elapsed / self.flash_chunks[key]['received']) * (total_chunks - self.flash_chunks[key]['received'])
            
            self.log(f"[*] Chunk {chunk_index+1}/{total_chunks} received ({progress:.1f}%) - ETA: {eta:.1f}s")
            
            if self.flash_chunks[key]['received'] >= total_chunks:
                self.log("[*] All chunks received! Combining and flashing...")
                
                all_data = b''
                for i in range(total_chunks):
                    all_data += self.flash_chunks[key]['chunks'].get(i, b'')
                
                valid, msg = self.validate_file(filename, all_data)
                if not valid:
                    del self.flash_chunks[key]
                    return {"status": "error", "msg": f"File validation failed: {msg}"}
                
                b64_data = base64.b64encode(all_data).decode('utf-8')
                result = self.flash_binary(b64_data, filename, username, ip)
                del self.flash_chunks[key]
                return result
            else:
                return {
                    "status": "success", 
                    "msg": f"Chunk {chunk_index+1}/{total_chunks} received",
                    "progress": progress,
                    "eta": eta
                }
                
        except Exception as e:
            self.log(f"[-] Chunk handler error: {e}")
            return {"status": "error", "msg": str(e)}

    # ============================================================
    # FLASH BINARY - NO SIZE CHECK (Like Original Code)
    # ============================================================
    def flash_binary(self, b64_data, filename="firmware.bin", username="", ip=""):
        try:
            if self.session is None:
                return {"status": "error", "msg": "Session not open. Call CONNECT first."}
            
            if FileProgrammer is None:
                return {"status": "error", "msg": "FileProgrammer not available"}
            
            if not b64_data:
                return {"status": "error", "msg": "No file data received"}
            
            try:
                bin_data = base64.b64decode(b64_data)
            except Exception as e:
                return {"status": "error", "msg": f"Base64 decode error: {e}"}
            
            if len(bin_data) == 0:
                return {"status": "error", "msg": "Empty binary data"}
            
            # ============================================================
            # NO FLASH SIZE CHECK - JUST LIKE YOUR ORIGINAL CODE
            # This allows 638KB file to flash (if STM32 supports it)
            # ============================================================
            
            # Log file operation
            self.db.log_file_operation(username, filename, len(bin_data), "FLASH", "STARTED", ip)
            
            original_ext = os.path.splitext(filename)[1].lower()
            if original_ext not in [".bin", ".hex", ".elf"]:
                original_ext = ".bin"
            
            with tempfile.NamedTemporaryFile(suffix=original_ext, delete=False) as tmp:
                tmp_path = tmp.name
                tmp.write(bin_data)
            
            try:
                self.log(f"[*] Flashing → {filename} Size: {len(bin_data)/1024:.1f}KB")
                
                if self.target is not None:
                    try:
                        self.target.halt()
                    except:
                        pass
                
                programmer = FileProgrammer(self.session)
                programmer.program(tmp_path, reset_type='hardware', halt=True)
                
                self.log("[+] Flash successful!")
                self.db.log_file_operation(username, filename, len(bin_data), "FLASH", "SUCCESS", ip)
                
                if self.target is not None:
                    try:
                        self.target.halt()
                    except:
                        pass
                
                return {"status": "success", "msg": f"{filename} Flashed successfully!"}
                
            finally:
                try:
                    os.remove(tmp_path)
                except:
                    pass
                
        except Exception as e:
            self.log(f"[-] Flash error: {e}")
            self.db.log_file_operation(username, filename, 0, "FLASH", f"ERROR: {e}", ip)
            return {"status": "error", "msg": str(e)}

    def start_bore_tunnel(self):
        try:
            self.log("[*] Starting bore tunnel...")
            
            bore_path = self.get_bore_path()
            
            if not os.path.exists(bore_path):
                self.log("[!] bore.exe not found! Skipping tunnel.")
                return False
            
            self.bore_process = subprocess.Popen(
                [bore_path, "local", str(self.port), "--to", "bore.pub"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            
            def read_output():
                try:
                    if self.bore_process and self.bore_process.stdout:
                        for line in iter(self.bore_process.stdout.readline, ''):
                            if not line:
                                break
                            match = re.search(r'listening at (bore\.pub:\d+)', line)
                            if match and not self.public_url:
                                self.public_url = match.group(1)
                                self.log(f"[+] Public URL: {self.public_url}")
                                with open(self.get_url_file_path(), "w") as f:
                                    f.write(self.public_url)
                except Exception as e:
                    self.log(f"[-] bore reader error: {e}")
            
            thread = threading.Thread(target=read_output, daemon=True)
            thread.start()
            
            time.sleep(5)
            return True
            
        except Exception as e:
            self.log(f"[-] Bore error: {e}")
            return False
    
    def start(self):
        self.start_bore_tunnel()
        
        self.log("=" * 60)
        self.log("[*] SECURE STM32 REMOTE SERVER v4.0")
        if self.enable_ssl:
            self.log("[*] SSL/TLS Encrypted")
        else:
            self.log("[!] SSL/TLS DISABLED - INSECURE!")
        self.log("[*] Rate Limiting Enabled")
        self.log("[*] File Validation Enabled (No Size Check)")
        self.log("[*] Audit Logging Enabled")
        self.log("[*] Large File Support: Up to 10MB")
        
        if self.public_url:
            self.log(f"[+] PUBLIC URL: {self.public_url}")
        else:
            self.log("[!] No tunnel available. Local mode only.")
        
        self.log("[*] Server listening on port 65432")
        self.log("[*] Default: admin/Admin@123#Secure")
        self.log("=" * 60)
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 20 * 1024 * 1024)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 20 * 1024 * 1024)
            
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            
            self.log(f"[*] Server listening on port {self.port}")
        except Exception as e:
            self.log(f"[-] Server start error: {e}")
            return
        
        while self.is_running:
            try:
                client, addr = self.server_socket.accept()
                ip = addr[0]
                
                ok, msg = self.check_connection_limit(ip)
                if not ok:
                    self.log(f"[-] Connection denied: {ip} - {msg}")
                    try:
                        client.close()
                    except:
                        pass
                    continue
                
                if self.enable_ssl and self.ssl_context:
                    try:
                        client = self.ssl_context.wrap_socket(client, server_side=True)
                        self.log(f"[+] SSL connection from {ip}")
                    except Exception as e:
                        self.log(f"[-] SSL handshake failed: {ip} - {e}")
                        try:
                            client.close()
                        except:
                            pass
                        continue
                
                self.log(f"[*] Client connected: {ip}")
                threading.Thread(
                    target=self.handle_client, 
                    args=(client, addr), 
                    daemon=True
                ).start()
            except Exception as e:
                if self.is_running:
                    self.log(f"[-] Accept error: {e}")
                pass
        
        if self.server_socket:
            self.server_socket.close()
        self.log("[*] Server stopped")
    
    def handle_client(self, client, addr):
        authenticated = False
        username = "unknown"
        ip = addr[0]
        
        try:
            client.settimeout(120)
            buffer = b''
            
            while True:
                try:
                    chunk = client.recv(1024 * 1024)
                    if not chunk:
                        break
                    buffer += chunk
                    
                    try:
                        req = json.loads(buffer.decode('utf-8'))
                        buffer = b''
                    except json.JSONDecodeError:
                        continue
                    
                    cmd = req.get("cmd")
                    
                    ok, msg = self.check_rate_limit(ip)
                    if not ok:
                        client.send(json.dumps({
                            "status": "error",
                            "msg": f"Rate limit: {msg}"
                        }).encode('utf-8'))
                        continue
                    
                    if cmd == "LOGIN":
                        resp = self.handle_login(
                            req.get("username"),
                            req.get("password"),
                            ip
                        )
                        if resp.get("status") == "success":
                            authenticated = True
                            username = req.get("username")
                            self.authenticated_clients.add(addr)
                        client.send(json.dumps(resp).encode('utf-8'))
                        continue
                    
                    if not authenticated and addr not in self.authenticated_clients:
                        client.send(json.dumps({
                            "status": "error",
                            "msg": "Authentication required. Please login first."
                        }).encode('utf-8'))
                        continue
                    
                    if cmd == "CONNECT":
                        resp = self.connect_device()
                    elif cmd == "READ_RAM":
                        resp = self.read_ram(req.get("addr"))
                    elif cmd == "WRITE_RAM":
                        resp = self.write_ram(req.get("addr"), req.get("val"))
                    elif cmd == "RESET":
                        resp = self.reset_device()
                    elif cmd == "FLASH_DEVICE":
                        resp = self.flash_binary(
                            req.get("file_data"), 
                            req.get("filename", "firmware.bin"),
                            username,
                            ip
                        )
                    elif cmd == "FLASH_CHUNK":
                        resp = self.handle_flash_chunk(
                            req, 
                            addr, 
                            username,
                            ip
                        )
                    else:
                        resp = {"status": "error", "msg": "Unknown Command"}
                    
                    client.send(json.dumps(resp).encode('utf-8'))
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    self.log(f"[-] Error: {e}")
                    break
                
        except Exception as e:
            self.log(f"[-] Client handler error: {e}")
        finally:
            if addr in self.authenticated_clients:
                self.authenticated_clients.remove(addr)
            self.connection_limiter[ip] = max(0, self.connection_limiter[ip] - 1)
            try:
                client.close()
            except:
                pass
    
    def stop(self):
        self.is_running = False
        if self.bore_process:
            try:
                self.bore_process.terminate()
                self.log("[+] bore tunnel stopped")
            except:
                pass
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        if self.session:
            try:
                self.session.close()
            except:
                pass

# ============================================================
# SECURE GUI
# ============================================================
class SecureSTM32GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure STM32 Remote Server")
        self.root.geometry("950x850")
        self.root.configure(bg='#2c3e50')
        
        self.server = None
        self.server_thread = None
        self.is_server_running = False
        
        self.setup_gui()
        
    def setup_gui(self):
        main_frame = tk.Frame(self.root, bg='#2c3e50')
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        title_frame = tk.Frame(main_frame, bg='#2c3e50')
        title_frame.pack(fill="x", pady=(0, 20))
        
        tk.Label(title_frame, text="Secure STM32 Remote Server",
                font=("Arial", 20, "bold"), fg='#3498db', bg='#2c3e50').pack()
        tk.Label(title_frame, text="SSL/TLS • Rate Limited • Audit Logged • Large File Support",
                font=("Arial", 11), fg='#bdc3c7', bg='#2c3e50').pack()
        
        status_frame = tk.Frame(main_frame, bg='#34495e', padx=15, pady=15)
        status_frame.pack(fill="x", pady=(0, 15))
        status_frame.configure(relief='raised', bd=2)
        
        self.status_label = tk.Label(status_frame, text="⚪ Server Stopped",
                                     font=("Arial", 12, "bold"), fg='#e74c3c', bg='#34495e')
        self.status_label.pack(side="left", padx=10)
        
        tk.Label(status_frame, text=" Public URL:", font=("Arial", 11, "bold"),
                fg='#ecf0f1', bg='#34495e').pack(side="left", padx=(30, 10))
        
        self.url_label = tk.Label(status_frame, text="Waiting for tunnel...",
                                  font=("Arial", 11), fg='#f1c40f', bg='#34495e')
        self.url_label.pack(side="left")
        
        btn_frame = tk.Frame(main_frame, bg='#2c3e50')
        btn_frame.pack(fill="x", pady=(0, 15))
        
        self.start_btn = tk.Button(btn_frame, text=" Start Server",
                                  command=self.start_server,
                                  bg='#2ecc71', fg='white',
                                  font=("Arial", 12, "bold"),
                                  padx=20, pady=8,
                                  relief='raised', bd=2)
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = tk.Button(btn_frame, text=" Stop Server",
                                 command=self.stop_server,
                                 bg='#e74c3c', fg='white',
                                 font=("Arial", 12, "bold"),
                                 padx=20, pady=8,
                                 relief='raised', bd=2,
                                 state='disabled')
        self.stop_btn.pack(side="left", padx=5)
        
        self.ssl_var = tk.BooleanVar(value=True)
        ssl_check = tk.Checkbutton(btn_frame, text=" SSL/TLS",
                                   variable=self.ssl_var,
                                   bg='#2c3e50', fg='#ecf0f1',
                                   selectcolor='#34495e',
                                   font=("Arial", 10))
        ssl_check.pack(side="left", padx=(20, 0))
        
        user_frame = tk.LabelFrame(main_frame, text="  User Management ",
                                  font=("Arial", 12, "bold"),
                                  fg='#ecf0f1', bg='#34495e',
                                  padx=15, pady=15)
        user_frame.pack(fill="x", pady=(0, 15))
        
        user_btn_frame = tk.Frame(user_frame, bg='#34495e')
        user_btn_frame.pack(fill="x")
        
        tk.Button(user_btn_frame, text=" Add User",
                 command=self.add_user,
                 bg='#3498db', fg='white',
                 font=("Arial", 10), padx=15, pady=5).pack(side="left", padx=5)
        
        tk.Button(user_btn_frame, text=" Delete User",
                 command=self.delete_user,
                 bg='#e67e22', fg='white',
                 font=("Arial", 10), padx=15, pady=5).pack(side="left", padx=5)
        
        tk.Button(user_btn_frame, text=" List Users",
                 command=self.list_users,
                 bg='#9b59b6', fg='white',
                 font=("Arial", 10), padx=15, pady=5).pack(side="left", padx=5)
        
        tk.Button(user_btn_frame, text=" Audit Log",
                 command=self.view_audit_log,
                 bg='#1abc9c', fg='white',
                 font=("Arial", 10), padx=15, pady=5).pack(side="left", padx=5)
        
        self.user_list = tk.Text(user_frame, height=4,
                                font=("Consolas", 9),
                                bg='#2c3e50', fg='#ecf0f1',
                                relief='flat', bd=0)
        self.user_list.pack(fill="x", pady=(10, 0))
        self.user_list.config(state='disabled')
        
        stm32_frame = tk.LabelFrame(main_frame, text="  STM32 Control ",
                                   font=("Arial", 12, "bold"),
                                   fg='#ecf0f1', bg='#34495e',
                                   padx=15, pady=15)
        stm32_frame.pack(fill="x", pady=(0, 15))
        
        btn_grid = tk.Frame(stm32_frame, bg='#34495e')
        btn_grid.pack()
        
        buttons = [
            (" Reset STM32", self.reset_stm32, '#e74c3c'),
            (" Flash File", self.flash_file, '#2ecc71'),
            (" Read Register", self.read_register, '#3498db'),
            (" Write Register", self.write_register, '#f39c12'),
        ]
        
        for i, (text, cmd, color) in enumerate(buttons):
            tk.Button(btn_grid, text=text,
                     command=cmd,
                     bg=color, fg='white',
                     font=("Arial", 10, "bold"),
                     padx=20, pady=8,
                     relief='raised', bd=2,
                     width=15).grid(row=i//4, column=i%4, padx=5, pady=5)
        
        self.progress_frame = tk.Frame(main_frame, bg='#34495e', padx=15, pady=10)
        self.progress_frame.pack(fill="x", pady=(0, 10))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame,
                                           variable=self.progress_var,
                                           maximum=100,
                                           length=400)
        self.progress_bar.pack(side="left", padx=(0, 20))
        
        self.progress_label = tk.Label(self.progress_frame,
                                      text="Ready",
                                      font=("Arial", 9),
                                      fg='#ecf0f1', bg='#34495e')
        self.progress_label.pack(side="left")
        
        log_frame = tk.LabelFrame(main_frame, text=" Server Log ",
                                 font=("Arial", 12, "bold"),
                                 fg='#ecf0f1', bg='#34495e',
                                 padx=15, pady=15)
        log_frame.pack(fill="both", expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame,
                                                 height=12,
                                                 font=("Consolas", 9),
                                                 bg='#1e1e1e',
                                                 fg='#00ff00',
                                                 relief='flat')
        self.log_text.pack(fill="both", expand=True)
        
        log_btn_frame = tk.Frame(log_frame, bg='#34495e')
        log_btn_frame.pack(fill="x", pady=(5, 0))
        
        tk.Button(log_btn_frame, text="Clear Log",
                 command=self.clear_log,
                 bg='#95a5a6', fg='white',
                 font=("Arial", 9), padx=15, pady=3).pack(side="right")
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def log_message(self, message):
        self.log_text.config(state='normal')
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
    
    def clear_log(self):
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')
    
    def update_progress(self, value, message=""):
        self.progress_var.set(value)
        if message:
            self.progress_label.config(text=message)
        self.root.update_idletasks()
    
    def start_server(self):
        if self.is_server_running:
            return
        
        self.is_server_running = True
        self.status_label.config(text="Server Running", fg='#2ecc71')
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        
        self.server = SecureSTM32Server(enable_ssl=self.ssl_var.get())
        self.server.set_log_callback(self.log_message)
        
        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_thread.start()
        
        self.root.after(5000, self.update_url)
        self.log_message("[+] Secure server started!")
        self.list_users()
    
    def update_url(self):
        if self.server and self.server.public_url:
            self.url_label.config(text=self.server.public_url, fg='#2ecc71')
        else:
            self.url_label.config(text="Tunnel unavailable", fg='#e74c3c')
            self.root.after(5000, self.update_url)
    
    def run_server(self):
        if self.server:
            self.server.start()
    
    def stop_server(self):
        if not self.is_server_running:
            return
        
        self.log_message("[*] Stopping server...")
        self.is_server_running = False
        
        if self.server:
            self.server.stop()
            self.server = None
        
        self.status_label.config(text="⚪ Server Stopped", fg='#e74c3c')
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.url_label.config(text="Waiting for tunnel...", fg='#f1c40f')
        self.progress_var.set(0)
        self.progress_label.config(text="Ready")
        
        self.log_message("[+] Server stopped.")
    
    def add_user(self):
        if not self.is_server_running or not self.server:
            messagebox.showerror("Error", "Server is not running!")
            return
        
        username = simpledialog.askstring("Add User", "Enter username:")
        if not username:
            return
        
        password = simpledialog.askstring("Add User",
                                         "Enter password (min 8 chars):",
                                         show='*')
        if not password or len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters!")
            return
        
        is_admin = messagebox.askyesno("Add User", "Give admin privileges?")
        
        success, msg = self.server.db.add_user(username, password, is_admin)
        if success:
            messagebox.showinfo("Success", f"User {username} added successfully!")
            self.list_users()
            self.server.db.log_audit("admin", "ADD_USER", "localhost",
                                    f"Added user: {username}", "SUCCESS")
        else:
            messagebox.showerror("Error", f"Failed to add user: {msg}")
    
    def delete_user(self):
        if not self.is_server_running or not self.server:
            messagebox.showerror("Error", "Server is not running!")
            return
        
        username = simpledialog.askstring("Delete User", "Enter username to delete:")
        if not username:
            return
        
        if username == "admin":
            messagebox.showerror("Error", "Cannot delete admin user!")
            return
        
        if messagebox.askyesno("Confirm", f"Delete user {username}?"):
            success, msg = self.server.db.delete_user(username)
            if success:
                messagebox.showinfo("Success", msg)
                self.list_users()
                self.server.db.log_audit("admin", "DELETE_USER", "localhost",
                                        f"Deleted user: {username}", "SUCCESS")
            else:
                messagebox.showerror("Error", msg)
    
    def list_users(self):
        if not self.is_server_running or not self.server:
            return
        
        users = self.server.db.get_all_users()
        self.user_list.config(state='normal')
        self.user_list.delete(1.0, tk.END)
        
        if users:
            header = "Username          Role    Created                 Last Login\n"
            self.user_list.insert(tk.END, header)
            self.user_list.insert(tk.END, "-" * 70 + "\n")
            for username, is_admin, created_at, last_login in users:
                role = "Admin" if is_admin else "User"
                last = last_login if last_login else "Never"
                self.user_list.insert(tk.END,
                    f"{username:16} {role:6}  {created_at[:19]}  {last[:19]}\n")
        else:
            self.user_list.insert(tk.END, "No users found.\n")
        
        self.user_list.config(state='disabled')
    
    def view_audit_log(self):
        if not self.is_server_running or not self.server:
            messagebox.showerror("Error", "Server is not running!")
            return
        
        audit_window = tk.Toplevel(self.root)
        audit_window.title("Audit Log")
        audit_window.geometry("800x500")
        audit_window.configure(bg='#2c3e50')
        
        log_text = scrolledtext.ScrolledText(audit_window,
                                            font=("Consolas", 9),
                                            bg='#1e1e1e', fg='#00ff00')
        log_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        try:
            conn = sqlite3.connect(self.server.db.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT timestamp, username, action, ip, status FROM audit_log ORDER BY id DESC LIMIT 100"
            )
            results = cursor.fetchall()
            conn.close()
            
            if results:
                header = "Timestamp           Username    Action              IP              Status\n"
                log_text.insert(tk.END, header)
                log_text.insert(tk.END, "-" * 80 + "\n")
                for ts, user, action, ip, status in results:
                    status_color = "SUCCESS" if status == "SUCCESS" else "FAILED"
                    log_text.insert(tk.END,
                        f"{ts[:19]}  {user:10} {action:18} {ip:15} {status_color}\n")
            else:
                log_text.insert(tk.END, "No audit logs found.\n")
            
            log_text.config(state='disabled')
            
        except Exception as e:
            log_text.insert(tk.END, f"Error loading audit log: {e}\n")
    
    def reset_stm32(self):
        if not self.is_server_running or not self.server:
            messagebox.showerror("Error", "Server is not running!")
            return
        
        self.log_message("[*] Resetting STM32...")
        if not self.server.target:
            self.server.connect_device()
        resp = self.server.reset_device()
        self.log_message(f"[+] {resp.get('msg', 'Reset done')}")
    
    def read_register(self):
        if not self.is_server_running or not self.server:
            messagebox.showerror("Error", "Server is not running!")
            return
        
        addr = simpledialog.askstring("Read Register",
                                     "Enter address (e.g., 0x20000000):",
                                     initialvalue="0x20000000")
        if addr:
            if not self.server.target:
                self.server.connect_device()
            resp = self.server.read_ram(addr)
            if resp.get("status") == "success":
                value = resp.get('value', 'N/A')
                self.log_message(f"[+] {addr} = {value}")
                messagebox.showinfo("Register Value", f"{addr} = {value}")
            else:
                self.log_message(f"[-] Read failed: {resp.get('msg', 'Unknown')}")
    
    def write_register(self):
        if not self.is_server_running or not self.server:
            messagebox.showerror("Error", "Server is not running!")
            return
        
        addr = simpledialog.askstring("Write Register",
                                     "Enter address (e.g., 0x20000000):",
                                     initialvalue="0x20000000")
        if not addr:
            return
        
        val = simpledialog.askstring("Write Register",
                                    "Enter value (e.g., 0x12345678):",
                                    initialvalue="0x12345678")
        if not val:
            return
        
        if not self.server.target:
            self.server.connect_device()
        resp = self.server.write_ram(addr, val)
        self.log_message(f"[+] {resp.get('msg', 'Write done')}")
    
    def flash_file(self):
        if not self.is_server_running or not self.server:
            messagebox.showerror("Error", "Server is not running!")
            return
        
        path = filedialog.askopenfilename(
            title="Select Firmware File",
            filetypes=[
                ("Binary files", "*.bin"),
                ("Hex files", "*.hex"),
                ("ELF files", "*.elf"),
                ("All files", "*.*")
            ]
        )
        if not path:
            return
        
        try:
            file_size = os.path.getsize(path)
            file_size_kb = file_size / 1024
            file_size_mb = file_size / (1024 * 1024)
            
            self.log_message(f"[*] Flashing {os.path.basename(path)} ({file_size_kb:.1f}KB)...")
            self.update_progress(0, "Starting flash...")
            
            if not self.server.target:
                self.server.connect_device()
            
            with open(path, "rb") as f:
                file_data = f.read()
            
            b64_data = base64.b64encode(file_data).decode('utf-8')
            resp = self.server.flash_binary(
                b64_data,
                os.path.basename(path),
                "admin",
                "localhost"
            )
            
            if resp.get("status") == "success":
                self.log_message("[+] Flash successful!")
                self.update_progress(100, "Flash complete!")
                messagebox.showinfo("Success",
                    f" Firmware flashed successfully!\n{os.path.basename(path)}\nSize: {file_size_kb:.1f}KB")
            else:
                self.log_message(f"[-] Flash failed: {resp.get('msg', 'Unknown')}")
                self.update_progress(0, "Flash failed!")
                messagebox.showerror("Error",
                    f"Flash failed!\n{resp.get('msg', 'Unknown')}")
                
        except Exception as e:
            self.log_message(f"[-] Flash error: {e}")
            self.update_progress(0, "Error!")
            messagebox.showerror("Error", f"Flash error:\n{str(e)}")
    
    def on_closing(self):
        if self.is_server_running:
            if messagebox.askokcancel("Quit", "Server is running. Stop and exit?"):
                self.stop_server()
                self.root.destroy()
        else:
            self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureSTM32GUI(root)
    root.mainloop()
