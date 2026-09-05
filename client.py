import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import json
import os
import threading
import base64
import ssl
import secrets
from datetime import datetime

class SecureSTM32Client:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure STM32 Remote Client")
        self.root.geometry("700x650")
        self.root.configure(bg='#2c3e50')
        
        self.socket = None
        self.authenticated = False
        self.username = None
        self.is_admin = False
        self.server_host = None
        self.server_port = 65432
        self.session_id = None
        
        # Large file settings
        self.CHUNK_SIZE = 512 * 1024  # 512KB chunks
        self.MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
        
        # SSL Context
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        self.auto_discover_server()
        self.setup_ui()
        self.log("[*] Secure Client Ready")
        self.log("[*] SSL/TLS encryption enabled")
        self.log("[*] Large File Support: Up to 10MB")
        self.log("[*] Enter your credentials to connect")
    
    def auto_discover_server(self):
        try:
            url_file = "server_url.txt"
            if os.path.exists(url_file):
                with open(url_file, 'r') as f:
                    url = f.read().strip()
                    if ':' in url:
                        host, port = url.split(':')
                        self.server_host = host
                        self.server_port = int(port)
                        return
            self.server_host = None
        except:
            self.server_host = None
    
    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg='#2c3e50', padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)
        
        tk.Label(main_frame, text="Secure STM32 Remote Client",
                font=("Arial", 20, "bold"), fg='#3498db', bg='#2c3e50').pack(pady=(0, 5))
        
        tk.Label(main_frame, text="SSL/TLS Encrypted Connection • Large File Support",
                font=("Arial", 11), fg='#bdc3c7', bg='#2c3e50').pack(pady=(0, 20))
        
        # Connection Frame
        conn_frame = tk.LabelFrame(main_frame, text=" Server Connection ",
                                  font=("Arial", 11, "bold"),
                                  fg='#ecf0f1', bg='#34495e',
                                  padx=15, pady=15)
        conn_frame.pack(fill="x", pady=(0, 15))
        
        tk.Label(conn_frame, text="Server URL:", font=("Arial", 10),
                fg='#ecf0f1', bg='#34495e').grid(row=0, column=0, sticky="w", pady=5)
        self.url_var = tk.StringVar(value=self.server_host or "")
        tk.Entry(conn_frame, textvariable=self.url_var,
                font=("Arial", 10), width=30,
                bg='#2c3e50', fg='#ecf0f1').grid(row=0, column=1, pady=5, padx=(10, 0))
        
        tk.Label(conn_frame, text="Port:", font=("Arial", 10),
                fg='#ecf0f1', bg='#34495e').grid(row=1, column=0, sticky="w", pady=5)
        self.port_var = tk.StringVar(value=str(self.server_port))
        tk.Entry(conn_frame, textvariable=self.port_var,
                font=("Arial", 10), width=10,
                bg='#2c3e50', fg='#ecf0f1').grid(row=1, column=1, sticky="w", pady=5, padx=(10, 0))
        
        # Login Frame
        login_frame = tk.LabelFrame(main_frame, text=" Login ",
                                   font=("Arial", 11, "bold"),
                                   fg='#ecf0f1', bg='#34495e',
                                   padx=15, pady=15)
        login_frame.pack(fill="x", pady=(0, 15))
        
        tk.Label(login_frame, text="Username:", font=("Arial", 10, "bold"),
                fg='#ecf0f1', bg='#34495e').grid(row=0, column=0, sticky="w", pady=5)
        self.username_var = tk.StringVar()
        tk.Entry(login_frame, textvariable=self.username_var,
                font=("Arial", 11), width=25,
                bg='#2c3e50', fg='#ecf0f1').grid(row=0, column=1, pady=5, padx=(10, 0))
        
        tk.Label(login_frame, text="Password:", font=("Arial", 10, "bold"),
                fg='#ecf0f1', bg='#34495e').grid(row=1, column=0, sticky="w", pady=5)
        self.password_var = tk.StringVar()
        tk.Entry(login_frame, textvariable=self.password_var,
                font=("Arial", 11), width=25, show="*",
                bg='#2c3e50', fg='#ecf0f1').grid(row=1, column=1, pady=5, padx=(10, 0))
        
        self.connect_btn = tk.Button(login_frame, text="CONNECT & LOGIN",
                                    command=self.connect_and_login,
                                    bg='#3498db', fg='white',
                                    font=("Arial", 12, "bold"),
                                    padx=30, pady=8,
                                    relief='raised', bd=2)
        self.connect_btn.grid(row=2, column=0, columnspan=2, pady=(15, 0))
        
        self.status_label = tk.Label(main_frame, text="Not Connected",
                                    font=("Arial", 11, "bold"),
                                    fg='#95a5a6', bg='#2c3e50')
        self.status_label.pack(pady=(0, 10))
        
        # Security Info
        info_frame = tk.LabelFrame(main_frame, text=" Security Information ",
                                  font=("Arial", 10, "bold"),
                                  fg='#ecf0f1', bg='#34495e',
                                  padx=15, pady=10)
        info_frame.pack(fill="x", pady=(0, 10))
        
        tk.Label(info_frame, text=" SSL/TLS Encrypted Connection",
                font=("Arial", 9), fg='#2ecc71', bg='#34495e').pack(anchor="w")
        tk.Label(info_frame, text=" Rate Limiting Protection",
                font=("Arial", 9), fg='#2ecc71', bg='#34495e').pack(anchor="w")
        tk.Label(info_frame, text=" File Validation & Malware Scanning",
                font=("Arial", 9), fg='#2ecc71', bg='#34495e').pack(anchor="w")
        tk.Label(info_frame, text=" Audit Logging",
                font=("Arial", 9), fg='#2ecc71', bg='#34495e').pack(anchor="w")
        tk.Label(info_frame, text=" Large File Support (up to 10MB)",
                font=("Arial", 9), fg='#2ecc71', bg='#34495e').pack(anchor="w")
               
        # Log Area
        tk.Label(main_frame, text=" Logs:", font=("Arial", 9, "bold"),
                fg='#ecf0f1', bg='#2c3e50').pack(anchor="w", pady=(5, 0))
        
        self.log_area = scrolledtext.ScrolledText(main_frame, height=12,
                                                 bg='#1e1e1e', fg='#00ff00',
                                                 font=("Consolas", 9),
                                                 relief='flat')
        self.log_area.pack(fill="both", expand=True, pady=(5, 0))
    
    def log(self, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log_area.see(tk.END)
    
    # ============================================================
    # COMMAND SENDING METHOD
    # ============================================================
    def send_cmd(self, cmd, params=None):
        """Send command to server and get response"""
        if not self.socket:
            self.log("[-] No socket connection!")
            return None
        
        try:
            payload = {"cmd": cmd}
            if params:
                payload.update(params)
            
            # Send command
            json_data = json.dumps(payload).encode('utf-8')
            self.socket.send(json_data)
            
            # Receive response
            data = b''
            while True:
                try:
                    chunk = self.socket.recv(1024 * 1024)
                    if not chunk:
                        break
                    data += chunk
                    try:
                        return json.loads(data.decode('utf-8'))
                    except json.JSONDecodeError:
                        continue
                except socket.timeout:
                    break
                except:
                    break
            
            if data:
                try:
                    return json.loads(data.decode('utf-8'))
                except:
                    return None
            return None
            
        except socket.timeout:
            self.log("[-] Command timeout")
            return None
        except ConnectionResetError:
            self.log("[-] Connection lost")
            self.authenticated = False
            self.status_label.config(text=" Disconnected", fg='#95a5a6')
            self.connect_btn.config(text=" CONNECT & LOGIN", bg='#3498db', state='normal')
            return None
        except Exception as e:
            self.log(f"[-] Command error: {e}")
            return None
    
    # ============================================================
    # CONNECT AND LOGIN
    # ============================================================
    def connect_and_login(self):
        """Secure connection and login"""
        server_host = self.url_var.get().strip()
        server_port_str = self.port_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        
        if not server_host:
            messagebox.showerror("Error", "Please enter Server URL!")
            return
        
        if not username:
            messagebox.showerror("Error", "Please enter Username!")
            return
        
        if not password:
            messagebox.showerror("Error", "Please enter Password!")
            return
        
        try:
            server_port = int(server_port_str) if server_port_str else 65432
        except ValueError:
            server_port = 65432
        
        try:
            self.log(f"[*] Connecting to {server_host}:{server_port}...")
            
            # Create socket
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(30)
            raw_socket.connect((server_host, server_port))
            
            # Wrap with SSL
            self.socket = self.ssl_context.wrap_socket(raw_socket, server_hostname=server_host)
            self.log("[+] SSL/TLS connection established")
            
            # Set buffer
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 10 * 1024 * 1024)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 10 * 1024 * 1024)
            
            # Send login
            resp = self.send_cmd("LOGIN", {
                "username": username,
                "password": password
            })
            
            if resp is not None and resp.get("status") == "success":
                self.authenticated = True
                self.username = username
                self.is_admin = resp.get("is_admin", False)
                self.session_id = resp.get("session_id", "")
                
                self.status_label.config(
                    text=f" Connected as {username} {'(Admin)' if self.is_admin else ''}",
                    fg='#2ecc71'
                )
                self.log(f"[+] Login successful! Welcome {username}")
                self.connect_btn.config(text=" CONNECTED", bg='#27ae60', state='disabled')
                
                # Auto-connect to STM32
                self.connect_stm32()
                
                messagebox.showinfo("Success",
                    f" Welcome {username}!\n\n"
                    f" Connection is encrypted with SSL/TLS\n"
                    f" You are now connected to STM32 server.\n"
                    f" You can close this window anytime.")
            else:
                error_msg = resp.get('msg', 'Invalid credentials') if resp else 'No response'
                self.log(f"[-] Login failed: {error_msg}")
                self.status_label.config(text=" Login Failed", fg='#e74c3c')
                messagebox.showerror("Error", f"Login failed!\n{error_msg}")
                
        except ssl.SSLError as e:
            self.log(f"[-] SSL error: {e}")
            messagebox.showerror("SSL Error",
                "SSL/TLS handshake failed!\n\n"
                "Make sure server has SSL enabled.\n"
                f"Error: {e}")
        except socket.timeout:
            self.log("[-] Connection timeout")
            messagebox.showerror("Error", "Server not responding!\nCheck if server is running.")
        except ConnectionRefusedError:
            self.log("[-] Connection refused")
            messagebox.showerror("Error", "Server not running!\nStart the server first.")
        except Exception as e:
            self.log(f"[-] Error: {e}")
            messagebox.showerror("Error", f"Connection error:\n{e}")
    
    def connect_stm32(self):
        """Connect to STM32 hardware automatically"""
        self.log("[*] Connecting to STM32...")
        resp = self.send_cmd("CONNECT")
        if resp is not None and resp.get("status") == "success":
            self.log("[+] STM32 connected!")
        else:
            error_msg = resp.get('msg', 'Unknown error') if resp else 'No response'
            self.log(f"[-] STM32 connection failed: {error_msg}")
    
    def on_closing(self):
        """Clean up on close"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.root.destroy()


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureSTM32Client(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
