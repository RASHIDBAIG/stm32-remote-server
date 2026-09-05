# stm32-remote-server
Secure remote firmware update system for STM32 microcontrollers with SSL/TLS, user authentication, and audit logging.
Secure STM32 Remote Programmer

A production-ready remote firmware update system for STM32 microcontrollers with enterprise-grade security.

Server handles user authentication, firmware storage, and STM32 programming via ST-Link.
Client connects securely over SSL/TLS to request and receive firmware updates.


Features

Server:
- SSL/TLS Encryption
- bcrypt Password Hashing
- User Registration and Management (Add/Delete/List Users)
- Rate Limiting (100 requests per minute)
- Account Lockout (5 failed attempts)
- Complete Audit Logging
- Chunked File Transfer (10MB support)
- Full GUI Interface (Tkinter)
- STM32 Flash, Read, Write, Reset
- Public URL via bore.pub

Client:
- SSL/TLS Encrypted Connection
- Secure Login with Username and Password
- 10MB File Support
- Real-time Logs
- Auto-Discovery via server_url.txt
- Auto-Connect to STM32


User Management

The server allows you to add, delete, and list users easily through the GUI.

How to Add a User:
1. Start the server
2. Click "Add User" button
3. Enter username (e.g., client1, device2, etc.)
4. Enter password (minimum 8 characters)
5. Choose admin privileges (Yes/No)
6. User is saved to database

How to Delete a User:
1. Click "Delete User" button
2. Enter username to delete
3. Confirm deletion
4. User is removed from database

How to List All Users:
1. Click "List Users" button
2. All users are displayed in the GUI
3. Shows: username, role (Admin/User), created date, last login

You can create unlimited users. Each user has their own username and password for secure access.


Tech Stack

Language: Python 3.x
Database: SQLite
Password Hashing: bcrypt
Encryption: SSL/TLS (built-in)
STM32 Programming: pyOCD
GUI: Tkinter
Networking: Python sockets


Project Structure

stm32-remote-server/
|
+-- server.py                 # Server application (GUI)
+-- stm32_client.py           # Client application (GUI)
+-- requirements.txt          # Python dependencies
+-- README.md                 # This file
+-- LICENSE                   # MIT License
+-- .gitignore                # Python gitignore
|
+-- server.crt                # SSL certificate (auto-generated)
+-- server.key                # SSL private key (auto-generated)
+-- users_secure.db           # SQLite database (auto-created)
+-- server_url.txt            # Auto-discovery file (auto-created)
|
+-- screenshots/              # (Optional) Screenshots
    +-- server_gui.png
    +-- client_gui.png


Installation

1. Install Python 3.x
   Download from python.org and check "Add to PATH" during installation.
   Verify: python --version

2. Install Dependencies
   Create requirements.txt file with:
   pyocd
   bcrypt
   cryptography
   
   Then run: pip install -r requirements.txt
   Or install individually: pip install pyocd bcrypt cryptography

3. Install Tkinter (GUI)
   Tkinter comes pre-installed with Python on most systems.
   Verify: python -c "import tkinter; print('Tkinter OK')"
   
   If not installed:
   - Ubuntu/Debian: sudo apt-get install python3-tk
   - Windows/Mac: Reinstall Python and check Tkinter option

4. Install ST-Link Drivers
   Download from ST Website and install.

5. Optional: bore.exe (Public URL)
   Download bore.exe from bore.pub and place it in the project folder.


Quick Start

1. Clone or Download
   git clone https://github.com/RASHIDBAIG/stm32-remote-server.git
   cd stm32-remote-server

2. Start the Server
   python server.py

3. Start the Client
   python stm32_client.py


Server Setup and Usage

Starting the Server:
1. Run python server.py
2. Click "Start Server"
3. Server auto-generates SSL certificates and database
4. Default admin account created automatically

Default Admin Account:
- Username: admin
- Password: Admin@123#Secure

IMPORTANT: Change this password immediately in production!

Server GUI Buttons:
- Start Server: Start the server
- Stop Server: Stop the server
- Add User: Add new user (Unlimited users can be added)
- Delete User: Delete existing user
- List Users: Show all users with their details
- Audit Log: View audit log
- Reset STM32: Reset connected STM32
- Flash File: Flash firmware (.bin/.hex/.elf)
- Read Register: Read STM32 RAM
- Write Register: Write STM32 RAM

Server Logs:
The server displays real-time logs for client connections, SSL/TLS handshakes, user logins, file operations, and errors.


Client Setup and Usage

Starting the Client:
python stm32_client.py

Client Login:
1. Enter Server IP or Hostname (or auto-discovered via server_url.txt)
2. Enter Port (default: 65432)
3. Enter your Username and Password
4. Click "CONNECT and LOGIN"

Client Auto-Discovery:
The client automatically looks for server_url.txt (created by bore.pub tunnel). If found, it auto-fills the server URL.

Client Logs Example:
[14:30:15] Secure Client Ready
[14:30:15] SSL/TLS encryption enabled
[14:30:20] Connecting to 192.168.1.100:65432...
[14:30:21] SSL/TLS connection established
[14:30:21] Login successful! Welcome admin
[14:30:21] Connecting to STM32...
[14:30:22] STM32 connected!


Security Features

- SSL/TLS Encryption: All network traffic encrypted
- bcrypt Password Hashing: Passwords stored securely with salt
- Rate Limiting: 100 requests per minute per IP
- Account Lockout: 5 failed attempts leads to 15 min lock
- Audit Logging: All actions logged with timestamps
- File Validation: Extension and suspicious content check
- Session Management: Each connection gets unique session ID


Database Schema

Users Table:
- id INTEGER PRIMARY KEY
- username TEXT UNIQUE
- password_hash TEXT
- salt TEXT
- is_admin INTEGER
- created_at TIMESTAMP
- last_login TIMESTAMP
- login_attempts INTEGER
- locked INTEGER
- lock_until TIMESTAMP

Audit Log Table:
- id INTEGER PRIMARY KEY
- timestamp TIMESTAMP
- username TEXT
- action TEXT
- ip TEXT
- details TEXT
- status TEXT

File Operations Table:
- id INTEGER PRIMARY KEY
- timestamp TIMESTAMP
- username TEXT
- filename TEXT
- file_size INTEGER
- action TEXT
- status TEXT
- ip TEXT


STM32 Hardware Support

This project supports almost all STM32 Cortex-M devices through pyOCD.

Supported Families:
- STM32F1: STM32F103RC, STM32F103C8 (Full)
- STM32F0: STM32F051, STM32F072 (Full)
- STM32F4: STM32F407, STM32F429 (Full)
- STM32F7: STM32F767, STM32F746 (Full)
- STM32H7: STM32H750, STM32H743 (Full)
- STM32L4: STM32L475, STM32L496 (Full)
- STM32U5: STM32U585 (Full)
- Any Cortex-M: Generic Cortex-M (Debug and Flash)

How It Works:
The code automatically tries these targets in order:
1. Specific STM32 targets (e.g., stm32f103rc)
2. Generic cortex_m target (fallback for any Cortex-M device)

Adding New STM32 Chips:
To add support for a new STM32 chip, add its target name to the list in server.py:
targets = [
    "stm32f103rc",
    "stm32f407vg",   # Add your chip here
    "stm32h750vbtx", # Add your chip here
    "stm32f103",
    "stm32f051",
    "cortex_m"
]

To see all supported targets: pyocd list --targets


Dependencies

Core Dependencies:
pip install pyocd bcrypt cryptography

System Requirements:
- Python 3.6 or higher
- Tkinter (usually pre-installed)
- ST-Link Drivers
- USB connection for ST-Link


Troubleshooting - Common Issues and Solutions

Issue 1: pip not found or not recognized
Solution: During Python installation, check "Add to PATH". If already installed, reinstall Python and select PATH option.

Issue 2: tkinter not found / No module named tkinter
Solution: 
- Ubuntu/Debian: sudo apt-get install python3-tk
- Windows/Mac: Reinstall Python and check Tkinter option
- Verify: python -c "import tkinter; print('OK')"

Issue 3: ModuleNotFoundError: No module named 'pyocd'
Solution: pip install pyocd. If error occurs: pip install --upgrade pip then pip install pyocd

Issue 4: ModuleNotFoundError: No module named 'bcrypt'
Solution: pip install bcrypt

Issue 5: ModuleNotFoundError: No module named 'cryptography'
Solution: pip install cryptography

Issue 6: ST-Link not detected / No probe found
Solution: 
- Install ST-Link driver from ST website
- Change USB cable
- Try different USB port
- Check Device Manager for ST-Link

Issue 7: SSL certificate error / SSL handshake failed
Solution: Server auto-generates certificates. If error occurs, delete server.crt and server.key from server folder and restart server.

Issue 8: Connection refused / Cannot connect to server
Solution: 
- Confirm server is running
- Check firewall port 65432 is open
- Verify IP address is correct
- Verify port number is correct (default: 65432)

Issue 9: Authentication failed / Invalid credentials
Solution: 
- Check username and password
- Default admin: admin / Admin@123#Secure
- If password changed, remember new password
- If user locked, wait 15 minutes

Issue 10: File too large error
Solution: Default limit is 10MB. For larger files, change MAX_FILE_SIZE in server.py.

Issue 11: Flash failed / Programming error
Solution: 
- Confirm STM32 is properly connected
- Check target chip selection
- Check STM32 power supply
- Update pyOCD: pip install --upgrade pyocd

Issue 12: bore.exe not found / Tunnel failed
Solution: 
- Download bore.exe from bore.pub
- Place in same folder as server.py
- If not working, ignore and use local network

Issue 13: Database locked / SQLite error
Solution: 
- Close server
- Delete users_secure.db file (warning: all users will be deleted)
- Restart server (new database will be created)

Issue 14: Port already in use (Address already in use)
Solution: 
- Port 65432 is being used by another application
- Close server and restart
- Or change port in server.py


Quick Diagnostic Commands

Check Python version: python --version
Check pip: pip --version
Check installed packages: pip list
Check Tkinter: python -c "import tkinter; print('OK')"
Check pyOCD: pyocd list --targets
Check ST-Link: pyocd list --probes


Still Having Issues?

1. Check GitHub repository for updates
2. Open an issue on GitHub
3. Contact: rashidbaig123kid@gmail.com


License

This project is licensed under the MIT License.


Support

GitHub Sponsors: https://github.com/sponsors/RASHIDBAIG
Your support helps me maintain and improve this project!


Contact

GitHub: RASHIDBAIG
LinkedIn: Rashid Baig
Email: rashidbaig123kid@gmail.com


Acknowledgements

- pyOCD for STM32 programming
- bcrypt for password hashing
- Open Source Collective for fiscal hosting


Built with by Rashid Baig
