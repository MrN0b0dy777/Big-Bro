# Big Bro Network Monitor for Windows

![Big Bro Logo](./Big-Bro.jpg)

Big Bro is a robust network monitoring tool built with Python, tailored for **Windows** users. It provides real-time network monitoring, integrates with external threat detection services (VirusTotal and AbuseIPDB), and includes a user-friendly GUI with system tray support.

## Features
- **Real-time Monitoring**:
  - Tracks active network connections, including IP, port, protocol, and associated processes.
- **Threat Detection**:
  - VirusTotal integration for checking IP reputation.
  - AbuseIPDB integration for identifying potential abuse risks.
- **Cloudflare IP Detection**:
  - Identifies connections originating from Cloudflare IP ranges.
- **Custom Alerts**:
  - Provides desktop notifications with detailed risk information.
- **Process Control**:
  - Terminate or block suspicious connections with a click.
- **Advanced Filtering**:
  - Search and filter network activity by IP address or port.
- **System Tray Integration**:
  - Minimize the app to the Windows system tray for background operation.

## Installation

### Prerequisites
1. **Windows**.
2. **Python 3.8 or higher**:
   - Download from the [official Python website](https://www.python.org/downloads/).
   - During installation, check the box to **Add Python to PATH**.
3. **Dependencies**:
   Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   
Running the Application
You have two options for running Big Bro:

1. Convert to a Standalone EXE (No Console)
If you wish to distribute Big Bro as a standalone executable (without a console window), use PyInstaller. Simply run:
```bash
pyinstaller --onefile --noconsole BigBro.py
```
The resulting EXE file will be located in the dist folder.
  
2. Run the Python Script Directly (No Console)
If you simply want to run Big Bro without opening a console window, use pythonw.exe instead of python.exe:
 ```bash 
   pythonw BigBro.py
 ```
This method is useful for testing or local use without packaging the script.
