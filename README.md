# VirusTotal Scanner

VirusTotal Scanner is a GUI-based application for Windows that allows users to scan files and URLs for malware using the VirusTotal API. The application calculates file hashes, submits them to VirusTotal, and displays detailed scan results, including the detection status from various antivirus engines. It also features API key management, saving the key for future use and ensuring it remains hidden from the UI.

## 💪 Features

- Scan files for malware using VirusTotal.
- Scan URLs for malware using VirusTotal.
- Display detailed scan results with detection status.
- Save and manage VirusTotal API key securely.
- User-friendly interface with a visually appealing layout.

## 💻 Installation & Usage

### **Pre-built Executable (Recommended)**

1. Download the latest executable from the [Releases Section](https://github.com/oop7/VirusTotal-Scanner/releases).
2. Enter your VirusTotal API key and save it.
3. Click "Select File" to choose a file to scan or enter a URL and click "Scan URL".
4. View the scan results, including the detection status from various antivirus engines.

## Running from Source (Optional)

1. **Clone the repository**: ```git clone https://github.com/oop7/VirusTotal-Scanner.git```
3. **Install required dependencies**:```pip install -r requirements.txt```
4. **Run the tool**:```python virus_total_scanner.py```

## Building the Executable (Optional)

### To build the tool into an executable using PyInstaller:

1. **Install PyInstaller**:```pip install pyinstaller```
2. **Build the executable**:```pyinstaller --onefile virus_total_scanner.py```

This will generate an `.exe` file in the `dist/` directory.

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 📙 Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## ❓  Acknowledgments

- [VirusTotal API](https://www.virustotal.com/)

