# 📂 Metadata Extractor Pro
Metadata Extractor Pro is a powerful, GUI-based tool for extracting metadata from various file formats and scanning them for potential malicious indicators. Whether you're a cybersecurity analyst, digital forensic examiner, or a curious user, this tool provides a comprehensive view into what's hidden behind the files you use every day.

# 🔍 Features
🖼 Image Metadata Extraction
Extracts EXIF metadata from image files (.jpg, .png, .tiff, etc.), including camera info, GPS data, and timestamps.

# 📄 Document Metadata Analysis
Parses metadata from:

**PDFs** (.pdf)

**Word documents** (.docx)

**Excel spreadsheets** (.xlsx)

# ⚙️ PE File Inspection
Reads internal structures of Windows executables (.exe) using pefile, revealing headers, sections, entry points, and more.

# 🛡 VirusTotal Integration
Automatically checks files against VirusTotal using their public API. If a file isn't found, it uploads it for live scanning.

# 📦 Generic File Fingerprinting
Displays file size, MIME type, and cryptographic hashes (MD5, SHA256) for any file format.

#🧵 Multithreaded UI with Animation
Responsive interface powered by Tkinter, providing visual feedback while scanning.

# 🚀 Installation
Clone the repository

git clone https://github.com/Threadlinee/Metadata-Extractor.git
cd Metadata-Extractor
**Install required dependencies**
Make sure you have Python 3.8+ installed, then run:

pip install -r requirements.txt
**Run the application**

python metadata_extractor.py
# 🧠 Use Cases
Digital Forensics: Identify hidden metadata or malicious indicators in user-submitted files.

Cybersecurity: Detect hidden payloads or suspicious executable structures.

Privacy Audits: Discover personal or location data embedded in photos or documents.

General Curiosity: Learn more about the files you interact with daily.

# 📎 Supported File Types
File Type	Support Level
**.jpg**, **.png**	EXIF metadata
**.pdf**	Document metadata
**.docx**	Document properties
**.xlsx**	Spreadsheet properties
**.exe**	PE structure + VirusTotal
Other	Generic file details

# 🔐 VirusTotal API Key
To enable VirusTotal scanning, replace the placeholder API key in the script with your own:

# 💡 TODOs / Future Improvements
Add drag & drop support

Add support for **.pptx**, **.mp4**, and other formats

Generate full scan reports in .txt or .html

Add support for recursive folder scans

# 🤝 Contributing
Pull requests are welcome! If you have suggestions for improvements or want to add support for more file types, feel free to fork and submit a PR.

# 📄 License
This project is licensed under the MIT License.

🌐 Author
Threadlinee
🔗 GitHub
🔍 Creator of Metadata Extractor Pro

# ☕ Support If you find this tool useful, drop a ⭐ or fork it. Contributions and proxy improvements are welcome. [![Buy Me a Coffee](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/G2G114SBVV)

