# ADVANCED-ENCRYPTION-TOOL
A robust encryption and decryption tool that secures your files using AES-256 algorithm. Designed with a clean and simple GUI for ease of use. 

#  Advanced Encryption Tool (AES-256 with GUI)

A powerful GUI-based file encryption and decryption tool using the AES-256 algorithm. Secure your files with ease.

## Features
- AES-256 encryption & decryption
- File selection and password input via GUI
- Simple and clean interface
- No need for terminal commands


##  Project Files

```
📁 advanced-encryption-tool/
├── main.py              # Python source code
├── encryption\_tool.exe  # Pre-built Windows executable
├── README.md            # Project documentation
├── requirements.txt     # Python dependencies

````

##  How to Run

### Option 1: Run using `.exe` file (No Python required)

1. Open the `dist/` folder or the main project folder (where `encryption_tool.exe` is located).
2. **Double-click `encryption_tool.exe`.**
3. The GUI will launch and allow you to:
   - Select a file
   - Enter a password
   - Click "Encrypt" or "Decrypt"

### Option 2: Run using `main.py` (Requires Python)

1. Ensure Python 3.x is installed.
2. Install required packages:
   ```bash
   pip install pycryptodome
````

3. Run the script:

   ```bash
   python main.py
   ```
##  Important Notes
* Encrypted files are saved with a `.enc` extension.
* Use the same password to decrypt that you used to encrypt.
* Losing the password means permanent loss of data.

