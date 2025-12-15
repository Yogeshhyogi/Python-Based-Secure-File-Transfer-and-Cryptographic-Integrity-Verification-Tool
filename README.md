Hybrid Threat Detection and Response System

### Python-Based Secure File Transfer and Cryptographic Integrity Verification Tool

### Abstract

This project implements a foundational security pipeline demonstrating secure data handling and integrity assurance. A Python script is used to perform **symmetric encryption (AES via Fernet)** on a sensitive file and simultaneously calculate its cryptographic hash (**SHA256**). The script simulates a secure transfer, then decrypts the file, and finally verifies its integrity by comparing the hash of the restored file against the original hash.

This successfully showcases **secure data transmission** and the **detection of potential tampering**.

### Technologies Used

  * **Language:** Python 3
  * **Libraries:** `cryptography` (for AES encryption/Fernet), `hashlib` (built-in, for SHA256 hashing)
  * **Environment:** Parrot OS / Linux (or any Python 3 environment)

###  Setup and Execution

#### 1\. Clone the Repository

```bash
git clone [YOUR_REPO_URL]
cd secure-file-project
```

#### 2\. Create a Virtual Environment (Recommended)

This prevents conflicts with system-wide Python packages.

```bash
python3 -m venv venv
source venv/bin/activate
```

#### 3\. Install Dependencies

You need to install the `cryptography` library and its system dependencies.

```bash
# Required for compiling cryptography library on Linux (Debian/Ubuntu-based)
sudo apt update
sudo apt install build-essential libssl-dev libffi-dev python3-dev

# Install the necessary Python library from requirements.txt
pip install -r requirements.txt
```

#### 4\. Run the Pipeline

The main script will automatically create the required input file (`sensitive_data.txt`) if it doesn't exist.

```bash
python3 secure_tool.py
```

###  Expected Output

The successful execution confirms that the original and restored file hashes match, proving integrity.

```
*** Starting Secure File Transfer Pipeline ***

--- 1. INITIAL INTEGRITY CHECK (SHA256) ---
INFO: Calculating SHA256 hash for sensitive_data.txt...
Original SHA256 Hash: 1091356f9de23301673666d75f85430ab1bf137c46b2d7131dc4505f68d80a72

--- 2. ENCRYPTION ---
INFO: Generating a new Fernet key...
File encrypted successfully to: sensitive_data.enc

--- 3. DECRYPTION ---
INFO: Decrypting sensitive_data.enc to sensitive_data_restored.txt...
File decrypted successfully.

--- 4. FINAL INTEGRITY VERIFICATION ---
INFO: Calculating SHA256 hash for sensitive_data_restored.txt...
Restored SHA256 Hash: 1091356f9de23301673666d75f85430ab1bf137c46b2d7131dc4505f68d80a72

 SUCCESS: The restored file integrity is verified! Hashes match.
