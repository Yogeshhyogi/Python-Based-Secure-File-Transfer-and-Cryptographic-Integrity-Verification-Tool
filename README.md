## Hybrid Threat Detection and Response System

## Title: Python-Based Secure File Transfer and Cryptographic Integrity Verification Tool

### Abstract

This project implements a foundational security pipeline demonstrating secure data handling and integrity assurance. A Python script performs **symmetric encryption (AES via Fernet)** on a sensitive file and simultaneously calculates its cryptographic hash (**SHA256**). The script simulates a secure transfer, then decrypts the file, and finally verifies its integrity by comparing the hash of the restored file against the original hash.

This showcases **secure data transmission** and the **detection of potential tampering**.

###  Technologies Used

  * **Language:** Python 3
  * **Libraries:** `cryptography` (for AES encryption/Fernet), `hashlib` (built-in, for SHA256 hashing)
  * **Environment:** Linux (Parrot OS, Debian/Ubuntu-based recommended)

###  Setup and Execution (Manual Command-Line Workflow)

Follow these steps exactly in your terminal to set up the environment, create the script, and run the pipeline.

#### 1\. System Dependency Installation and Cleanup

Install the necessary Linux development headers required for the `cryptography` library.

```bash
# Install packages (essential Python libraries)
sudo apt update
sudo apt install build-essential libssl-dev libffi-dev python3-dev

# Resolve broken package installations
sudo dpkg --configure -a
sudo apt install -f
```

#### 2\. Project Setup and Virtual Environment

Create the project directory and set up an isolated Python environment.

```bash
mkdir secure-file-project
cd secure-file-project

# Create and activate the virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python library
pip install cryptography
```

#### 3\. Create the Python Script (`secure_tool.py`)

Open the editor and paste the full code for the security tool.

```bash
nano secure_tool.py
```

**Paste the following Python code into the `nano` editor:**

```python
import hashlib
import os
from cryptography.fernet import Fernet
import sys 

# --- 1. File Paths and Variables ---
INPUT_FILE = "sensitive_data.txt"
ENCRYPTED_FILE = "sensitive_data.enc"
DECRYPTED_FILE = "sensitive_data_restored.txt"
ENCRYPTION_KEY = None

# --- 2. UTILITY FUNCTIONS ---

def calculate_sha256(filepath):
    """Calculates the SHA256 hash of a file for integrity checking."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return None
    except Exception as e:
        print(f"Error during hashing: {e}")
        return None

def generate_key():
    """Generates a Fernet encryption key (AES-128 + HMAC)."""
    try:
        key = Fernet.generate_key()
        # Key display is only for demo; DO NOT print keys in production code.
        print(f"Encryption Key Generated: {key.decode()}") 
        return key
    except Exception as e:
        print(f"Failed to generate encryption key: {e}")
        return None

def encrypt_file(input_filepath, output_filepath, key):
    """Encrypts a file using the Fernet key."""
    if key is None:
        print("Encryption failed: Key is missing.")
        return False
        
    f = Fernet(key)
    try:
        with open(input_filepath, "rb") as file:
            original_data = file.read()
        
        encrypted_data = f.encrypt(original_data)
        
        with open(output_filepath, "wb") as file:
            file.write(encrypted_data)
        print(f" File encrypted successfully to: {output_filepath}")
        return True
    except Exception as e:
        print(f"Encryption process failed: {e}")
        return False

def decrypt_file(input_filepath, output_filepath, key):
    """Decrypts a file using the Fernet key."""
    if key is None:
        print("Decryption failed: Key is missing.")
        return False
        
    f = Fernet(key)
    try:
        with open(input_filepath, "rb") as file:
            encrypted_data = file.read()
            
        decrypted_data = f.decrypt(encrypted_data)
        
        with open(output_filepath, "wb") as file:
            file.write(decrypted_data)
        print(f" File decrypted successfully to: {output_filepath}")
        return True
    except Exception as e:
        print(f"Decryption failed (Possible Tampering or Wrong Key): {e}")
        return False

# --- 3. MAIN PIPELINE FUNCTION ---

def main_security_pipeline():
    """Executes the full secure transfer and integrity check pipeline."""
    global ENCRYPTION_KEY
    
    print("\n--- 1. INITIAL INTEGRITY CHECK (SHA256) ---")
    original_hash = calculate_sha256(INPUT_FILE)
    if original_hash is None:
        return

    print(f"Original File: {INPUT_FILE}")
    print(f"Original SHA256 Hash: {original_hash}")
    print("-" * 45)

    # --- 2. ENCRYPTION & SIMULATED TRANSFER ---
    ENCRYPTION_KEY = generate_key()
    
    if ENCRYPTION_KEY and encrypt_file(INPUT_FILE, ENCRYPTED_FILE, ENCRYPTION_KEY):
        print("\n*** Simulated Secure Transfer Completed *** (Encrypted data moved)")
        print("-" * 45)

        # --- 3. DECRYPTION (Receiver Side) ---
        print("\n--- 3. DECRYPTING RECEIVED FILE ---")
        if decrypt_file(ENCRYPTED_FILE, DECRYPTED_FILE, ENCRYPTION_KEY):
            
            # --- 4. FINAL INTEGRITY VERIFICATION ---
            print("\n--- 4. FINAL INTEGRITY VERIFICATION ---")
            restored_hash = calculate_sha256(DECRYPTED_FILE)

            print(f"Restored File: {DECRYPTED_FILE}")
            print(f"Restored SHA256 Hash: {restored_hash}")

            if original_hash == restored_hash:
                print("\n SUCCESS: The restored file integrity is verified! Hashes match.")
                print("PROJECT 10 COMPLETED SUCCESSFULLY!")
            else:
                print("\n FAILURE: Integrity check failed! File was tampered with during transfer.")
            
            # Clean up the temporary encrypted and restored files
            try:
                os.remove(DECRYPTED_FILE)
                os.remove(ENCRYPTED_FILE)
                print("Cleanup: Removed temporary encrypted and restored files.")
            except:
                pass
            
    else:
        print("\nPipeline failed due to key or encryption error.")


# --- 4. EXECUTION BLOCK ---

if __name__ == "__main__":
    
    # 1. Check if the input file exists. If not, create it.
    if not os.path.exists(INPUT_FILE):
        print(f"Creating sample file: {INPUT_FILE}")
        try:
            with open(INPUT_FILE, 'w') as f:
                f.write("This is highly confidential information for the project.")
                f.write("\nFile created by the script for testing.")
            print("Sample input file created successfully.")
            
        except Exception as e:
            print(f"Error creating sample file: {e}")
            sys.exit(1) # Exit if file creation fails
            
    # 2. Run the pipeline.
    if os.path.exists(INPUT_FILE):
        print("\n*** Starting Secure File Transfer Pipeline ***")
        main_security_pipeline()
    else:
        print("\nCannot start pipeline: Input file is missing or creation failed.")

```

  * **To Save and Exit in `nano`:** Press `Ctrl+x`, hit `Enter` to confirm the filename(Exit).

#### 4\. Create the Input Data File

Create the sensitive data file that the script will encrypt.

```bash
echo "This is highly confidential information for the project." > sensitive_data.txt
```

#### 5\. Execute the Pipeline

Run the script to perform the encryption, decryption, and integrity check.

```bash
python3 secure_tool.py
```

###  Expected Output

The script's output confirms successful data handling and integrity verification:

```
*** Starting Secure File Transfer Pipeline ***

--- 1. INITIAL INTEGRITY CHECK (SHA256) ---
Original File: sensitive_data.txt
Original SHA256 Hash: [A 64-character hash value]
---------------------------------------------
Encryption Key Generated: [A long base64 string]
File encrypted successfully to: sensitive_data.enc

*** Simulated Secure Transfer Completed *** (Encrypted data moved)
---------------------------------------------

--- 3. DECRYPTING RECEIVED FILE ---
File decrypted successfully to: sensitive_data_restored.txt

--- 4. FINAL INTEGRITY VERIFICATION ---
Restored File: sensitive_data_restored.txt
Restored SHA256 Hash: [The SAME 64-character hash value]

 SUCCESS: The restored file integrity is verified! Hashes match.
 COMPLETED SUCCESSFULLY!
Cleanup: Removed temporary encrypted and restored files.
```
