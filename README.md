# 🔐 ZioleCryptor v13.0 & v11.0 - Enterprise Edition

ZioleCryptor is an ultra-fast file encryption and decryption tool built for professionals, sysadmins, and power users who demand **maximum security**, **flexibility**, and **automation**.
Created by **Bhimantara Arsya Dewanto** (aka Ziole Visa Charles).

> 🧠 Hybrid Encryption with RSA-4096 + AES-256-GCM, digital signature, integrity verification, and built-in key revocation.

---

## 🚀 Key Features

- ✅ **Hybrid Encryption**: RSA-4096 + AES-256-GCM
- ✅ **Auto compression** for files >100KB
- ✅ **SHA-256 integrity check**
- ✅ **PSS Signature** with key fingerprint
- ✅ **Key protection** via PBKDF2-HMAC-SHA256
- ✅ **Built-in Key Revocation System**
- ✅ **Dual Mode**: CLI & Interactive UI (TUI)
- ✅ **Headless mode** for CI/CD pipelines
- ✅ **Secure Delete** (overwrite 3x + fsync)
- ✅ **Auto Backup** before encryption
- ✅ **Multithreaded** encryption
- ✅ **Decrypt directly to stdout**

---

## 📦 Requirements

- Python `3.8+`
- Required Modules:
  - `cryptography`
  - `tqdm`

If not installed, dependencies will auto-install.

---

## 🧠 Installation

```bash
git clone https://github.com/oozvc/ziocryptor.git
cd ziocryptor
python3 run.py
```

---

## ⚙️ How to Use

### A. Interactive Mode (UI CLI)
```bash
python3 run.py
```
> Provides a step-by-step UI CLI to select files, modes, etc.

### B. Automatic Mode (Headless / CLI) for ver 13
```bash
python ziocryptor.py -m encrypt -i file.txt -o output/
```

---

## 📌 Important Arguments

| Argument | Description |
|----------|-------------|
| `-m encrypt/decrypt` | Select mode (required in headless) |
| `-i file.txt` | Input file or directory (multi-input supported) |
| `-o output/` | Output directory |
| `--headless` | Disable interactive mode |
| `--no-confirm` | Skip all confirmation prompts |
| `--stdout` | Print decrypted content to terminal |
| `--revoke-key [FINGERPRINT]` | Revoke a specific key |

---

## 🧪 Example Usage

### 🔒 Encrypt
```bash
# Single file encryption
python ziocryptor.py -m encrypt -i secret.pdf -o encrypted/

# Encrypt full folder, non-interactive
python ziocryptor.py -m encrypt -i data/ --headless --no-confirm --delete
```

### 🔓 Decrypt
```bash
# Output to folder
python ziocryptor.py -m decrypt -i file.enc -o decrypted/

# Output to terminal (stdout)
python ziocryptor.py -m decrypt -i file.enc --stdout > result.txt
```

### 🔑 Key Management
```bash
# Revoke key
python ziocryptor.py --revoke-key i+JPmyv6rFO33Otx

# View all keys
ls ~/.ziole_keys/
```

---

## 🛠️ Advanced Options

| Argument Combination | Function |
|----------------------|----------|
| `--shred --delete` | Securely delete original file after encryption |
| `--threads 8` | Process files in parallel using 8 threads |
| `--dry-run` | Simulate process without modifying files |
| `--no-verify` | Skip SHA-256 verification |

---

## 📂 Important Locations
- 🔐 Keys stored at: `~/.ziole_keys/`
- 🗃️ Backup files: `~/.ziole_backups/`
- 📄 Activity logs: `~/.ziocrptorv13.log`
- but for v11 is `~/.ziocryptor.conf` for config file and `~/.ziocrptorv13.log` for v13

---

## 🔁 CI/CD Integration
```bash
# Auto encryption in build pipeline
python ziocryptor.py -m encrypt -i artifacts/ --headless --no-confirm -o encrypted_artifacts/
```

---

## 🧭 Help & Tips

Use `python ziocryptor.py --help` to view all available options. This guide covers 90% of common use-cases. For more complex workflows, mix and match arguments as needed.

---

Made with 💻 by **Ziole Visa Charles**
