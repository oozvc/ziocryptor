# 🔐 ZioleCryptor v13.0 - Enterprise Edition

ZioleCryptor adalah alat enkripsi dan dekripsi file ultra-cepat yang dirancang untuk profesional, sysadmin, dan power users yang butuh **keamanan maksimal**, **fleksibilitas**, dan **otomatisasi**.
Dibuat oleh **Bhimantara Arsya Dewanto** (aka Ziole Visa Charles).

> 🧠 Hybrid Encryption RSA-4096 + AES-256-GCM, digital signature, integrity verification, dan key revocation built-in.

---

## 🚀 Fitur Utama

- ✅ **Hybrid Encryption**: RSA-4096 + AES-256-GCM
- ✅ **Otomatis kompresi** untuk file >100KB
- ✅ **SHA-256 integrity check**
- ✅ **Signature PSS** dengan key fingerprint
- ✅ **Proteksi kunci** via PBKDF2-HMAC-SHA256
- ✅ **Key Revocation** system built-in
- ✅ **Dual Mode**: CLI & Interactive UI (TUI)
- ✅ **Headless mode** buat CI/CD
- ✅ **Secure Delete** (overwrite 3x + fsync)
- ✅ **Auto Backup** sebelum enkripsi
- ✅ **Multithread** encryption
- ✅ **Deskripsi langsung ke stdout**

---

## 📦 Requirements

- Python `3.8+`
- Modules:
  - `cryptography`
  - `tqdm`

Jika belum terpasang, dependensi akan auto-install.

---

## 🧠 Instalasi

```bash
git clone https://github.com/oozvc/ziocryptor.git
cd ziocryptor
pip install cryptography tqdm
python3 run.py
```

---

## ⚙️ Cara Penggunaan

### A. Mode Interaktif (UI CLI)
```bash
python3 run.py
```
> Tampil UI CLI step-by-step buat milih file, mode, dll.

### B. Mode Otomatis (Headless / CLI) khusus ver 13
```bash
python ziocryptor.py -m encrypt -i file.txt -o output/
```

---

## 📌 Argumen Penting

| Argumen | Fungsi |
|--------|--------|
| `-m encrypt/decrypt` | Pilih mode (wajib di headless) |
| `-i file.txt` | Input file/direktori (multi input juga bisa) |
| `-o output/` | Direktori output |
| `--headless` | Matikan mode interaktif |
| `--no-confirm` | Lewati semua prompt konfirmasi |
| `--stdout` | Print hasil deskripsi ke terminal |
| `--revoke-key [FINGERPRINT]` | Cabut kunci tertentu |

---

## 🧪 Contoh Penggunaan

### 🔒 Enkripsi
```bash
# File tunggal
python ziocryptor.py -m encrypt -i rahasia.pdf -o encrypted/

# Folder full, otomatis
python ziocryptor.py -m encrypt -i data/ --headless --no-confirm --delete
```

### 🔓 Deskripsi
```bash
# Output ke folder
python ziocryptor.py -m decrypt -i file.enc -o decrypted/

# Output langsung ke terminal
python ziocryptor.py -m decrypt -i file.enc --stdout > hasil.txt
```

### 🔑 Manajemen Kunci
```bash
# Revoke kunci
python ziocryptor.py --revoke-key i+JPmyv6rFO33Otx

# Lihat semua kunci
ls ~/.ziole_keys/
```

---

## 🛠️ Opsi Lanjutan

| Argumen Kombinasi | Fungsi |
|-------------------|--------|
| `--shred --delete` | Hapus file asli setelah enkripsi |
| `--threads 8` | Proses file secara paralel |
| `--dry-run` | Simulasi tanpa ubah file |
| `--no-verify` | Lewati verifikasi SHA-256 |

---

## 📂 Lokasi Penting
- 🔐 Kunci disimpan di: `~/.ziole_keys/`
- 🗃️ Backup file: `~/.ziole_backups/`
- 📄 Log aktivitas: `~/.ziolecryptor.log`

---

## 🔁 Integrasi CI/CD
```bash
# Enkripsi otomatis di pipeline build
python ziocryptor.py -m encrypt -i artifacts/ --headless --no-confirm -o encrypted_artifacts/
```

---

## 🧭 Bantuan & Tips

Gunakan `python ziocryptor.py --help` untuk semua opsi yang tersedia. Panduan ini mencakup 90% kebutuhan umum. Untuk skenario spesial, tinggal kombinasikan argumen sesuai use-case kamu.

---

Made with 💻 by **Ziole Visa Charles**
