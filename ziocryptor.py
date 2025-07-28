limport os
import sys
import base64
import json
import getpass
import shutil
import time
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import hmac
import secrets
import platform
import argparse

try:
    from cryptography.fernet import Fernet
    from tqdm import tqdm
except ImportError:
    print("⏳ Installing required dependencies...")
    os.system(f"{sys.executable} -m pip install cryptography tqdm -q")
    from cryptography.fernet import Fernet
    from tqdm import tqdm

VERSION = "v10.0-multiOS"
DEFAULT_KEY_DIR = os.path.join(os.path.expanduser("~"), "ziole_keys")
BACKUP_DIR = os.path.join(os.path.expanduser("~"), "ziole_backups")
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB
DEFAULT_ITERATIONS = 600000  # Increased for better security
SUPPORTED_OS = ['windows', 'linux', 'darwin']  # Windows, Linux, macOS

def os_compatible_path(path: str) -> str:
    """Convert path to OS-specific format"""
    if platform.system() == 'Windows':
        return path.replace('/', '\\').strip('"')
    return path.replace('\\', '/').strip('"')

def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Cross-platform key derivation using PBKDF2-HMAC-SHA256"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations,
        dklen=32  # 256-bit key
    )

def generate_rsa_keys():
    print("🔑 Generating secure RSA 4096-bit keys...")
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    pub_key = priv_key.public_key()
    return priv_key, pub_key

def save_keys(priv_key, pub_key, folder, password=None):
    os.makedirs(folder, exist_ok=True)
    
    salt = secrets.token_bytes(16)
    if password:
        key = derive_key(password, salt)
        encryption_alg = serialization.BestAvailableEncryption(key)
    else:
        encryption_alg = serialization.NoEncryption()
    
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_alg
    )
    
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(os.path.join(folder, "private_key.pem"), "wb") as f:
        f.write(priv_pem)
    with open(os.path.join(folder, "public_key.pem"), "wb") as f:
        f.write(pub_pem)
    
    if password:
        with open(os.path.join(folder, "key_salt.bin"), "wb") as f:
            f.write(salt)
    
    print(f"✅ Keys saved securely to {folder}")

def load_keys(folder):
    try:
        with open(os.path.join(folder, "private_key.pem"), "rb") as f:
            priv_key_data = f.read()
            priv_key = serialization.load_pem_private_key(priv_key_data, password=None)
    except Exception as e:
        password = getpass.getpass("🔐 Enter private key password: ")
        salt_path = os.path.join(folder, "key_salt.bin")
        
        if not os.path.exists(salt_path):
            print("❌ Key salt not found! Using empty salt...")
            salt = b''
        else:
            with open(salt_path, "rb") as f:
                salt = f.read()
        
        key = derive_key(password, salt)
        priv_key = serialization.load_pem_private_key(priv_key_data, password=key)
    
    with open(os.path.join(folder, "public_key.pem"), "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())
    
    return priv_key, pub_key

def hybrid_encrypt(data, pub_key):
    """🔐 Hybrid encryption with HMAC integrity check"""
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    hmac_key = secrets.token_bytes(32)

    # Encrypt data
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt in chunks
    chunk_size = 64 * 1024
    encrypted_chunks = []
    total = len(data)
    
    with tqdm(total=total, unit='B', unit_scale=True, desc="🔐 Encrypting") as pbar:
        for i in range(0, total, chunk_size):
            chunk = data[i:i+chunk_size]
            enc_chunk = encryptor.update(chunk)
            encrypted_chunks.append(enc_chunk)
            pbar.update(len(chunk))
    
    encrypted_data = b''.join(encrypted_chunks) + encryptor.finalize()

    # Calculate HMAC for integrity
    h = hmac.new(hmac_key, encrypted_data, hashlib.sha256)
    hmac_digest = h.digest()

    # Encrypt keys with RSA
    enc_aes_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    enc_hmac_key = pub_key.encrypt(
        hmac_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "iv": base64.b64encode(iv).decode(),
        "aes_key": base64.b64encode(enc_aes_key).decode(),
        "hmac_key": base64.b64encode(enc_hmac_key).decode(),
        "hmac": base64.b64encode(hmac_digest).decode(),
        "payload": base64.b64encode(encrypted_data).decode(),
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "platform": platform.platform()
        }
    }

def hybrid_decrypt(payload, priv_key):
    """🔓 Hybrid decryption with HMAC verification"""
    iv = base64.b64decode(payload["iv"])
    enc_aes_key = base64.b64decode(payload["aes_key"])
    enc_hmac_key = base64.b64decode(payload["hmac_key"])
    hmac_value = base64.b64decode(payload["hmac"])
    encrypted_data = base64.b64decode(payload["payload"])

    # Decrypt keys
    aes_key = priv_key.decrypt(
        enc_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    hmac_key = priv_key.decrypt(
        enc_hmac_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Verify HMAC
    h = hmac.new(hmac_key, encrypted_data, hashlib.sha256)
    if not hmac.compare_digest(h.digest(), hmac_value):
        raise InvalidTag("❌ HMAC verification failed! File may be corrupted.")

    # Decrypt data
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    chunk_size = 64 * 1024
    decrypted_chunks = []
    total = len(encrypted_data)
    
    with tqdm(total=total, unit='B', unit_scale=True, desc="🔓 Decrypting") as pbar:
        for i in range(0, total, chunk_size):
            chunk = encrypted_data[i:i+chunk_size]
            decrypted_chunks.append(decryptor.update(chunk))
            pbar.update(len(chunk))
    
    return b''.join(decrypted_chunks) + decryptor.finalize()

def backup_file(file_path):
    """Create timestamped backup of file"""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.basename(file_path)
    backup_path = os.path.join(BACKUP_DIR, f"{filename}_{timestamp}.bak")
    
    try:
        shutil.copy2(file_path, backup_path)
        print(f"📥 Backup created: {backup_path}")
        return True
    except Exception as e:
        print(f"⚠️ Backup failed: {str(e)}")
        return False

def main():
    print(f"\n🔐 ziocryptor {VERSION}")
    print(f"🚀 Running on: {platform.platform()}\n")
    
    # Check OS compatibility
    if platform.system().lower() not in SUPPORTED_OS:
        print(f"⚠️ Warning: Unsupported OS - {platform.system()} - Use at your own risk")

    # File input
    file_path = input("📂 Enter file path (or drag & drop): ").strip()
    file_path = os_compatible_path(file_path)
    
    if not os.path.isfile(file_path):
        print("❌ File not found!")
        return

    # Check file size
    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        print(f"❌ File too large! Max size: {MAX_FILE_SIZE//(1024*1024)}MB")
        return

    # Mode selection
    mode = input("🛠️ Mode (e = encrypt / d = decrypt): ").lower()
    if mode not in ['e', 'd']:
        print("❌ Invalid mode!")
        return

    # Key management
    use_custom_key = input("🔧 Use custom keys? (y/n): ").lower()
    key_dir = DEFAULT_KEY_DIR
    
    if use_custom_key == 'y':
        key_dir = input("📁 Enter key folder path: ").strip()
        key_dir = os_compatible_path(key_dir)
        if not os.path.exists(os.path.join(key_dir, "private_key.pem")):
            print("❌ Keys not found in specified directory!")
            return
    
    # Create keys if needed
    if not os.path.exists(os.path.join(key_dir, "private_key.pem")):
        print("🔑 Generating new keys...")
        priv_key, pub_key = generate_rsa_keys()
        password = getpass.getpass("🔒 Set password for private key (press Enter for no password): ")
        save_keys(priv_key, pub_key, key_dir, password if password else None)
    else:
        priv_key, pub_key = load_keys(key_dir)

    # Backup original file before encryption
    if mode == 'e':
        print("⏳ Creating backup...")
        if not backup_file(file_path):
            proceed = input("⚠️ Continue without backup? (y/n): ").lower()
            if proceed != 'y':
                print("🛑 Operation cancelled")
                return

    try:
        if mode == 'e':
            with open(file_path, "rb") as f:
                data = f.read()
            
            encrypted = hybrid_encrypt(data, pub_key)
            output_path = file_path + ".zenc"
            
            with open(output_path, "w") as f:
                json.dump(encrypted, f)
            
            print(f"✅ Encryption successful! Output: {output_path}")
            
            # Cleanup options
            cleanup = input("🧹 Delete original file? (y/n): ").lower()
            if cleanup == 'y':
                os.remove(file_path)
                print("🗑️ Original file deleted")
        
        elif mode == 'd':
            with open(file_path, "r") as f:
                payload = json.load(f)
            
            # Verify version compatibility
            if payload.get('metadata', {}).get('version') != VERSION:
                print(f"⚠️ Version mismatch: File={payload.get('metadata', {}).get('version')}, Tool={VERSION}")
            
            decrypted = hybrid_decrypt(payload, priv_key)
            output_path = file_path.replace(".zenc", "")
            
            # Handle existing files
            if os.path.exists(output_path):
                print("⚠️ Output file exists!")
                action = input("(o)verwrite, (r)ename, (c)ancel: ").lower()
                if action == 'o':
                    pass
                elif action == 'r':
                    output_path += "_decrypted"
                else:
                    print("🛑 Operation cancelled")
                    return
            
            with open(output_path, "wb") as f:
                f.write(decrypted)
            
            print(f"✅ Decryption successful! Output: {output_path}")
            
            # Cleanup options
            cleanup = input("🧹 Delete encrypted file? (y/n): ").lower()
            if cleanup == 'y':
                os.remove(file_path)
                print("🗑️ Encrypted file deleted")
    
    except InvalidTag as e:
        print(f"❌ Security alert: {str(e)}")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")