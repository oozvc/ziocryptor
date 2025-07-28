import os
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


try:
    from cryptography.fernet import Fernet
    import tqdm
except ImportError:
    print("⏳ Installing required dependencies...")
    os.system(f"{sys.executable} -m pip install cryptography tqdm")
    from cryptography.fernet import Fernet
    import tqdm


VERSION = "v9.2-windows"
DEFAULT_KEY_DIR = "./ziole_keys"
BACKUP_DIR = "./ziole_backups"
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB
DEFAULT_ITERATIONS = 100000  # For PBKDF2


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
        
    except:
        # If failed, ask for password
        password = getpass.getpass("🔐 Enter private key password: ")
        salt = open(os.path.join(folder, "key_salt.bin"), "rb").read()
        key = derive_key(password, salt)
        
        with open(os.path.join(folder, "private_key.pem"), "rb") as f:
            priv_key_data = f.read()
            priv_key = serialization.load_pem_private_key(priv_key_data, password=key)
    
    with open(os.path.join(folder, "public_key.pem"), "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())
    
    return priv_key, pub_key

# 🔐 Hybrid encryption
def hybrid_encrypt(data, pub_key):
    aes_key = secrets.token_bytes(32)  # 256-bit AES
    iv = secrets.token_bytes(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt in chunks with progress
    chunk_size = 64 * 1024  # 64KB
    encrypted_chunks = []
    total = len(data)
    
    with tqdm.tqdm(total=total, unit='B', unit_scale=True, desc="🔐 Encrypting") as pbar:
        for i in range(0, total, chunk_size):
            chunk = data[i:i+chunk_size]
            encrypted_chunks.append(encryptor.update(chunk))
            pbar.update(len(chunk))
    
    encrypted_data = b''.join(encrypted_chunks) + encryptor.finalize()

    # Encrypt AES key with RSA
    enc_aes_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "iv": base64.b64encode(iv).decode(),
        "aes_key": base64.b64encode(enc_aes_key).decode(),
        "payload": base64.b64encode(encrypted_data).decode(),
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "version": VERSION
        }
    }

# 🔓 Hybrid decryption
def hybrid_decrypt(payload, priv_key):
    iv = base64.b64decode(payload["iv"])
    enc_key = base64.b64decode(payload["aes_key"])
    encrypted_data = base64.b64decode(payload["payload"])

    aes_key = priv_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt in chunks
    chunk_size = 64 * 1024
    decrypted_chunks = []
    total = len(encrypted_data)
    
    with tqdm.tqdm(total=total, unit='B', unit_scale=True, desc="🔓 Decrypting") as pbar:
        for i in range(0, total, chunk_size):
            chunk = encrypted_data[i:i+chunk_size]
            decrypted_chunks.append(decryptor.update(chunk))
            pbar.update(len(chunk))
    
    return b''.join(decrypted_chunks) + decryptor.finalize()

# 🚀 Main function
def main():
    print(f"\n🔐 Ziole Secure Encryptor {VERSION} - Windows Optimized\n")
    
    # File input
    file_path = input("📂 Enter file path (or drag & drop): ").strip().strip('"')
    if not os.path.isfile(file_path):
        print("❌ File not found!")
        return
    
    # Mode selection
    mode = input("🛠️ Mode (e = encrypt / d = decrypt): ").lower()
    if mode not in ['e', 'd']:
        print("❌ Invalid mode!")
        return
    
    # Key management
    use_custom_key = input("🔧 Use custom keys? (y/n): ").lower()
    key_dir = DEFAULT_KEY_DIR if use_custom_key != 'y' else input("📁 Enter key folder path: ").strip().strip('"')
    
    if use_custom_key == 'y':
        if not os.path.exists(os.path.join(key_dir, "private_key.pem")):
            print("❌ Keys not found in specified directory!")
            return
        priv_key, pub_key = load_keys(key_dir)
    else:
        if not os.path.exists(os.path.join(key_dir, "private_key.pem")):
            print("🔑 Generating new keys...")
            priv_key, pub_key = generate_rsa_keys()
            save_keys(priv_key, pub_key, key_dir)
        else:
            priv_key, pub_key = load_keys(key_dir)
    
    # Process file
    try:
        if mode == 'e':
            with open(file_path, "rb") as f:
                data = f.read()
            
            encrypted = hybrid_encrypt(data, pub_key)
            output_path = file_path + ".zenc"
            
            with open(output_path, "w") as f:
                json.dump(encrypted, f)
            
            print(f"✅ Encryption successful! Output: {output_path}")
        
        elif mode == 'd':
            with open(file_path, "r") as f:
                payload = json.load(f)
            
            decrypted = hybrid_decrypt(payload, priv_key)
            output_path = file_path.replace(".zenc", ".dec")
            
            with open(output_path, "wb") as f:
                f.write(decrypted)
            
            print(f"✅ Decryption successful! Output: {output_path}")
    
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")