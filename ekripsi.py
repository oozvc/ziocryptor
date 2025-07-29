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
from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
import hmac
import secrets
import platform
import argparse
import tempfile

try:
    from tqdm import tqdm
except ImportError:
    print("⏳ Installing tqdm...")
    os.system(f"{sys.executable} -m pip install tqdm -q")
    from tqdm import tqdm

VERSION = "v10.3-multiOS"
DEFAULT_KEY_DIR = os.path.join(os.path.expanduser("~"), "ziole_keys")
BACKUP_DIR = os.path.join(os.path.expanduser("~"), "ziole_backups")
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB
DEFAULT_ITERATIONS = 600000
SUPPORTED_OS = ['windows', 'linux', 'darwin']
CHUNK_SIZE = 1024 * 1024  # 1MB

def os_compatible_path(path: str) -> str:
    """Handle path differences between OSes"""
    path = path.strip().strip('"')
    if platform.system() == 'Windows':
        return path.replace('/', '\\')
    return path.replace('\\', '/')

def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Secure key derivation"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations,
        dklen=32
    )

def generate_rsa_keys():
    """Generate RSA 4096-bit keys"""
    print("🔑 Generating secure RSA keys...")
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

def save_keys(priv_key, folder, password=None):
    """Save keys with proper permissions"""
    os.makedirs(folder, exist_ok=True)
    
    # Set secure permissions for Linux/macOS
    if platform.system() != 'Windows':
        os.chmod(folder, 0o700)
    
    # Handle key encryption
    if password:
        salt = secrets.token_bytes(32)
        key = derive_key(password, salt)
        encryption = serialization.BestAvailableEncryption(key)
    else:
        salt = b''
        encryption = serialization.NoEncryption()
    
    # Serialize private key
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    
    # Serialize public key
    pub_pem = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save keys
    priv_path = os.path.join(folder, "private_key.pem")
    pub_path = os.path.join(folder, "public_key.pem")
    
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    
    # Save salt if password is used
    if password:
        salt_path = os.path.join(folder, "key_params.json")
        with open(salt_path, "w") as f:
            json.dump({
                'salt': base64.b64encode(salt).decode(),
                'iterations': DEFAULT_ITERATIONS
            }, f)
    
    # Set file permissions for Linux/macOS
    if platform.system() != 'Windows':
        os.chmod(priv_path, 0o600)
        os.chmod(pub_path, 0o644)
        if password:
            os.chmod(salt_path, 0o600)
    
    print(f"✅ Keys saved to {folder}")
    return True

def load_keys(folder):
    """Load keys with backward compatibility and password retry"""
    priv_path = os.path.join(folder, "private_key.pem")
    if not os.path.exists(priv_path):
        raise FileNotFoundError("Private key not found")
    
    # Read private key data
    with open(priv_path, "rb") as f:
        priv_key_data = f.read()
    
    # Try without password first
    try:
        return serialization.load_pem_private_key(
            priv_key_data,
            password=None,
            backend=default_backend()
        ), None
    except (TypeError, ValueError, UnsupportedAlgorithm):
        pass  # Key is encrypted
    
    # Load encryption parameters
    salt = b''
    iterations = DEFAULT_ITERATIONS
    salt_path = os.path.join(folder, "key_params.json")
    
    if os.path.exists(salt_path):
        with open(salt_path, "r") as f:
            params = json.load(f)
        salt = base64.b64decode(params['salt'])
        iterations = params.get('iterations', DEFAULT_ITERATIONS)
    else:
        # Legacy support for old key format
        old_salt_path = os.path.join(folder, "key_salt.bin")
        if os.path.exists(old_salt_path):
            print("🔐 Found legacy key format")
            with open(old_salt_path, "rb") as f:
                salt = f.read()
            # Migrate to new format
            with open(salt_path, "w") as f:
                json.dump({
                    'salt': base64.b64encode(salt).decode(),
                    'iterations': iterations
                }, f)
            os.remove(old_salt_path)
            print("🔄 Migrated to new key format")
    
    # Password handling with retry
    for attempt in range(3):
        password = getpass.getpass("🔐 Enter private key password: ")
        if not password:
            print("❌ Password cannot be empty!")
            continue
        
        key = derive_key(password, salt, iterations)
        
        try:
            priv_key = serialization.load_pem_private_key(
                priv_key_data,
                password=key,
                backend=default_backend()
            )
            # Test if key is valid
            test_pubkey = priv_key.public_key()
            test_pubkey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return priv_key, None
        except Exception as e:
            if attempt < 2:
                print(f"❌ Incorrect password! Attempts left: {2-attempt}")
            else:
                print("🔒 Password reset required")
                raise ValueError("Incorrect password after 3 attempts") from e
    
    raise RuntimeError("Key loading failed")

def hybrid_encrypt(data, pub_key):
    """Encrypt data with RSA+AES with HMAC integrity"""
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    hmac_key = secrets.token_bytes(32)
    
    # Encrypt data
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Process in chunks
    encrypted_chunks = []
    total_size = len(data)
    h = hmac.new(hmac_key, digestmod=hashlib.sha256)
    
    with tqdm(total=total_size, unit='B', unit_scale=True, desc="🔐 Encrypting") as pbar:
        for i in range(0, total_size, CHUNK_SIZE):
            chunk = data[i:i+CHUNK_SIZE]
            enc_chunk = encryptor.update(chunk)
            encrypted_chunks.append(enc_chunk)
            h.update(enc_chunk)
            pbar.update(len(chunk))
    
    final_chunk = encryptor.finalize()
    if final_chunk:
        encrypted_chunks.append(final_chunk)
        h.update(final_chunk)
    
    encrypted_data = b''.join(encrypted_chunks)
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
    """Decrypt data with integrity verification"""
    # Decode base64 data
    iv = base64.b64decode(payload["iv"])
    enc_aes_key = base64.b64decode(payload["aes_key"])
    enc_hmac_key = base64.b64decode(payload["hmac_key"])
    hmac_value = base64.b64decode(payload["hmac"])
    encrypted_data = base64.b64decode(payload["payload"])

    # Decrypt keys
    try:
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
    except Exception as e:
        raise ValueError("Key decryption failed") from e

    # Verify HMAC
    h = hmac.new(hmac_key, encrypted_data, hashlib.sha256)
    if not hmac.compare_digest(h.digest(), hmac_value):
        raise InvalidTag("❌ HMAC verification failed! File may be corrupted.")

    # Decrypt data
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_chunks = []
    total_size = len(encrypted_data)
    
    with tqdm(total=total_size, unit='B', unit_scale=True, desc="🔓 Decrypting") as pbar:
        for i in range(0, total_size, CHUNK_SIZE):
            chunk = encrypted_data[i:i+CHUNK_SIZE]
            decrypted_chunks.append(decryptor.update(chunk))
            pbar.update(len(chunk))
    
    final_chunk = decryptor.finalize()
    if final_chunk:
        decrypted_chunks.append(final_chunk)
    
    return b''.join(decrypted_chunks)

def backup_file(file_path):
    """Create backup with timestamp"""
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
    
    # Handle unsupported OS
    current_os = platform.system().lower()
    if current_os not in SUPPORTED_OS:
        print(f"⚠️ Warning: Unsupported OS - {platform.system()}")
    
    # File input
    file_path = input("📂 Enter file path: ").strip()
    file_path = os_compatible_path(file_path)
    
    if not os.path.isfile(file_path):
        print(f"❌ File not found: {file_path}")
        return
    
    # File size check
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
        priv_key = generate_rsa_keys()
        password = getpass.getpass("🔒 Set password for private key (press Enter for no password): ")
        save_keys(priv_key, key_dir, password if password else None)
        pub_key = priv_key.public_key()
    else:
        try:
            priv_key, error = load_keys(key_dir)
            if error:
                print(error)
                return
            pub_key = priv_key.public_key()
        except Exception as e:
            print(f"❌ Failed to load keys: {str(e)}")
            print("💡 If you forgot your password, you can:")
            print(f"   1. Delete the key folder: {key_dir}")
            print("   2. Rerun the program to generate new keys")
            return
    
    # Backup for encryption
    if mode == 'e':
        if not backup_file(file_path):
            proceed = input("⚠️ Continue without backup? (y/n): ").lower()
            if proceed != 'y':
                print("🛑 Operation cancelled")
                return
    
    try:
        if mode == 'e':
            # Read file
            with open(file_path, "rb") as f:
                data = f.read()
            
            # Encrypt
            encrypted = hybrid_encrypt(data, pub_key)
            output_path = file_path + ".zenc"
            
            # Save encrypted file
            with open(output_path, "w") as f:
                json.dump(encrypted, f, indent=2)
            
            print(f"✅ Encryption successful! Output: {output_path}")
            
            # Cleanup option
            cleanup = input("🧹 Delete original file? (y/n): ").lower()
            if cleanup == 'y':
                os.remove(file_path)
                print("🗑️ Original file deleted")
        
        elif mode == 'd':
            # Read encrypted file
            with open(file_path, "r") as f:
                payload = json.load(f)
            
            # Version check
            if payload.get('metadata', {}).get('version') != VERSION:
                print(f"⚠️ Version mismatch: File={payload.get('metadata', {}).get('version')}, Tool={VERSION}")
                proceed = input("Continue anyway? (y/n): ").lower()
                if proceed != 'y':
                    print("🛑 Operation cancelled")
                    return
            
            # Decrypt
            decrypted = hybrid_decrypt(payload, priv_key)
            output_path = file_path.replace(".zenc", "")
            
            # Handle existing file
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
            
            # Save decrypted file
            with open(output_path, "wb") as f:
                f.write(decrypted)
            
            print(f"✅ Decryption successful! Output: {output_path}")
            
            # Cleanup option
            cleanup = input("🧹 Delete encrypted file? (y/n): ").lower()
            if cleanup == 'y':
                os.remove(file_path)
                print("🗑️ Encrypted file deleted")
    
    except InvalidTag as e:
        print(f"❌ Security alert: {str(e)}")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")