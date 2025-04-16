import os
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from typing import Optional, Dict

LOCKER_DIR = os.path.join(os.getcwd(), 'locker')
DB_PATH = r"C:\Users\aikan\Downloads\AdvancedProtectionSuite\Database\files.db"


os.makedirs(LOCKER_DIR, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS files
                     (id INTEGER PRIMARY KEY,
                      filename TEXT UNIQUE,
                      original_name TEXT,
                      extension TEXT,
                      status TEXT CHECK(status IN ('Encrypted', 'Decrypted')),
                      size_mb REAL,
                      salt BLOB)''')

init_db()

def sync_database():
    """Synchronize the database with actual files in the locker directory"""
    with get_db() as conn:
        # Get all files currently in the database
        db_files = {row['filename']: dict(row) for row in 
                   conn.execute("SELECT * FROM files")}
        
        # Get all files actually present in the locker directory
        actual_files = set(os.listdir(LOCKER_DIR))
        
        # Remove database entries for files that no longer exist
        for filename in list(db_files.keys()):
            if filename not in actual_files:
                conn.execute("DELETE FROM files WHERE filename=?", (filename,))
        
        # Add new files that exist in directory but not in database
        for filename in actual_files:
            if filename not in db_files:
                filepath = os.path.join(LOCKER_DIR, filename)
                if os.path.isfile(filepath):  # Only process files, not directories
                    try:
                        # For manually added encrypted files, we can't recover original name
                        original_name, extension = os.path.splitext(filename)
                        size_mb = os.path.getsize(filepath) / (1024 ** 2)
                        
                        # Try to read salt from the file (first 16 bytes)
                        with open(filepath, 'rb') as f:
                            salt = f.read(16)
                        
                        # If file is too small to contain salt, skip or mark differently
                        status = 'Encrypted' if len(salt) == 16 else 'Unknown'
                        
                        conn.execute('''INSERT INTO files 
                                     (filename, original_name, extension, status, size_mb, salt)
                                     VALUES (?, ?, ?, ?, ?, ?)''',
                                   (filename, original_name, extension, status, size_mb, salt))
                    except Exception as e:
                        print(f"Error processing manually added file {filename}: {str(e)}")

def get_db_connection():
    """Get a database connection that automatically syncs before operations"""
    sync_database()
    return get_db()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(filepath: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(filepath, 'rb') as f:
        file_data = f.read()

    encrypted = fernet.encrypt(file_data)
    filename = os.path.basename(filepath)
    locker_path = os.path.join(LOCKER_DIR, filename)

    # Check if file already exists in locker and database
    if os.path.exists(locker_path):
        raise FileExistsError(f"File {filename} already exists in locker")

    with open(locker_path, 'wb') as f:
        f.write(salt + encrypted)

    original_name, extension = os.path.splitext(filename)
    size_mb = os.path.getsize(filepath) / (1024 ** 2)

    with get_db_connection() as conn:
        # First try to delete any existing entry (though sync_database should prevent this)
        conn.execute("DELETE FROM files WHERE filename=?", (filename,))
        # Then insert the new record
        conn.execute('''INSERT INTO files 
                     (filename, original_name, extension, status, size_mb, salt)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (filename, original_name, extension, 'Encrypted', size_mb, salt))
def decrypt_file(filename: str, password: str) -> bool:
    try:
        with get_db_connection() as conn:
            row = conn.execute("SELECT salt FROM files WHERE filename=?", 
                             (filename,)).fetchone()
            if not row:
                return False
            salt = row['salt']

        key = derive_key(password, salt)
        fernet = Fernet(key)
        locker_path = os.path.join(LOCKER_DIR, filename)

        with open(locker_path, 'rb') as f:
            data = f.read()

        decrypted = fernet.decrypt(data[16:])
        
        with open(locker_path, 'wb') as f:
            f.write(decrypted)

        with get_db_connection() as conn:
            conn.execute("UPDATE files SET status='Decrypted' WHERE filename=?", 
                       (filename,))
        return True
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return False

def reencrypt_file(filename: str, password: str) -> bool:
    try:
        with get_db_connection() as conn:
            row = conn.execute("SELECT salt FROM files WHERE filename=?", 
                             (filename,)).fetchone()
            if not row:
                return False
            salt = row['salt']

        key = derive_key(password, salt)
        fernet = Fernet(key)
        locker_path = os.path.join(LOCKER_DIR, filename)

        with open(locker_path, 'rb') as f:
            decrypted_data = f.read()

        encrypted = fernet.encrypt(decrypted_data)
        with open(locker_path, 'wb') as f:
            f.write(salt + encrypted)

        with get_db_connection() as conn:
            conn.execute("UPDATE files SET status='Encrypted' WHERE filename=?", 
                       (filename,))
        return True
    except Exception as e:
        print(f"Re-encryption error: {str(e)}")
        return False

def get_locker_files():
    sync_database()  # Ensure we have the latest state
    with get_db() as conn:
        rows = conn.execute('''SELECT filename, original_name, extension, status, size_mb 
                            FROM files''').fetchall()
        return [dict(row) for row in rows]

def cleanup_database():
    sync_database()  # This now handles the cleanup
    return 0  # sync_database() handles the removal internally

def batch_reencrypt(filenames: list, password: str) -> list:
    """Batch re-encrypt files"""
    sync_database()  # Ensure we're working with current files
    results = []
    for filename in filenames:
        try:
            success = reencrypt_file(filename, password)
            results.append({'filename': filename, 'success': success})
        except Exception as e:
            results.append({'filename': filename, 'success': False, 'error': str(e)})
    return results

def get_file_info(filename: str) -> Optional[Dict]:
    """Get information about a specific file"""
    sync_database()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM files WHERE filename=?", (filename,)).fetchone()
        return dict(row) if row else None