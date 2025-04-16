import os
import sqlite3
import hashlib
import psutil

DATABASE_PATH = r"C:\Users\aikan\Downloads\AdvancedProtectionSuite\Database\latestdata.db"

def connect_to_database(db_path):
    """Connect to the SQLite hash database."""
    try:
        conn = sqlite3.connect(db_path)
        return conn
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        return None

def get_known_hashes(conn):
    """Fetch known malicious hashes from the 'unique_hashes' table."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT hash FROM unique_hashes")
        return set(row[0] for row in cursor.fetchall())
    except sqlite3.Error as e:
        print(f"Error reading database: {e}")
        return set()

def calculate_file_hash(file_path):
    """Calculate the MD5 hash of a given file."""
    try:
        md5_hash = hashlib.md5()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
        return md5_hash.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def scan_memory(known_hashes):
    """Scan memory for malicious and clean hashes and yield process data in real time."""
    total_scanned = 0
    malicious_count = 0
    clean_count = 0

    for process in psutil.process_iter(attrs=['pid', 'name', 'exe']):
        try:
            exe_path = process.info['exe']
            if exe_path:
                file_hash = calculate_file_hash(exe_path)
                if file_hash:
                    total_scanned += 1
                    status = "Malicious" if file_hash in known_hashes else "Clean"

                    if status == "Malicious":
                        malicious_count += 1
                    else:
                        clean_count += 1

                    process_data = {
                        "pid": process.info['pid'],
                        "name": process.info['name'],
                        "path": exe_path,
                        "hash": file_hash,
                        "status": status
                    }

                    print(f"DEBUG: Scanned {total_scanned} => {process_data}")  # Debugging
                    yield total_scanned, malicious_count, clean_count, process_data

        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
