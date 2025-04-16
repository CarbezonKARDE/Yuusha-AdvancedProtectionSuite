import os
import sqlite3
import hashlib
import time

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
    except (FileNotFoundError, PermissionError, OSError):
        return None

def scan_path(path, known_hashes):
    """
    Scan a file or all files in a folder for malicious hashes.
    Yields progress updates as dictionaries.
    """
    total_scanned = 0
    malicious_count = 0
    clean_count = 0
    skipped_count = 0
    start_time = time.time()
    malicious_files = []
    total_files = 0
    
    # Estimate total files (if directory)
    if os.path.isdir(path):
        try:
            for root, _, files in os.walk(path):
                total_files += len(files)
                # Stop counting if we hit a large number to prevent excessive startup time
                if total_files > 10000:
                    break
        except (PermissionError, OSError):
            pass

    if os.path.isfile(path):
        # Single file scan
        total_files = 1
        file_hash = calculate_file_hash(path)
        if file_hash:
            total_scanned = 1
            if file_hash in known_hashes:
                malicious_count = 1
                malicious_files.append([os.path.basename(path), path, "Malicious File"])
            else:
                clean_count = 1
        else:
            skipped_count = 1
            
        # Yield initial progress
        yield {
            "status": "progress",
            "total_scanned": total_scanned,
            "malicious_count": malicious_count,
            "clean_count": clean_count,
            "skipped_count": skipped_count,
            "total_files": total_files,
            "files_per_second": 1,
            "malicious_files": malicious_files
        }
    else:
        # Folder scan
        last_update_time = start_time
        files_since_last_update = 0
        files_per_second = 0
        
        # Yield initial progress
        yield {
            "status": "progress",
            "total_scanned": total_scanned,
            "malicious_count": malicious_count,
            "clean_count": clean_count,
            "skipped_count": skipped_count,
            "total_files": total_files,
            "files_per_second": files_per_second,
            "malicious_files": malicious_files
        }
        
        for root, _, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    file_hash = calculate_file_hash(file_path)
                    if file_hash:
                        total_scanned += 1
                        files_since_last_update += 1
                        
                        if file_hash in known_hashes:
                            malicious_count += 1
                            malicious_files.append([file, file_path, "Malicious File"])
                        else:
                            clean_count += 1
                    else:
                        skipped_count += 1
                except (PermissionError, OSError):
                    skipped_count += 1
                
                # Calculate scan speed and update progress every 100 files or 0.5 seconds
                current_time = time.time()
                if files_since_last_update >= 100 or (current_time - last_update_time) >= 0.5:
                    time_diff = current_time - last_update_time
                    if time_diff > 0:
                        files_per_second = files_since_last_update / time_diff
                    
                    yield {
                        "status": "progress",
                        "total_scanned": total_scanned,
                        "malicious_count": malicious_count,
                        "clean_count": clean_count,
                        "skipped_count": skipped_count,
                        "total_files": max(total_files, total_scanned),
                        "files_per_second": files_per_second,
                        "malicious_files": malicious_files
                    }
                    
                    last_update_time = current_time
                    files_since_last_update = 0

    elapsed_time = time.time() - start_time
    
    # Final progress update
    yield {
        "status": "progress",
        "total_scanned": total_scanned,
        "malicious_count": malicious_count,
        "clean_count": clean_count,
        "skipped_count": skipped_count,
        "total_files": max(total_files, total_scanned),
        "files_per_second": total_scanned / max(elapsed_time, 0.001),
        "malicious_files": malicious_files,
        "elapsed_time": elapsed_time
    }