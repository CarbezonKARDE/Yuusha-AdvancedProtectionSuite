import os
import subprocess
import time
import threading
import ctypes

class VPNClient:
    def __init__(self):
        self.OVPN_DIR = r"path\to\Yuusha\vpn_configs"
        self.OPENVPN_PATH = r"C:\Program Files\OpenVPN\bin\openvpn.exe"
        self.LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'openvpn.log')
        
        self.status_lock = threading.Lock()
        self.active_connection = None
        self.connection_status = "Disconnected"
        self.connection_process = None
        self.status_thread = None
        self.stop_thread = False

    def get_ovpn_files(self):
        if not os.path.exists(self.OVPN_DIR):
            return []
        return [f for f in os.listdir(self.OVPN_DIR) if f.endswith('.ovpn')]

    def _connection_monitor(self):
        while not self.stop_thread:
            if self.connection_process.poll() is not None:
                with self.status_lock:
                    self.connection_status = "Disconnected"
                break
            
            try:
                with open(self.LOG_PATH, 'r') as f:
                    log_content = f.read()
                
                with self.status_lock:
                    if "Initialization Sequence Completed" in log_content:
                        self.connection_status = "Connected"
                    else:
                        self.connection_status = "Connecting..."
            except Exception as e:
                with self.status_lock:
                    self.connection_status = "Connecting..."
            
            time.sleep(1)

    def connect(self, profile):
        if self.connection_process and self.connection_process.poll() is None:
            self.disconnect()
        
        profile_path = os.path.join(self.OVPN_DIR, profile)
        
        try:
            self.connection_process = subprocess.Popen(
                [self.OPENVPN_PATH, '--config', profile_path, '--log', self.LOG_PATH],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=True
            )
            
            with self.status_lock:
                self.active_connection = profile
                self.connection_status = "Connecting..."
            
            self.stop_thread = False
            self.status_thread = threading.Thread(target=self._connection_monitor)
            self.status_thread.daemon = True
            self.status_thread.start()
            return True
        except Exception as e:
            with self.status_lock:
                self.connection_status = f"Error: {str(e)}"
            return False

    def _cleanup_openvpn(self):
        """Force kill any remaining OpenVPN processes"""
        subprocess.run(
            ['taskkill', '/F', '/IM', 'openvpn.exe', '/T'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )
        time.sleep(1)  # Give system time to clean up

    def disconnect(self):
        """Disconnect from VPN and clean up processes"""
        # Kill main process
        if self.connection_process:
            try:
                self.connection_process.terminate()
                self.connection_process.wait(timeout=3)
            except:
                pass
        
        # Force kill all OpenVPN processes
        self._cleanup_openvpn()
        
        # Thread cleanup
        self.stop_thread = True
        if self.status_thread and self.status_thread.is_alive():
            self.status_thread.join(timeout=2)
        self.status_thread = None
        self.stop_thread = False
        
        # Reset state
        with self.status_lock:
            self.connection_process = None
            self.active_connection = None
            self.connection_status = "Disconnected"
        
        return True

    def get_status(self):
        with self.status_lock:
            return {
                'status': self.connection_status,
                'active_connection': self.active_connection
            }
