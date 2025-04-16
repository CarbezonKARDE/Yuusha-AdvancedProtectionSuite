from flask import Flask, render_template, jsonify, Response, request, url_for, redirect
from modules.memory_scanner import connect_to_database as mem_connect, get_known_hashes as get_mem_hashes, scan_memory
from modules.task_manager import update_process_info
from modules.file_scanner import connect_to_database, get_known_hashes, scan_path
from modules.locker import encrypt_file, decrypt_file, get_locker_files, reencrypt_file, cleanup_database
from flask import Flask, render_template, request, redirect, flash
from modules.firewall import get_firewall_rules, block_ip, unblock_rule, block_port
from modules.vpn_client import VPNClient
import ctypes
import threading
import queue
import json
import time
import os
import tempfile
import sys

app = Flask(__name__)

vpn_client = VPNClient()  # Initialize VPNClient


# Configuration
DATABASE_PATH = r"C:\Users\aikan\Downloads\AdvancedProtectionSuite\Database\latestdata.db"
scan_queue = queue.Queue()
current_scan_thread = None
stop_event = threading.Event()


@app.route('/')
def index():
    """Homepage with navigation to different sections."""
    return render_template('index.html')

@app.route('/task_manager')
def task_manager_route():
    """Task Manager page with real-time system monitoring."""
    return render_template('task_manager.html')

@app.route('/task_manager/data')
def task_manager_data():
    """Stream real-time system monitoring data using SSE."""
    def generate():
        while True:
            processes, total_cpu, total_read, total_write = update_process_info()
            data = {
                "cpu": total_cpu,
                "read": total_read,
                "write": total_write,
                "processes": processes
            }
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(1)
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/memory_scanner')
def memory_scanner():
    """Memory Scanner page."""
    return render_template('memory_scanner.html')

@app.route('/memory_scan/start')
def memory_scan_start():
    """Stream memory scan results using SSE."""
    def generate():
        conn = mem_connect(DATABASE_PATH)
        known_hashes = get_mem_hashes(conn)
        conn.close()

        for total_scanned, malicious_count, clean_count, process in scan_memory(known_hashes):
            data = {
                "total": total_scanned,
                "malicious": malicious_count,
                "clean": clean_count,
                "process": process
            }
            yield f"data: {json.dumps(data)}\n\n"
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/file_scanner')
def file_scanner():
    """File Scanner page."""
    return render_template('file_scanner.html')

@app.route('/file_scan/start', methods=['POST'])
def start_file_scan():
    global current_scan_thread, stop_event
    stop_event.clear()
    
    scan_type = request.json.get('type')
    custom_path = request.json.get('path', '')
    
    if current_scan_thread and current_scan_thread.is_alive():
        return jsonify({"status": "error", "message": "Scan already in progress"}), 400
    
    # Determine scan path
    root_path = ''
    if scan_type == 'full':
        root_path = 'C:\\' if os.name == 'nt' else '/'
    elif scan_type == 'folder':
        root_path = custom_path.strip()
        if not root_path:
            return jsonify({"status": "error", "message": "Please enter a valid path"}), 400
    elif scan_type == 'file':
        root_path = custom_path.strip()
        if not root_path:
            return jsonify({"status": "error", "message": "Please enter a valid file path"}), 400
        if not os.path.isfile(root_path):
            return jsonify({"status": "error", "message": f"Invalid file path: {root_path}"}), 400
    else:
        # Handle custom scan type
        root_path = custom_path.strip()
        if not root_path:
            return jsonify({"status": "error", "message": "Please enter a valid path"}), 400
        if not os.path.exists(root_path):
            return jsonify({"status": "error", "message": f"Invalid path: {root_path}"}), 400
    
    if not os.path.exists(root_path):
        return jsonify({"status": "error", "message": f"Invalid path: {root_path}"}), 400

    # Start scan thread
    def scan_runner():
        try:
            conn = connect_to_database(DATABASE_PATH)
            known_hashes = get_known_hashes(conn)
            conn.close()
            
            for progress in scan_path(root_path, known_hashes):
                if stop_event.is_set():
                    break
                scan_queue.put(progress)
            
            scan_queue.put({"status": "completed", "stopped": stop_event.is_set()})
        except Exception as e:
            scan_queue.put({"status": "error", "message": str(e)})

    current_scan_thread = threading.Thread(target=scan_runner)
    current_scan_thread.daemon = True  # Ensure thread exits when main program exits
    current_scan_thread.start()
    
    return jsonify({"status": "success", "message": f"Scan started for {root_path}"})

@app.route('/file_scan/stop', methods=['POST'])
def stop_file_scan():
    global stop_event
    stop_event.set()
    return jsonify({"status": "success", "message": "Scan stopping..."})

@app.route('/file_scan/status')
def file_scan_status():
    def generate():
        while True:
            try:
                data = scan_queue.get(timeout=5)  # Reduced timeout for more responsive UI
                if data.get('status') == 'completed':
                    yield f"data: {json.dumps(data)}\n\n"
                    break
                yield f"data: {json.dumps(data)}\n\n"
            except queue.Empty:
                yield "data: {\"status\": \"ping\"}\n\n"
    return Response(generate(), mimetype='text/event-stream')

app.secret_key = "firewall_manager_secret_key"

@app.route("/firewall", methods=["GET", "POST"])
def firewall():
    if request.method == "POST":
        action = request.form.get("action")
        rule_name = request.form.get("rule_name")
        
        try:
            if action in ["block_ip", "unblock_ip"]:
                target = request.form.get("target_ip")
                direction = request.form.get("ip_direction", "Inbound")
                
                if action == "block_ip":
                    if not target:
                        raise ValueError("IP address is required")
                    result = block_ip(rule_name, target, direction)
                    if "error" not in result.lower():
                        flash(f"Blocked IP {target}", "success")
                    else:
                        flash(result, "error")
                        
                elif action == "unblock_ip":
                    result = unblock_rule(rule_name)
                    if "error" not in result.lower():
                        flash(f"Removed rule: {rule_name}", "success")
                    else:
                        flash(result, "error")
                        
            elif action in ["block_port", "unblock_port"]:
                port = request.form.get("port")
                direction = request.form.get("port_direction", "Inbound")
                protocol = request.form.get("protocol", "TCP")
                
                if action == "block_port":
                    if not port:
                        raise ValueError("Port number is required")
                    result = block_port(rule_name, port, protocol, direction)
                    if "error" not in result.lower():
                        flash(f"Blocked {protocol} port {port}", "success")
                    else:
                        flash(result, "error")
                        
                elif action == "unblock_port":
                    result = unblock_rule(rule_name)
                    if "error" not in result.lower():
                        flash(f"Removed rule: {rule_name}", "success")
                    else:
                        flash(result, "error")
                        
        except Exception as e:
            flash(f"Error: {str(e)}", "error")

    rules, headers, active_rules = get_firewall_rules()
    return render_template(
        "firewall.html",
        rules=rules,
        headers=headers,
        active_rules=active_rules
    )


LOCKER_DIR = os.path.join(os.getcwd(), 'locker')
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()

@app.route('/locker')
def locker():
    return render_template('locker.html')

@app.route('/locker/files')
def handle_locker_files():
    try:
        return jsonify(get_locker_files())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/locker/encrypt', methods=['POST'])
def handle_encrypt():
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files selected'}), 400
        
        password = request.form.get('password')
        if not password or len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400

        for file in request.files.getlist('files'):
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(temp_path)
            encrypt_file(temp_path, password)
            os.remove(temp_path)
            
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/locker/decrypt', methods=['POST'])
def handle_decrypt():
    try:
        data = request.get_json()
        if not data or 'filenames' not in data or 'password' not in data:
            return jsonify({'error': 'Invalid request'}), 400

        results = []
        all_success = True  # Track if all files decrypt successfully

        for filename in data['filenames']:
            success = decrypt_file(filename, data['password'])
            results.append({'filename': filename, 'success': success})
            
            if not success:  # If even one file fails, mark `all_success` as False
                all_success = False

        return jsonify({'success': all_success, 'results': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/locker/reencrypt', methods=['POST'])
def handle_reencrypt():
    try:
        data = request.get_json()
        if not data or 'filename' not in data or 'password' not in data:
            return jsonify({'success': False, 'error': 'Missing parameters'}), 400
            
        success = reencrypt_file(data['filename'], data['password'])
        return jsonify({'success': success, 'filename': data['filename']})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/locker/cleanup', methods=['POST'])
def handle_cleanup():
    try:
        removed = cleanup_database()
        return jsonify({'success': True, 'removed': removed})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/locker/bulk-reencrypt', methods=['POST'])
def handle_bulk_reencrypt():
    try:
        data = request.get_json()
        if not data or 'filenames' not in data or 'password' not in data:
            return jsonify({'error': 'Invalid request'}), 400

        results = []
        for filename in data['filenames']:
            try:
                success = reencrypt_file(filename, data['password'])
                results.append({'filename': filename, 'success': success})
            except Exception as e:
                results.append({'filename': filename, 'success': False, 'error': str(e)})
        
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def check_admin():
    try:
        if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            print("Error: This application must be run as administrator.")
            sys.exit(1)
    except AttributeError:
        pass

@app.route('/vpn')
def vpn_interface():
    """VPN management interface."""
    return render_template('vpn.html',
                         ovpn_files=vpn_client.get_ovpn_files(),
                         status=vpn_client.get_status())

@app.route('/vpn/connect', methods=['POST'])
def vpn_connect():
    """Connect to a VPN profile."""
    profile = request.form.get('profile')
    if profile:
        vpn_client.connect(profile)
    return redirect(url_for('vpn_interface'))

@app.route('/vpn/disconnect', methods=['POST'])
def vpn_disconnect():
    """Disconnect from the VPN."""
    vpn_client.disconnect()
    return redirect(url_for('vpn_interface'))

@app.route('/vpn/status')
def vpn_status():
    """Get current VPN status."""
    return jsonify(vpn_client.get_status())

if __name__ == '__main__':
    check_admin()  # Ensure admin rights
    app.run(debug=True, threaded=True)