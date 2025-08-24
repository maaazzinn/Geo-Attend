import os
import re
import csv
import time
import sqlite3
import subprocess
import socket
import threading
import ipaddress
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Replace with a proper secret key in production
DB_PATH = "database.db"

# Initialize database if it doesn't exist
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Drop existing tables to recreate with correct schema
    cursor.execute("DROP TABLE IF EXISTS attendance")
    cursor.execute("DROP TABLE IF EXISTS students")
    
    # Create students table with correct schema
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        class_name TEXT NOT NULL,
        roll_no TEXT NOT NULL,
        mac_address TEXT NOT NULL UNIQUE
    )
    ''')
    
    # Create attendance table with correct schema
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        class_name TEXT NOT NULL,
        subject TEXT NOT NULL,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        FOREIGN KEY (student_id) REFERENCES students (id)
    )
    ''')
    
    conn.commit()
    conn.close()

# Call init_db at startup
init_db()

# Function to get local IP address
def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))  # Connect to Google DNS
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# Function to get subnet based on local IP
def get_subnet():
    """Get the subnet of the local network based on local IP."""
    local_ip = get_local_ip()
    # Extract the first three octets of the IP address
    ip_parts = local_ip.split('.')
    if len(ip_parts) == 4:
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        return subnet
    return "192.168.1.0/24"  # Default fallback

# Function to ping a host
def ping_host(ip, alive_hosts):
    """Ping a host to check if it's alive."""
    try:
        # Use ping with fast timeout (1 second)
        ping_param = "-n 1 -w 1000" if os.name == "nt" else "-c 1 -W 1"
        subprocess.check_output(f"ping {ping_param} {ip}", shell=True, stderr=subprocess.DEVNULL)
        alive_hosts.append(ip)
    except:
        pass

# Function to ping sweep a subnet
def ping_sweep(subnet):
    """Perform a ping sweep of the subnet to find active hosts."""
    # Parse the subnet
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
    except:
        network = ipaddress.IPv4Network("192.168.1.0/24", strict=False)
    
    # Prepare threading
    threads = []
    alive_hosts = []
    
    # Start ping sweep with multiple threads
    for ip in network.hosts():
        ip_str = str(ip)
        thread = threading.Thread(target=ping_host, args=(ip_str, alive_hosts))
        thread.daemon = True
        threads.append(thread)
        thread.start()
        
        # Limit number of concurrent threads
        if len(threads) >= 20:
            for t in threads:
                t.join()
            threads = []
    
    # Wait for remaining threads
    for t in threads:
        t.join()
    
    return alive_hosts

# Enhanced function to list connected devices
def list_connected_devices():
    """List devices connected to the network with enhanced detection."""
    devices = []
    macs = []
    
    # First, use ARP table to find devices
    try:
        output = subprocess.check_output("arp -a", shell=True).decode("utf-8", errors="ignore")
        lines = output.splitlines()
        
        for line in lines:
            if re.search(r"\d+\.\d+\.\d+\.\d+", line):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    mac = parts[1].lower()
                    
                    # Skip invalid MAC addresses or broadcast addresses
                    if mac == "ff-ff-ff-ff-ff-ff" or mac.startswith("00-00-00"):
                        continue
                    
                    macs.append(mac)
                    devices.append({
                        'ip': ip,
                        'mac': mac
                    })
    except Exception as e:
        print(f"Error fetching ARP table: {e}")
    
    # Get IPs of all devices using ping sweep for more comprehensive detection
    subnet = get_subnet()
    active_ips = ping_sweep(subnet)
    
    # For each active IP not already in our list, try to get MAC
    for ip in active_ips:
        # Skip if we already have this IP
        if any(d['ip'] == ip for d in devices):
            continue
        
        # Force an ARP cache update by pinging again
        try:
            subprocess.check_output(f"ping -n 1 {ip}", shell=True, stderr=subprocess.DEVNULL)
            time.sleep(0.1)  # Small delay to allow ARP cache update
        except:
            pass
        
        # Check ARP cache again for this specific IP
        try:
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode("utf-8", errors="ignore")
            mac_match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+", output)
            
            if mac_match and mac_match.group(2) != "ff-ff-ff-ff-ff-ff" and not mac_match.group(2).startswith("00-00-00"):
                mac = mac_match.group(2).lower()
                macs.append(mac)
                devices.append({
                    'ip': ip,
                    'mac': mac
                })
        except:
            pass
    
    return macs

# Check if user is logged in
def is_logged_in():
    return 'logged_in' in session and session['logged_in']

# Routes
@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Hardcoded credentials (in a real app, use a secure auth system)
        if username == 'icet' and password == 'icet123':
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    # Get today's date
    today = datetime.now().strftime('%Y-%m-%d')
    
    # Get class list for dropdown
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT class_name FROM students ORDER BY class_name")
    classes = [row[0] for row in cursor.fetchall()]
    
    # Get today's attendance summary
    cursor.execute('''
    SELECT s.class_name, a.subject, COUNT(DISTINCT a.student_id) as count
    FROM attendance a
    JOIN students s ON a.student_id = s.id
    WHERE a.date = ?
    GROUP BY s.class_name, a.subject
    ''', (today,))
    
    attendance_summary = cursor.fetchall()
    conn.close()
    
    return render_template('dashboard.html', 
                          classes=classes, 
                          today=today, 
                          attendance_summary=attendance_summary)

@app.route('/start_attendance', methods=['POST'])
def start_attendance():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    selected_class = request.form.get('class')
    subject = request.form.get('subject')
    
    if not selected_class or not subject:
        return jsonify({'success': False, 'message': 'Class and subject are required'})
    
    # Get connected devices with enhanced detection
    connected_macs = list_connected_devices()
    
    # Mark attendance for matching devices
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get students in the selected class
    cursor.execute('''
    SELECT id, name, roll_no, mac_address FROM students
    WHERE class_name = ?
    ''', (selected_class,))
    
    students = cursor.fetchall()
    marked_students = []
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.now().strftime('%H:%M:%S')
    
    for student in students:
        student_id, name, roll_no, mac_address = student
        
        # Check if MAC address is in connected devices
        if mac_address.lower() in connected_macs:
            # Check if attendance already marked for today
            cursor.execute('''
            SELECT COUNT(*) FROM attendance
            WHERE student_id = ? AND date = ? AND subject = ?
            ''', (student_id, current_date, subject))
            
            already_marked = cursor.fetchone()[0] > 0
            
            if not already_marked:
                # Mark attendance
                cursor.execute('''
                INSERT INTO attendance (student_id, class_name, subject, date, time)
                VALUES (?, ?, ?, ?, ?)
                ''', (student_id, selected_class, subject, current_date, current_time))
                
                marked_students.append({
                    'id': student_id,
                    'name': name,
                    'roll_no': roll_no,
                    'status': 'Present'
                })
            else:
                marked_students.append({
                    'id': student_id,
                    'name': name,
                    'roll_no': roll_no,
                    'status': 'Already Marked'
                })
        else:
            marked_students.append({
                'id': student_id,
                'name': name,
                'roll_no': roll_no,
                'status': 'Absent'
            })
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True, 
        'message': f'Attendance marked for {len(marked_students)} students',
        'students': marked_students
    })

@app.route('/students')
def students():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM students ORDER BY class_name, name")
    students_list = cursor.fetchall()
    
    conn.close()
    
    return render_template('students.html', students=students_list)

@app.route('/add_student', methods=['POST'])
def add_student():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    name = request.form.get('name')
    student_class = request.form.get('class')
    roll_no = request.form.get('roll_no')
    mac_address = request.form.get('mac_address').lower()
    
    if not name or not student_class or not roll_no or not mac_address:
        flash('All fields are required!', 'error')
        return redirect(url_for('students'))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
        INSERT INTO students (name, class_name, roll_no, mac_address)
        VALUES (?, ?, ?, ?)
        ''', (name, student_class, roll_no, mac_address))
        
        conn.commit()
        flash('Student added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('MAC address already exists!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('students'))

@app.route('/edit_student/<int:student_id>', methods=['GET', 'POST'])
def edit_student(student_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if request.method == 'POST':
        name = request.form.get('name')
        student_class = request.form.get('class')
        roll_no = request.form.get('roll_no')
        mac_address = request.form.get('mac_address').lower()
        
        try:
            cursor.execute('''
            UPDATE students
            SET name = ?, class_name = ?, roll_no = ?, mac_address = ?
            WHERE id = ?
            ''', (name, student_class, roll_no, mac_address, student_id))
            
            conn.commit()
            flash('Student updated successfully!', 'success')
        except sqlite3.IntegrityError:
            flash('MAC address already exists!', 'error')
        
        conn.close()
        return redirect(url_for('students'))
    
    # GET request - display edit form
    cursor.execute("SELECT * FROM students WHERE id = ?", (student_id,))
    student = cursor.fetchone()
    
    if not student:
        flash('Student not found!', 'error')
        conn.close()
        return redirect(url_for('students'))
    
    conn.close()
    return render_template('edit_student.html', student=student)

@app.route('/delete_student/<int:student_id>')
def delete_student(student_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if student exists
    cursor.execute("SELECT * FROM students WHERE id = ?", (student_id,))
    student = cursor.fetchone()
    
    if not student:
        flash('Student not found!', 'error')
        conn.close()
        return redirect(url_for('students'))
    
    # Delete student
    cursor.execute("DELETE FROM students WHERE id = ?", (student_id,))
    
    # Delete associated attendance records
    cursor.execute("DELETE FROM attendance WHERE student_id = ?", (student_id,))
    
    conn.commit()
    conn.close()
    
    flash('Student deleted successfully!', 'success')
    return redirect(url_for('students'))

@app.route('/history')
def history():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    cursor = conn.cursor()
    
    # Get filter parameters
    date_filter = request.args.get('date', '')
    class_filter = request.args.get('class', '')
    subject_filter = request.args.get('subject', '')
    
    # Base query
    query = '''
    SELECT a.id, s.name, s.roll_no, a.class_name, a.subject, a.date, a.time
    FROM attendance a
    JOIN students s ON a.student_id = s.id
    WHERE 1=1
    '''
    
    params = []
    
    # Add filters if provided
    if date_filter:
        query += " AND a.date = ?"
        params.append(date_filter)
    
    if class_filter:
        query += " AND a.class_name = ?"
        params.append(class_filter)
    
    if subject_filter:
        query += " AND a.subject = ?"
        params.append(subject_filter)
    
    query += " ORDER BY a.date DESC, a.time DESC"
    
    cursor.execute(query, params)
    attendance_records = cursor.fetchall()
    
    # Get distinct classes and subjects for filters
    cursor.execute("SELECT DISTINCT class_name FROM students ORDER BY class_name")
    classes = [row['class_name'] for row in cursor.fetchall()]
    
    cursor.execute("SELECT DISTINCT subject FROM attendance ORDER BY subject")
    subjects = [row['subject'] for row in cursor.fetchall()]
    
    cursor.execute("SELECT DISTINCT date FROM attendance ORDER BY date DESC")
    dates = [row['date'] for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template('history.html',
                          attendance=attendance_records,
                          classes=classes,
                          subjects=subjects,
                          dates=dates,
                          date_filter=date_filter,
                          class_filter=class_filter,
                          subject_filter=subject_filter)

@app.route('/export_csv')
def export_csv():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    # Get filter parameters
    date_filter = request.args.get('date', '')
    class_filter = request.args.get('class', '')
    subject_filter = request.args.get('subject', '')
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Base query
    query = '''
    SELECT s.name, s.roll_no, a.class_name, a.subject, a.date, a.time
    FROM attendance a
    JOIN students s ON a.student_id = s.id
    WHERE 1=1
    '''
    
    params = []
    filename = "attendance"
    
    # Add filters if provided
    if date_filter:
        query += " AND a.date = ?"
        params.append(date_filter)
        filename += f"_{date_filter}"
    
    if class_filter:
        query += " AND a.class_name = ?"
        params.append(class_filter)
        filename += f"_{class_filter}"
    
    if subject_filter:
        query += " AND a.subject = ?"
        params.append(subject_filter)
        filename += f"_{subject_filter}"
    
    query += " ORDER BY a.date DESC, a.time DESC"
    
    cursor.execute(query, params)
    attendance_records = cursor.fetchall()
    
    # Create a CSV file
    filepath = f"temp_{filename}.csv"
    with open(filepath, 'w', newline='') as csvfile:
        fieldnames = ['Name', 'Roll No', 'Class', 'Subject', 'Date', 'Time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for record in attendance_records:
            writer.writerow({
                'Name': record['name'],
                'Roll No': record['roll_no'],
                'Class': record['class_name'],
                'Subject': record['subject'],
                'Date': record['date'],
                'Time': record['time']
            })
    
    conn.close()
    
    # Send file to user and delete it after
    response = send_file(filepath, as_attachment=True, 
                         download_name=f"{filename}.csv",
                         mimetype='text/csv')
    
    # Schedule file deletion after response is sent
    @response.call_on_close
    def delete_file():
        time.sleep(1)  # Small delay to ensure file transfer is complete
        if os.path.exists(filepath):
            os.remove(filepath)
    
    return response

@app.route('/scan_devices')
def scan_devices():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    connected_devices = list_connected_devices()
    return jsonify({
        'success': True,
        'devices': connected_devices
    })

@app.route('/network_info')
def network_info():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    # Get network information
    local_ip = get_local_ip()
    subnet = get_subnet()
    
    # Get connected devices with IP and MAC addresses
    devices = []
    
    try:
        # Use ARP table to find devices
        output = subprocess.check_output("arp -a", shell=True).decode("utf-8", errors="ignore")
        lines = output.splitlines()
        
        for line in lines:
            if re.search(r"\d+\.\d+\.\d+\.\d+", line):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    mac = parts[1].lower()
                    
                    # Skip invalid MAC addresses
                    if mac == "ff-ff-ff-ff-ff-ff" or mac.startswith("00-00-00"):
                        continue
                    
                    # Try to get hostname
                    hostname = "Unknown"
                    try:
                        hostname_result = socket.getfqdn(ip)
                        if hostname_result != ip:
                            hostname = hostname_result
                    except:
                        pass
                    
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'hostname': hostname
                    })
    except Exception as e:
        flash(f'Error scanning network: {e}', 'error')
    
    return render_template('network_info.html', 
                          local_ip=local_ip,
                          subnet=subnet,
                          devices=devices)

@app.route('/scan_wifi')
def scan_wifi():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    networks = []
    
    try:
        # Scan for WiFi networks
        result = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True).decode("utf-8", errors="ignore")
        
        ssid_blocks = re.split(r"\n\s*SSID \d+ : ", result)[1:]
        
        for block in ssid_blocks:
            lines = block.splitlines()
            ssid = lines[0].strip()
            
            # Extract signal and security information
            signal = "Unknown"
            security = "Unknown"
            
            for line in lines:
                if "Signal" in line and ":" in line:
                    signal = line.split(":", 1)[1].strip()
                if "Authentication" in line and ":" in line:
                    security = line.split(":", 1)[1].strip()
            
            # Extract BSSIDs (MAC addresses)
            bssids = [line.strip().split(" : ")[1] for line in lines if "BSSID" in line]
            
            networks.append({
                'ssid': ssid,
                'signal': signal,
                'security': security,
                'bssids': bssids
            })
    except Exception as e:
        flash(f'Error scanning WiFi networks: {e}', 'error')
    
    return render_template('wifi_scan.html', networks=networks)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')