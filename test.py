import subprocess
import re
import socket
import time
import os
import threading
import ipaddress

def scan_wifi_windows():
    """Scan for available Wi-Fi networks with more details."""
    print("\n📡 Scanning for Wi-Fi networks...\n")
    try:
        result = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True).decode("utf-8", errors="ignore")
        
        networks = []
        ssid_blocks = re.split(r"\n\s*SSID \d+ : ", result)[1:]
        
        print("=" * 60)
        print(f"{'SSID':<25} {'Signal':<10} {'Security':<15} {'BSSID/MAC':<20}")
        print("=" * 60)
        
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
            
            if not bssids:  # If no BSSIDs found
                print(f"{ssid:<25} {signal:<10} {security:<15} {'N/A':<20}")
            else:
                # Print first BSSID with network info
                print(f"{ssid:<25} {signal:<10} {security:<15} {bssids[0]:<20}")
                
                # Print additional BSSIDs if any
                for bssid in bssids[1:]:
                    print(f"{'↳':<25} {'':^10} {'':^15} {bssid:<20}")
            
            networks.append({
                'ssid': ssid,
                'signal': signal,
                'security': security,
                'bssids': bssids
            })
        
        return networks
    except Exception as e:
        print(f"❌ Error scanning WiFi networks: {e}")
        return []

def get_connected_wifi():
    """Get the currently connected WiFi network."""
    try:
        results = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], encoding="utf-8")
        ssid_match = re.search(r"SSID\s+: (.*)\r", results)
        if ssid_match:
            return ssid_match.group(1)
        return "Not connected"
    except Exception as e:
        return "Unknown"

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

def get_subnet():
    """Get the subnet of the local network based on local IP."""
    local_ip = get_local_ip()
    # Extract the first three octets of the IP address
    ip_parts = local_ip.split('.')
    if len(ip_parts) == 4:
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        return subnet
    return "192.168.1.0/24"  # Default fallback

def ping_host(ip, alive_hosts):
    """Ping a host to check if it's alive."""
    try:
        # Use ping with fast timeout (1 second)
        ping_param = "-n 1 -w 1000" if os.name == "nt" else "-c 1 -W 1"
        subprocess.check_output(f"ping {ping_param} {ip}", shell=True, stderr=subprocess.DEVNULL)
        alive_hosts.append(ip)
    except:
        pass

def ping_sweep(subnet):
    """Perform a ping sweep of the subnet to find active hosts."""
    print(f"\nPerforming ping sweep on subnet {subnet}...")
    
    # Parse the subnet
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
    except:
        print("❌ Invalid subnet, using default 192.168.1.0/24")
        network = ipaddress.IPv4Network("192.168.1.0/24", strict=False)
    
    # Prepare threading
    threads = []
    alive_hosts = []
    
    # Start ping sweep with multiple threads
    print("⏳ This might take a moment...")
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
    
    print(f"✅ Found {len(alive_hosts)} active hosts via ping sweep")
    return alive_hosts

def list_connected_devices():
    """List devices connected to the network with enhanced detection."""
    print("\n🔍 Scanning for connected devices...\n")
    
    devices = []
    
    # First, use ARP table to find devices
    try:
        output = subprocess.check_output("arp -a", shell=True).decode("utf-8", errors="ignore")
        lines = output.splitlines()
        
        for line in lines:
            if re.search(r"\d+\.\d+\.\d+\.\d+", line):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    mac = parts[1]
                    
                    # Skip invalid MAC addresses or broadcast addresses
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
                        'hostname': hostname,
                        'source': 'ARP'
                    })
    except Exception as e:
        print(f"❌ Error fetching ARP table: {e}")
    
    # Get IPs of all devices using ping sweep
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
                    'mac': mac_match.group(2),
                    'hostname': hostname,
                    'source': 'Ping+ARP'
                })
            else:
                # If we found an active IP but no MAC, add it anyway
                devices.append({
                    'ip': ip,
                    'mac': 'Unknown (Privacy?)',
                    'hostname': 'Unknown',
                    'source': 'Ping Only'
                })
        except:
            # If we can't get MAC, still add the IP
            devices.append({
                'ip': ip,
                'mac': 'Unknown (Privacy?)',
                'hostname': 'Unknown',
                'source': 'Ping Only'
            })
    
    # Display devices in a table format
    if devices:
        print("=" * 75)
        print(f"{'IP Address':<16} {'MAC Address':<24} {'Hostname':<20} {'Source':<10}")
        print("=" * 75)
        
        for device in devices:
            print(f"{device['ip']:<16} {device['mac']:<24} {device['hostname']:<20} {device['source']:<10}")
    else:
        print("No devices found on the network.")
    
    return devices

def check_hotspot_status():
    """Check if Windows hotspot is enabled and get its details."""
    try:
        output = subprocess.check_output("netsh wlan show hostednetwork", shell=True).decode("utf-8", errors="ignore")
        
        status_match = re.search(r"Status\s+:\s+(\w+)", output)
        ssid_match = re.search(r"SSID name\s+:\s+\"(.+?)\"", output)
        
        if status_match and ssid_match:
            status = status_match.group(1)
            ssid = ssid_match.group(1)
            
            if status.lower() == "started":
                print(f"\n✅ Hotspot active: {ssid}")
                return True
            else:
                print("\n❌ Hotspot is not active")
                return False
        else:
            print("\n❓ Couldn't determine hotspot status")
            return False
    except:
        print("\n❌ No hotspot configuration found")
        return False

def main():
    # Clear screen for better visibility
    os.system('cls')
    
    print("=" * 75)
    print("📶 Advanced WiFi Scanner and Device Detector (with Mobile Phone Detection) 📶")
    print("=" * 75)
    
    # Display current connection info
    connected_wifi = get_connected_wifi()
    local_ip = get_local_ip()
    print(f"Connected WiFi: {connected_wifi}")
    print(f"Your IP address: {local_ip}")
    
    # Check if hotspot is active
    hotspot_active = check_hotspot_status()
    
    # Scan WiFi networks
    networks = scan_wifi_windows()
    
    # List connected devices with enhanced detection
    devices = list_connected_devices()
    
    print("\n" + "=" * 75)
    print(f"Found {len(networks)} WiFi networks and {len(devices)} connected devices")
    print("Note: If a device shows 'Unknown (Privacy?)' for MAC, it likely has MAC randomization enabled")
    print("=" * 75)
    
    # Keep console open
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()