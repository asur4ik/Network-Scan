#comand-line, arguments and exiting
import sys
#networking interface and ip operations
import socket
#ip network calculations
import ipaddress
# parallel executions
import concurrent.futures
#detect operating sys
import platform
#run os-programms
import subprocess
#reg expressions
import re
#future os operations
import os

#======================================================================================================

def print_app_name():
    print(r""" 
/$$                 /$$ /$$          
| $$                | $$| $$          
| $$$$$$$   /$$$$$$ | $$| $$  /$$$$$$ 
| $$__  $$ /$$__  $$| $$| $$ /$$__  $$
| $$  \ $$| $$$$$$$$| $$| $$| $$  \ $$
| $$  | $$| $$_____/| $$| $$| $$  | $$
| $$  | $$|  $$$$$$$| $$| $$|  $$$$$$/
|__/  |__/ \_______/|__/|__/ \______/ 
            """)

#========================================================================================================

def get_local_ip_and_mask():
    """
    Ermittelt die lokale IP-Adresse und die Subnetzmaske des Systems.
    Funktioniert sowohl unter Windows als auch unter Unix-artigen Systemen.
    """
    system = platform.system().lower()  # detect the OS type
    if system == 'windows':
        output = subprocess.check_output("ipconfig", universal_newlines=True)  # Run ipconfig and get output
        ip_match = re.search(r'IPv4 Address[. ]*: ([\d.]+)', output)  # findet IPv4 Adresse
        mask_match = re.search(r'Subnet Mask[. ]*: ([\d.]+)', output)  # findet Subnetzmaske
        if ip_match and mask_match:
            return ip_match.group(1), mask_match.group(1)
    else:
        # Linux/macOS
        output = subprocess.check_output(["ifconfig"], universal_newlines=True)
        ip_match = re.search(r'inet ([\d.]+).*?netmask (0x[\da-f]+|[\d.]+)', output)
        if ip_match:
            ip = ip_match.group(1)
            mask = ip_match.group(2)
            if mask.startswith("0x"):
                mask = socket.inet_ntoa(int(mask, 16).to_bytes(4, "big"))
            return ip, mask

    # Fallback: connect out to detect the local IP if nothing matched above
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip, '255.255.255.0'

#========================================================================================================

def mask_to_cidr(mask):
    return sum(bin(int(x)).count('1') for x in mask.split('.'))

#========================================================================================================

def parse_network(arg=None):
    """
    Analysiert das Netzwerk-Argument und gibt ein ip_network-Objekt zurück.
    Unterstützt den Aufruf ohne Argumente (automatische Erkennung) sowie
    Angaben wie /24, /16 usw.
    """
    if not arg:
        ip, mask = get_local_ip_and_mask()
        cidr = mask_to_cidr(mask)
        return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
    if '/' in arg:
        return ipaddress.ip_network(arg, strict=False)
    elif re.match(r'^\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '.0/24', strict=False)
    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '/24', strict=False)
    else:
        raise ValueError("Invalid network format")

#=====================================================================================================

def ping(ip):
    ip = str(ip)
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if re.search(r"ttl", result.stdout, re.IGNORECASE):
            return ip
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

#=====================================================================================================

def scan_network(network):
    print(f"Scanning network: {network}")
    active_hosts = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(ping, ip): ip for ip in network.hosts()}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        active_hosts.append(result)
                except Exception:
                    continue
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Showing results so far...")
    return active_hosts

#=====================================================================================================

def show_help():
    """
    Prints usage and help information for the script.
    """
    print(
        "Usage: netScan [network]\n"
        "Scan a network for active hosts.\n"
        "Options:\n"
        "  -h, --help    Show this help message and exit\n"
        "Examples:\n"
        "  netScan                    # Scan the local network\n"
        "  netScan 192.168.1.0        # Scan 192.168.1.0/24\n"
        "  netScan 192.168.1          # Scan 192.168.1.0/24\n"
        "  netScan 192.168.1.0/24     # Scan 192.168.1.0/24"
    )

#=====================================================================================================

def main():
    """
    Main function: parses arguments, runs scans, prints results.
    """
    args = sys.argv[1:]

    if not args:
        try:
            network = parse_network()
        except Exception as e:
            print(f"Error: {e}")
            show_help()
            return
    elif args[0] in ("-h", "--help"):
        show_help()
        return
    elif len(args) == 1:
        try:
            network = parse_network(args[0])
        except Exception as e:
            print(f"Error: {e}")
            show_help()
            return
    else:
        print("Error: too many arguments")
        show_help()
        return

    try:
        active_hosts = scan_network(network)
        print("Active hosts found:")
        for host in sorted(active_hosts, key=lambda ip: tuple(map(int, ip.split('.')))):
            print(host)
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Showing results so far...")


if __name__ == "__main__":
    main()
