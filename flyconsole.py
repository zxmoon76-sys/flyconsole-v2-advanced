import os
import sys
import time
import socket
import subprocess
import threading
import json
import re
import ssl
import hashlib
import random
import queue
import ipaddress
import concurrent.futures
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse
import argparse

# Try importing optional dependencies
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from scapy.all import ARP, Ether, srp, IP, TCP, sr1, sniff, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed. Some features limited.")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def show_banner():
    """Flyconsole Advanced ASCII Banner"""
    banner = f"""
{Colors.CYAN}    
    ███████╗██╗     ██╗   ██╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██╗     ███████╗
    ██╔════╝██║     ╚██╗ ██╔╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██║     ██╔════╝
    █████╗  ██║      ╚████╔╝ ██║     ██║   ██║██╔██╗ ██║███████╗██║   ██║██║     █████╗  
    ██╔══╝  ██║       ╚██╔╝  ██║     ██║   ██║██║╚██╗██║╚════██║██║   ██║██║     ██╔══╝  
    ██║     ███████╗   ██║   ╚██████╗╚██████╔╝██║ ╚████║███████║╚██████╔╝███████╗███████╗
    ╚═╝     ╚══════╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚══════╝╚══════╝
                                                                                    
    {Colors.RED}{Colors.BOLD}>>> ADVANCED SECURITY ANALYSIS FRAMEWORK v2.0 <<<{Colors.END}
    {Colors.WHITE}Created by: {Colors.YELLOW}Mamun (Natespo){Colors.END} | {Colors.WHITE}Status: {Colors.GREEN}Operational{Colors.END}
    {Colors.BLUE}─────────────────────────────────────────────────────────────────────────────{Colors.END}
    """
    print(banner)

class Logger:
    """Advanced logging system"""
    def __init__(self, log_file="flyconsole_log.json"):
        self.log_file = log_file
        self.logs = []
        
    def add_log(self, module, action, status, details):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'module': module,
            'action': action,
            'status': status,
            'details': details
        }
        self.logs.append(log_entry)
        self.save_to_file()
        
    def save_to_file(self):
        with open(self.log_file, 'w') as f:
            json.dump(self.logs[-100:], f, indent=2)  # Keep last 100 logs
            
    def display_logs(self):
        print(f"\n{Colors.CYAN}[*] Recent Activity Log:{Colors.END}")
        for log in self.logs[-5:]:  # Show last 5
            color = Colors.GREEN if log['status'] == 'success' else Colors.RED
            print(f"{color}[{log['timestamp']}] {log['module']}: {log['action']} - {log['status']}{Colors.END}")

logger = Logger()

class AdvancedScanner:
    """Enhanced scanning capabilities"""
    
    @staticmethod
    def tcp_syn_scan(target, port):
        """SYN scan using Scapy"""
        if not SCAPY_AVAILABLE:
            return None
        try:
            syn_packet = IP(dst=target)/TCP(dport=port, flags="S")
            response = sr1(syn_packet, timeout=1, verbose=0)
            if response and response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    return "OPEN"
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return "CLOSED"
            return "FILTERED"
        except:
            return None
    
    @staticmethod
    def service_detection(target, port):
        """Detect service version"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, port))
            
            # Send probe based on common services
            probes = {
                80: b"GET / HTTP/1.0\r\n\r\n",
                443: b"\x16\x03\x01\x00\xa1\x01\x00\x00\x9d\x03\x03",
                21: None,  # Will wait for banner
                22: None,
                25: None,
                3306: None,
            }
            
            if port in probes and probes[port]:
                s.send(probes[port])
            
            banner = s.recv(1024)
            s.close()
            return banner.decode('utf-8', errors='ignore')[:100]
        except:
            return None
    
    @staticmethod
    def os_fingerprint(target):
        """Basic OS fingerprinting using TTL and window size"""
        if not SCAPY_AVAILABLE:
            return "Unknown"
        try:
            response = sr1(IP(dst=target)/TCP(dport=80, flags="S"), timeout=2, verbose=0)
            if response:
                ttl = response.ttl
                if ttl <= 64:
                    return "Likely Linux/Unix"
                elif ttl <= 128:
                    return "Likely Windows"
                elif ttl <= 255:
                    return "Likely Network Device"
            return "Unknown"
        except:
            return "Unknown"

class VulnerabilityDatabase:
    """Local vulnerability database"""
    
    COMMON_VULNERABILITIES = {
        'ftp': {
            21: [
                {'name': 'Anonymous FTP access', 'severity': 'HIGH'},
                {'name': 'FTP bounce attack', 'severity': 'MEDIUM'},
            ]
        },
        'ssh': {
            22: [
                {'name': 'SSH version disclosure', 'severity': 'LOW'},
                {'name': 'Weak SSH algorithms', 'severity': 'MEDIUM'},
            ]
        },
        'http': {
            80: [
                {'name': 'Missing security headers', 'severity': 'MEDIUM'},
                {'name': 'Directory listing enabled', 'severity': 'LOW'},
                {'name': 'HTTP methods enabled', 'severity': 'MEDIUM'},
            ]
        },
        'https': {
            443: [
                {'name': 'SSL/TLS vulnerabilities', 'severity': 'HIGH'},
                {'name': 'Weak ciphers', 'severity': 'HIGH'},
            ]
        },
        'smb': {
            445: [
                {'name': 'SMBv1 enabled (EternalBlue)', 'severity': 'CRITICAL'},
            ]
        }
    }
    
    @classmethod
    def check_vulnerabilities(cls, port, service):
        """Check for known vulnerabilities"""
        found_vulns = []
        for category, ports in cls.COMMON_VULNERABILITIES.items():
            if port in ports:
                found_vulns.extend(ports[port])
        return found_vulns

class AdvancedHoneypot:
    """Advanced honeypot with deception techniques"""
    
    def __init__(self):
        self.active_honeypots = []
        self.connection_log = []
        self.deception_files = {
            'passwords.txt': 'admin:password123\nroot:toor\nuser:123456',
            'config.ini': '[database]\nhost=192.168.1.100\nuser=admin\npass=secret',
            'id_rsa': '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...'
        }
    
    def start_http_honeypot(self, port=8080):
        """HTTP honeypot with fake admin panel"""
        def handle_http():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen(5)
            
            while True:
                try:
                    conn, addr = s.accept()
                    request = conn.recv(1024).decode('utf-8', errors='ignore')
                    
                    # Log the attack
                    logger.add_log('Honeypot', 'HTTP Request', 'detected', f"From: {addr[0]}, Request: {request.split(chr(10))[0]}")
                    
                    # Check if it's a login attempt
                    if 'POST' in request and 'login' in request.lower():
                        logger.add_log('Honeypot', 'Login Attempt', 'alert', f"Brute force from {addr[0]}")
                        time.sleep(random.uniform(2, 5))  # Slow down attacker
                        response = "HTTP/1.1 401 Unauthorized\r\n\r\nInvalid credentials"
                    elif 'wp-admin' in request or 'phpmyadmin' in request:
                        # Fake admin panel
                        response = """HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
                        <html><head><title>Admin Panel</title></head>
                        <body><h1>Admin Panel</h1>
                        <form method="post"><input type="text" name="username">
                        <input type="password" name="password">
                        <input type="submit"></form></body></html>"""
                    else:
                        response = "HTTP/1.1 404 Not Found\r\n\r\nPage not found"
                    
                    conn.send(response.encode())
                    conn.close()
                    
                    # Log to file
                    with open('honeypot_attacks.log', 'a') as f:
                        f.write(f"{datetime.now()} - {addr[0]} - {request[:100]}\n")
                        
                except:
                    pass
        
        thread = threading.Thread(target=handle_http, daemon=True)
        thread.start()
        return thread
    
    def start_ftp_honeypot(self, port=21):
        """FTP honeypot with fake files"""
        def handle_ftp():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen(5)
            
            while True:
                conn, addr = s.accept()
                conn.send(b"220 FTP Server Ready\r\n")
                
                # Simulate FTP protocol
                authenticated = False
                while True:
                    try:
                        data = conn.recv(1024).decode()
                        if 'USER' in data:
                            conn.send(b"331 Username OK, need password\r\n")
                        elif 'PASS' in data:
                            logger.add_log('Honeypot', 'FTP Login', 'alert', f"FTP login attempt from {addr[0]}: {data.strip()}")
                            conn.send(b"230 Login successful\r\n")
                            authenticated = True
                        elif 'LIST' in data and authenticated:
                            # Send fake file listing
                            conn.send(b"150 Opening data connection\r\n")
                            time.sleep(1)
                            files = "-rw-r--r-- 1 user user 1234 Jan 01 2024 passwords.txt\r\n"
                            files += "-rw------- 1 user user 1679 Jan 01 2024 id_rsa\r\n"
                            conn.send(files.encode())
                            conn.send(b"226 Transfer complete\r\n")
                        elif 'QUIT' in data:
                            break
                    except:
                        break
                conn.close()
        
        thread = threading.Thread(target=handle_ftp, daemon=True)
        thread.start()
        return thread

class NetworkMapper:
    """Advanced network mapping capabilities"""
    
    @staticmethod
    def arp_scan(network="192.168.1.0/24"):
        """ARP scan to discover devices"""
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            result = srp(packet, timeout=3, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': NetworkMapper.get_mac_vendor(received.hwsrc)
                })
            return devices
        except:
            return None
    
    @staticmethod
    def get_mac_vendor(mac):
        """Get vendor from MAC address"""
        # Simplified vendor lookup
        vendors = {
            '00:1A:79': 'Cisco',
            '00:1B:63': 'Apple',
            '00:0C:29': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:1D:92': 'Aruba',
            'B8:27:EB': 'Raspberry Pi',
        }
        prefix = mac[:8].upper()
        return vendors.get(prefix, 'Unknown')

class WebSecurityAnalyzer:
    """Advanced web security analysis"""
    
    def __init__(self):
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        self.security_headers = {
            'Strict-Transport-Security': 'HSTS not enabled',
            'Content-Security-Policy': 'CSP not configured',
            'X-Frame-Options': 'Clickjacking vulnerable',
            'X-Content-Type-Options': 'MIME sniffing possible',
            'Referrer-Policy': 'Referrer leakage possible',
            'Permissions-Policy': 'Feature permissions not controlled',
        }
    
    def analyze_headers(self, url):
        """Analyze security headers"""
        if not REQUESTS_AVAILABLE:
            return None
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            headers = response.headers
            
            results = {
                'status_code': response.status_code,
                'server': headers.get('Server', 'Not disclosed'),
                'missing_headers': [],
                'present_headers': [],
                'cookies_secure': True,
                'vulnerabilities': []
            }
            
            # Check security headers
            for header, risk in self.security_headers.items():
                if header in headers:
                    results['present_headers'].append(header)
                else:
                    results['missing_headers'].append({'header': header, 'risk': risk})
            
            # Check cookies
            for cookie in response.cookies:
                if not cookie.secure:
                    results['cookies_secure'] = False
                    results['vulnerabilities'].append(f"Cookie '{cookie.name}' missing Secure flag")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    results['vulnerabilities'].append(f"Cookie '{cookie.name}' missing HttpOnly flag")
            
            # Check for information disclosure
            if 'X-Powered-By' in headers:
                results['vulnerabilities'].append(f"Technology disclosure: {headers['X-Powered-By']}")
            
            return results
        except Exception as e:
            return {'error': str(e)}
    
    def scan_common_paths(self, base_url):
        """Scan for common sensitive paths"""
        paths = [
            '/admin', '/backup', '/config', '/.git', '/.env',
            '/wp-admin', '/phpinfo.php', '/robots.txt', '/sitemap.xml',
            '/api', '/graphql', '/swagger', '/docs', '/debug'
        ]
        
        found_paths = []
        for path in paths:
            try:
                url = base_url.rstrip('/') + path
                response = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                if response.status_code != 404:
                    found_paths.append({
                        'path': path,
                        'status': response.status_code,
                        'size': len(response.content)
                    })
            except:
                pass
        
        return found_paths

class ReportGenerator:
    """Generate comprehensive reports"""
    
    @staticmethod
    def generate_html_report(scan_results, filename="scan_report.html"):
        """Generate HTML report from scan results"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Flyconsole Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #2c3e50; color: white; padding: 20px; }
                .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; }
                .critical { border-left: 5px solid #e74c3c; }
                .high { border-left: 5px solid #e67e22; }
                .medium { border-left: 5px solid #f1c40f; }
                .low { border-left: 5px solid #3498db; }
                .timestamp { color: #7f8c8d; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Flyconsole Security Scan Report</h1>
                <p>Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
            </div>
            <div class="content">
                {content}
            </div>
        </body>
        </html>
        """
        
        content = ""
        for module, findings in scan_results.items():
            content += f"<h2>{module}</h2>"
            for finding in findings:
                severity = finding.get('severity', 'low')
                content += f"""
                <div class="finding {severity}">
                    <h3>{finding.get('title', 'Finding')}</h3>
                    <p>{finding.get('description', '')}</p>
                    <p class="timestamp">Found: {finding.get('timestamp', '')}</p>
                </div>
                """
        
        with open(filename, 'w') as f:
            f.write(html_template.format(content=content))
        
        return filename

class AdvancedModules:
    """Enhanced module implementations"""
    
    def __init__(self):
        self.scanner = AdvancedScanner()
        self.web_analyzer = WebSecurityAnalyzer()
        self.mapper = NetworkMapper()
        self.honeypot = AdvancedHoneypot()
        self.results = defaultdict(list)
    
    def comprehensive_scan(self, target):
        """Run comprehensive security scan"""
        print(f"\n{Colors.CYAN}[*] Starting comprehensive scan on {target}{Colors.END}")
        print(f"{Colors.YELLOW}[!] This may take several minutes...{Colors.END}\n")
        
        # Port Scan
        print(f"{Colors.BOLD}Phase 1: Port Scanning{Colors.END}")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                       993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {
                executor.submit(self.scanner.tcp_syn_scan, target, port): port 
                for port in common_ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                result = future.result()
                if result == "OPEN":
                    open_ports.append(port)
                    print(f"{Colors.GREEN}[+] Port {port}: OPEN{Colors.END}")
                    
                    # Service detection
                    service = self.scanner.service_detection(target, port)
                    if service:
                        print(f"    Service: {service[:50]}")
                    
                    # Vulnerability check
                    vulns = VulnerabilityDatabase.check_vulnerabilities(port, service or '')
                    for vuln in vulns:
                        print(f"    {Colors.RED}[!] {vuln['name']} ({vuln['severity']}){Colors.END}")
                        self.results['Port Scan'].append({
                            'title': vuln['name'],
                            'description': f"Found on port {port}",
                            'severity': vuln['severity'].lower(),
                            'timestamp': datetime.now().isoformat()
                        })
        
        # OS Detection
        print(f"\n{Colors.BOLD}Phase 2: OS Detection{Colors.END}")
        os_type = self.scanner.os_fingerprint(target)
        print(f"{Colors.GREEN}[+] OS: {os_type}{Colors.END}")
        
        # Web Analysis (if web ports open)
        if 80 in open_ports or 443 in open_ports:
            print(f"\n{Colors.BOLD}Phase 3: Web Security Analysis{Colors.END}")
            protocol = 'https' if 443 in open_ports else 'http'
            url = f"{protocol}://{target}"
            
            header_analysis = self.web_analyzer.analyze_headers(url)
            if header_analysis and 'error' not in header_analysis:
                print(f"{Colors.GREEN}[+] Server: {header_analysis['server']}{Colors.END}")
                
                for missing in header_analysis['missing_headers']:
                    print(f"{Colors.RED}[!] Missing {missing['header']}: {missing['risk']}{Colors.END}")
                
                for vuln in header_analysis['vulnerabilities']:
                    print(f"{Colors.YELLOW}[!] {vuln}{Colors.END}")
                
                # Scan common paths
                paths = self.web_analyzer.scan_common_paths(url)
                if paths:
                    print(f"\n{Colors.YELLOW}[*] Interesting paths found:{Colors.END}")
                    for path in paths:
                        print(f"    {path['path']} (Status: {path['status']})")
            
            # Generate report
            report_file = ReportGenerator.generate_html_report(dict(self.results))
            print(f"\n{Colors.GREEN}[+] Report saved: {report_file}{Colors.END}")
        
        # ARP Scan for local targets
        if target.startswith('192.168.') or target.startswith('10.') or target.startswith('172.'):
            print(f"\n{Colors.BOLD}Phase 4: Network Discovery{Colors.END}")
            devices = self.mapper.arp_scan()
            if devices:
                print(f"\n{Colors.GREEN}Discovered Devices:{Colors.END}")
                for device in devices:
                    print(f"  IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}")

def show_advanced_menu():
    """Display the advanced menu"""
    clear_screen()
    show_banner()
    
    print(f"\n{Colors.BOLD}═══════════ MAIN MODULES ═══════════{Colors.END}")
    print(f"{Colors.WHITE}1.  Comprehensive Security Scan")
    print("2.  Advanced Port Scanner (SYN/Connect)")
    print("3.  Service & Version Detection")
    print("4.  OS Fingerprinting")
    print("5.  Web Security Analyzer")
    print("6.  Network Mapper (ARP/Traceroute)")
    
    print(f"\n{Colors.BOLD}═══════════ EXPLOITATION ═══════════{Colors.END}")
    print(f"{Colors.WHITE}7.  Vulnerability Assessment")
    print("8.  Web Path Scanner")
    print("9.  SSL/TLS Analyzer")
    
    print(f"\n{Colors.BOLD}═══════════ DEFENSE ═══════════{Colors.END}")
    print(f"{Colors.WHITE}10. Advanced Honeypot System")
    print("11. Intrusion Detection Monitor")
    print("12. Traffic Analysis")
    
    print(f"\n{Colors.BOLD}═══════════ UTILITIES ═══════════{Colors.END}")
    print(f"{Colors.WHITE}13. Generate Security Report")
    print("14. Log Viewer")
    print("15. Update Vulnerability Database")
    print(f"16. Exit{Colors.END}")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def loading_animation(message="Loading", duration=3):
    """Show loading animation"""
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f"\r{Colors.CYAN}{chars[i % len(chars)]} {message}...{Colors.END}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    print()

def main():
    """Main function with advanced features"""
    parser = argparse.ArgumentParser(description='Flyconsole Advanced Security Toolkit')
    parser.add_argument('--target', '-t', help='Target IP or hostname')
    parser.add_argument('--scan', '-s', choices=['quick', 'full', 'stealth'], help='Scan type')
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--module', '-m', help='Specific module to run')
    args = parser.parse_args()
    
    clear_screen()
    show_banner()
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("Initializing Flyconsole Advanced Engine...")
    
    # Enhanced loading animation
    loading_animation("Loading core modules", 2)
    
    modules = AdvancedModules()
    
    # If command line arguments provided, run in CLI mode
    if args.target:
        if args.scan:
            print(f"Running {args.scan} scan on {args.target}")
            modules.comprehensive_scan(args.target)
            return
    
    # Interactive mode
    while True:
        show_advanced_menu()
        try:
            choice = input(f"\n{Colors.GREEN}flyconsole-adv > {Colors.END}").strip()
            
            if choice == '1':
                target = input(f"{Colors.YELLOW}Enter target IP/domain: {Colors.END}").strip()
                if target:
                    loading_animation("Initiating comprehensive scan", 2)
                    modules.comprehensive_scan(target)
                    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
            
            elif choice == '2':
                print(f"{Colors.YELLOW}[*] Advanced Scanner Module{Colors.END}")
                target = input("Target: ").strip()
                if target:
                    # Custom port range
                    ports = input("Ports (e.g., 1-1000 or 80,443,8080): ").strip()
                    if '-' in ports:
                        start, end = map(int, ports.split('-'))
                        port_list = list(range(start, end+1))
                    elif ',' in ports:
                        port_list = [int(p) for p in ports.split(',')]
                    else:
                        port_list = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]
                    
                    loading_animation("Scanning ports", 1)
                    for port in port_list:
                        result = modules.scanner.tcp_syn_scan(target, port)
                        if result:
                            print(f"  Port {port}: {result}")
                    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
            
            elif choice == '10':
                print(f"{Colors.GREEN}[*] Starting Advanced Honeypot System{Colors.END}")
                print("1. HTTP Honeypot")
                print("2. FTP Honeypot")
                print("3. Both")
                hp_choice = input("Select: ").strip()
                
                if hp_choice in ['1', '3']:
                    thread = modules.honeypot.start_http_honeypot()
                    print(f"{Colors.GREEN}[+] HTTP Honeypot active on port 8080{Colors.END}")
                if hp_choice in ['2', '3']:
                    thread = modules.honeypot.start_ftp_honeypot()
                    print(f"{Colors.GREEN}[+] FTP Honeypot active on port 21{Colors.END}")
                
                print(f"{Colors.YELLOW}[!] Honeypots running. Check honeypot_attacks.log{Colors.END}")
                input(f"\n{Colors.CYAN}Press Enter to return to menu (honeypots continue running)...{Colors.END}")
            
            elif choice == '13':
                report_file = ReportGenerator.generate_html_report(dict(modules.results))
                print(f"{Colors.GREEN}[+] Report generated: {report_file}{Colors.END}")
                input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
            
            elif choice == '14':
                logger.display_logs()
                input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
            
            elif choice == '16':
                print(f"{Colors.RED}[!] Shutting down Flyconsole Advanced...{Colors.END}")
                loading_animation("Cleaning up", 1)
                print(f"{Colors.GREEN}Goodbye! Stay ethical.{Colors.END}")
                break
            
            else:
                print(f"{Colors.RED}[!] Module under development{Colors.END}")
                time.sleep(1)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Interrupt received{Colors.END}")
            break
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
            logger.add_log('System', 'Error', 'failed', str(e))
            time.sleep(2)

if __name__ == "__main__":
    main()
