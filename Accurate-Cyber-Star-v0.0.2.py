"""
ACCURATE ONLINE OS - COMPLETE CYBERSECURITY TOOL
Author: Ian Carter Kulani
Version: 1.0.0
Integrated Features: Network Monitoring, Traffic Generation, SSH Client, Telegram Bot
"""

import socket
import threading
import time
import requests
import json
import subprocess
import os
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Set, Tuple, Optional, Any
import sys
import random
import platform
import psutil
import getpass
import hashlib
import sqlite3
from pathlib import Path
import ipaddress
import re
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import paramiko
from io import StringIO

# Core security imports
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Note: python-nmap not available. Some scan features limited.")

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Note: scapy not available. Traffic generation features limited.")

# Configuration
CONFIG_FILE = "cyber_security_config.json"
DATABASE_FILE = "network_data.db"
REPORT_DIR = "reports"
SSH_CONFIG_FILE = "ssh_config.json"

class TracerouteTool:
    """Enhanced interactive traceroute tool"""
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if name.endswith('.'):
            name = name[:-1]
        HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
        return bool(HOSTNAME_RE.match(name))

    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        system = platform.system()

        if system == 'Windows':
            return ['tracert', '-d', target]

        if shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '1', '-w', '2', target]
        if shutil.which('tracepath'):
            return ['tracepath', target]
        if shutil.which('ping'):
            return ['ping', '-c', '4', target]

        raise EnvironmentError('No traceroute utilities found')

    @staticmethod
    def stream_subprocess(cmd: List[str]) -> Tuple[int, str]:
        """Run subprocess and capture output"""
        output_lines = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            if proc.stdout:
                for line in proc.stdout:
                    cleaned_line = line.rstrip()
                    output_lines.append(cleaned_line)
                    print(cleaned_line)

            proc.wait()
            return proc.returncode, '\n'.join(output_lines)
        except KeyboardInterrupt:
            print('\n[+] User cancelled traceroute...')
            try:
                proc.terminate()
            except Exception:
                pass
            return -1, '\n'.join(output_lines)
        except Exception as e:
            error_msg = f'[!] Error: {e}'
            print(error_msg)
            output_lines.append(error_msg)
            return -2, '\n'.join(output_lines)

    def interactive_traceroute(self, target: str = None) -> str:
        """Run interactive traceroute with validation"""
        if not target:
            target = self.prompt_target()
            if not target:
                return "Traceroute cancelled."

        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"

        try:
            cmd = self.choose_traceroute_cmd(target)
        except EnvironmentError as e:
            return f"❌ Traceroute error: {e}"

        print(f'Running: {" ".join(cmd)}\n')
        
        start_time = time.time()
        returncode, output = self.stream_subprocess(cmd)
        execution_time = time.time() - start_time

        result = f"🛣️ <b>Traceroute to {target}</b>\n\n"
        result += f"Command: <code>{' '.join(cmd)}</code>\n"
        result += f"Execution time: {execution_time:.2f}s\n"
        result += f"Return code: {returncode}\n\n"
        
        if len(output) > 3000:
            result += f"<code>{output[-3000:]}</code>"
        else:
            result += f"<code>{output}</code>"

        return result

class DatabaseManager:
    """Manage SQLite database for network data"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traceroute_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT,
                execution_time REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                traffic_type TEXT NOT NULL,
                target TEXT NOT NULL,
                packets_sent INTEGER,
                duration REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssh_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                username TEXT NOT NULL,
                port INTEGER DEFAULT 22,
                auth_type TEXT DEFAULT 'password',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                successful BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssh_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                command TEXT NOT NULL,
                output TEXT,
                execution_time REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True):
        """Log command to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)',
            (command, source, success)
        )
        conn.commit()
        conn.close()
    
    def log_ssh_session(self, host: str, username: str, port: int, auth_type: str, successful: bool):
        """Log SSH session to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO ssh_sessions (host, username, port, auth_type, successful) VALUES (?, ?, ?, ?, ?)',
            (host, username, port, auth_type, successful)
        )
        conn.commit()
        conn.close()
    
    def log_ssh_command(self, session_id: int, command: str, output: str, execution_time: float):
        """Log SSH command to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO ssh_commands (session_id, command, output, execution_time) VALUES (?, ?, ?, ?)',
            (session_id, command, output, execution_time)
        )
        conn.commit()
        conn.close()
    
    def get_ssh_history(self, limit: int = 20) -> List[Tuple]:
        """Get SSH session history"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT host, username, port, auth_type, timestamp, successful 
            FROM ssh_sessions 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_command_history(self, limit: int = 50) -> List[Tuple]:
        """Get command history from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT command, source, timestamp, success FROM command_history ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def log_threat(self, ip_address: str, threat_type: str, severity: str, description: str = ""):
        """Log threat detection to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO threat_logs (ip_address, threat_type, severity, description) VALUES (?, ?, ?, ?)',
            (ip_address, threat_type, severity, description)
        )
        conn.commit()
        conn.close()
    
    def get_recent_threats(self, limit: int = 20) -> List[Tuple]:
        """Get recent threats from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT ip_address, threat_type, severity, timestamp FROM threat_logs ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results

class SSHClientManager:
    """Manage SSH connections and operations"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.connections = {}
        self.current_session_id = None
        
    def connect_password(self, host: str, username: str, password: str, port: int = 22) -> Tuple[bool, str]:
        """Connect via SSH using password authentication"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            start_time = time.time()
            client.connect(hostname=host, username=username, password=password, port=port, timeout=10)
            connection_time = time.time() - start_time
            
            session_id = hash(f"{host}:{username}:{time.time()}")
            self.connections[session_id] = {
                'client': client,
                'host': host,
                'username': username,
                'port': port,
                'auth_type': 'password',
                'connected_at': datetime.now()
            }
            
            self.current_session_id = session_id
            self.db_manager.log_ssh_session(host, username, port, 'password', True)
            
            return True, f"✅ Connected to {host} as {username} in {connection_time:.2f}s"
            
        except paramiko.AuthenticationException:
            self.db_manager.log_ssh_session(host, username, port, 'password', False)
            return False, "❌ Authentication failed"
        except paramiko.SSHException as e:
            self.db_manager.log_ssh_session(host, username, port, 'password', False)
            return False, f"❌ SSH error: {str(e)}"
        except Exception as e:
            self.db_manager.log_ssh_session(host, username, port, 'password', False)
            return False, f"❌ Connection error: {str(e)}"
    
    def connect_key(self, host: str, username: str, key_path: str, port: int = 22, 
                   key_password: str = None) -> Tuple[bool, str]:
        """Connect via SSH using key authentication"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            key = paramiko.RSAKey.from_private_key_file(key_path, password=key_password)
            
            start_time = time.time()
            client.connect(hostname=host, username=username, pkey=key, port=port, timeout=10)
            connection_time = time.time() - start_time
            
            session_id = hash(f"{host}:{username}:{time.time()}")
            self.connections[session_id] = {
                'client': client,
                'host': host,
                'username': username,
                'port': port,
                'auth_type': 'key',
                'connected_at': datetime.now()
            }
            
            self.current_session_id = session_id
            self.db_manager.log_ssh_session(host, username, port, 'key', True)
            
            return True, f"✅ Connected to {host} as {username} using key in {connection_time:.2f}s"
            
        except paramiko.AuthenticationException:
            self.db_manager.log_ssh_session(host, username, port, 'key', False)
            return False, "❌ Key authentication failed"
        except Exception as e:
            self.db_manager.log_ssh_session(host, username, port, 'key', False)
            return False, f"❌ Connection error: {str(e)}"
    
    def execute_command(self, command: str, session_id: int = None) -> Tuple[bool, str]:
        """Execute command on SSH server"""
        if not session_id:
            session_id = self.current_session_id
        
        if session_id not in self.connections:
            return False, "❌ No active SSH session"
        
        try:
            client = self.connections[session_id]['client']
            start_time = time.time()
            
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            execution_time = time.time() - start_time
            
            result = output if output else error
            self.db_manager.log_ssh_command(session_id, command, result, execution_time)
            
            return True, f"⏱️ Execution time: {execution_time:.2f}s\n\n{result}"
            
        except Exception as e:
            return False, f"❌ Command execution error: {str(e)}"
    
    def list_directory(self, path: str = ".", session_id: int = None) -> Tuple[bool, str]:
        """List directory contents"""
        return self.execute_command(f"ls -la {path}", session_id)
    
    def get_system_info(self, session_id: int = None) -> Tuple[bool, str]:
        """Get remote system information"""
        commands = [
            "uname -a",
            "cat /etc/os-release",
            "df -h",
            "free -h",
            "uptime"
        ]
        
        results = []
        for cmd in commands:
            success, output = self.execute_command(cmd, session_id)
            if success:
                results.append(f"$ {cmd}\n{output}")
        
        if results:
            return True, "\n".join(results)
        return False, "❌ Failed to get system info"
    
    def upload_file(self, local_path: str, remote_path: str, session_id: int = None) -> Tuple[bool, str]:
        """Upload file to remote server"""
        if not session_id:
            session_id = self.current_session_id
        
        if session_id not in self.connections:
            return False, "❌ No active SSH session"
        
        try:
            if not os.path.exists(local_path):
                return False, f"❌ Local file not found: {local_path}"
            
            client = self.connections[session_id]['client']
            sftp = client.open_sftp()
            
            start_time = time.time()
            sftp.put(local_path, remote_path)
            upload_time = time.time() - start_time
            
            file_size = os.path.getsize(local_path)
            sftp.close()
            
            return True, f"✅ Uploaded {local_path} to {remote_path} ({file_size} bytes in {upload_time:.2f}s)"
            
        except Exception as e:
            return False, f"❌ Upload error: {str(e)}"
    
    def download_file(self, remote_path: str, local_path: str, session_id: int = None) -> Tuple[bool, str]:
        """Download file from remote server"""
        if not session_id:
            session_id = self.current_session_id
        
        if session_id not in self.connections:
            return False, "❌ No active SSH session"
        
        try:
            client = self.connections[session_id]['client']
            sftp = client.open_sftp()
            
            start_time = time.time()
            sftp.get(remote_path, local_path)
            download_time = time.time() - start_time
            
            file_size = os.path.getsize(local_path)
            sftp.close()
            
            return True, f"✅ Downloaded {remote_path} to {local_path} ({file_size} bytes in {download_time:.2f}s)"
            
        except Exception as e:
            return False, f"❌ Download error: {str(e)}"
    
    def disconnect(self, session_id: int = None) -> Tuple[bool, str]:
        """Disconnect SSH session"""
        if not session_id:
            session_id = self.current_session_id
        
        if session_id in self.connections:
            try:
                self.connections[session_id]['client'].close()
                host = self.connections[session_id]['host']
                del self.connections[session_id]
                
                if self.current_session_id == session_id:
                    self.current_session_id = None
                
                return True, f"✅ Disconnected from {host}"
            except Exception as e:
                return False, f"❌ Disconnect error: {str(e)}"
        
        return False, "❌ No active session to disconnect"
    
    def get_active_sessions(self) -> List[Dict]:
        """Get list of active SSH sessions"""
        sessions = []
        for session_id, info in self.connections.items():
            sessions.append({
                'id': session_id,
                'host': info['host'],
                'username': info['username'],
                'auth_type': info['auth_type'],
                'connected_at': info['connected_at']
            })
        return sessions

class NetworkScanner:
    """Network scanning capabilities"""
    
    def __init__(self):
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
        self.traceroute_tool = TracerouteTool()
    
    def ping_ip(self, ip: str) -> str:
        """Simple ping that works reliably"""
        try:
            if os.name == 'nt':
                cmd = ['ping', '-n', '4', ip]
            else:
                cmd = ['ping', '-c', '4', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Ping timeout for {ip}"
        except Exception as e:
            return f"Ping error: {str(e)}"
    
    def traceroute(self, target: str) -> str:
        """Perform enhanced traceroute"""
        return self.traceroute_tool.interactive_traceroute(target)
    
    def port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform port scan"""
        if self.nm:
            try:
                self.nm.scan(ip, ports, arguments='-T4')
                open_ports = []
                
                if ip in self.nm.all_hosts():
                    for proto in self.nm[ip].all_protocols():
                        lport = self.nm[ip][proto].keys()
                        for port in lport:
                            if self.nm[ip][proto][port]['state'] == 'open':
                                open_ports.append({
                                    'port': port,
                                    'state': self.nm[ip][proto][port]['state'],
                                    'service': self.nm[ip][proto][port].get('name', 'unknown')
                                })
                
                return {
                    'success': True,
                    'target': ip,
                    'open_ports': open_ports,
                    'scan_time': datetime.now().isoformat()
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': 'Nmap not available'}
    
    def get_ip_location(self, ip: str) -> str:
        """Get IP location using ip-api.com"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return json.dumps({
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }, indent=2)
                else:
                    return f"Location error: {data.get('message', 'Unknown error')}"
            else:
                return f"Location error: HTTP {response.status_code}"
        except Exception as e:
            return f"Location error: {str(e)}"

class NetworkTrafficGenerator:
    """Network traffic generation capabilities"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.running = False
        self.current_thread = None
    
    def generate_tcp_traffic(self, target_ip: str, port: int, packet_count: int, delay: float) -> str:
        """Generate TCP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for TCP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                packet = IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=port)
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            self.db_manager.log_traffic("TCP Flood", target_ip, packets_sent, duration)
            
            return f"✅ Sent {packets_sent} TCP packets to {target_ip}:{port} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ TCP traffic error: {str(e)}"
    
    def generate_udp_traffic(self, target_ip: str, port: int, packet_count: int, delay: float) -> str:
        """Generate UDP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for UDP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                payload = random._urandom(random.randint(64, 512))
                packet = IP(src=src_ip, dst=target_ip)/UDP(sport=random.randint(1024, 65535), dport=port)/payload
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            self.db_manager.log_traffic("UDP Flood", target_ip, packets_sent, duration)
            
            return f"✅ Sent {packets_sent} UDP packets to {target_ip}:{port} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ UDP traffic error: {str(e)}"
    
    def generate_icmp_traffic(self, target_ip: str, packet_count: int, delay: float) -> str:
        """Generate ICMP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for ICMP traffic generation"
        
        try:
            packets_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                packet = IP(dst=target_ip)/ICMP()
                send(packet, verbose=0)
                packets_sent += 1
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            self.db_manager.log_traffic("ICMP Flood", target_ip, packets_sent, duration)
            
            return f"✅ Sent {packets_sent} ICMP packets to {target_ip} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ ICMP traffic error: {str(e)}"
    
    def stop_traffic(self):
        """Stop all traffic generation"""
        self.running = False
        if self.current_thread and self.current_thread.is_alive():
            self.current_thread.join(timeout=2)

class TrafficGeneratorGUI:
    """GUI for network traffic generation"""
    
    def __init__(self, root, traffic_generator: NetworkTrafficGenerator):
        self.root = root
        self.traffic_generator = traffic_generator
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the GUI interface"""
        self.root.title("Accurate Cyber Defense - Traffic Generator")
        self.root.geometry("700x500")
        
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(main_frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_entry = ttk.Entry(main_frame, width=30)
        self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Label(main_frame, text="Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.port_entry = ttk.Entry(main_frame, width=10)
        self.port_entry.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        self.port_entry.insert(0, "80")
        
        ttk.Label(main_frame, text="Traffic Type:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.traffic_type = ttk.Combobox(main_frame, values=["TCP", "UDP", "ICMP"], width=15)
        self.traffic_type.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)
        self.traffic_type.current(0)
        
        ttk.Label(main_frame, text="Packet Count:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.packet_count = ttk.Entry(main_frame, width=10)
        self.packet_count.grid(row=3, column=1, sticky=tk.W, pady=5, padx=5)
        self.packet_count.insert(0, "100")
        
        ttk.Label(main_frame, text="Delay (ms):").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.delay_entry = ttk.Entry(main_frame, width=10)
        self.delay_entry.grid(row=4, column=1, sticky=tk.W, pady=5, padx=5)
        self.delay_entry.insert(0, "10")
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start Traffic", command=self.start_traffic)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Traffic", command=self.stop_traffic, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(main_frame, text="Output:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.output_text = scrolledtext.ScrolledText(main_frame, width=80, height=15)
        self.output_text.grid(row=8, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(8, weight=1)
    
    def log_output(self, message: str):
        """Add message to output console"""
        self.output_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
        self.output_text.see(tk.END)
        self.root.update()
    
    def start_traffic(self):
        """Start traffic generation"""
        target = self.target_entry.get().strip()
        traffic_type = self.traffic_type.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target IP/hostname")
            return
        
        try:
            packet_count = int(self.packet_count.get())
            delay = float(self.delay_entry.get()) / 1000
        except ValueError:
            messagebox.showerror("Error", "Invalid numeric values")
            return
        
        self.traffic_generator.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        self.log_output(f"Starting {traffic_type} traffic to {target}...")
        
        def traffic_thread():
            try:
                if traffic_type == "TCP":
                    port = int(self.port_entry.get())
                    result = self.traffic_generator.generate_tcp_traffic(target, port, packet_count, delay)
                elif traffic_type == "UDP":
                    port = int(self.port_entry.get())
                    result = self.traffic_generator.generate_udp_traffic(target, port, packet_count, delay)
                elif traffic_type == "ICMP":
                    result = self.traffic_generator.generate_icmp_traffic(target, packet_count, delay)
                else:
                    result = "❌ Unknown traffic type"
                
                self.log_output(result)
                
            except Exception as e:
                self.log_output(f"❌ Error: {str(e)}")
            finally:
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                self.traffic_generator.running = False
        
        thread = threading.Thread(target=traffic_thread, daemon=True)
        thread.start()
    
    def stop_traffic(self):
        """Stop traffic generation"""
        self.traffic_generator.stop_traffic()
        self.log_output("Stopping traffic generation...")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

class SSHClientGUI:
    """GUI for SSH client operations"""
    
    def __init__(self, root, ssh_manager: SSHClientManager):
        self.root = root
        self.ssh_manager = ssh_manager
        self.setup_gui()
    
    def setup_gui(self):
        """Setup SSH GUI"""
        self.root.title("Accurate Cyber Defense - SSH Client")
        self.root.geometry("800x600")
        
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Connection Tab
        self.connection_frame = ttk.Frame(notebook)
        notebook.add(self.connection_frame, text="Connect")
        self.setup_connection_tab()
        
        # Command Tab
        self.command_frame = ttk.Frame(notebook)
        notebook.add(self.command_frame, text="Commands")
        self.setup_command_tab()
        
        # File Transfer Tab
        self.file_frame = ttk.Frame(notebook)
        notebook.add(self.file_frame, text="File Transfer")
        self.setup_file_transfer_tab()
        
        # Sessions Tab
        self.sessions_frame = ttk.Frame(notebook)
        notebook.add(self.sessions_frame, text="Sessions")
        self.setup_sessions_tab()
        
        self.update_sessions_list()
    
    def setup_connection_tab(self):
        """Setup connection tab"""
        frame = ttk.LabelFrame(self.connection_frame, text="SSH Connection", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Host configuration
        ttk.Label(frame, text="Host:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.host_entry = ttk.Entry(frame, width=30)
        self.host_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Label(frame, text="Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.port_entry = ttk.Entry(frame, width=10)
        self.port_entry.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        self.port_entry.insert(0, "22")
        
        ttk.Label(frame, text="Username:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(frame, width=30)
        self.username_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        # Authentication method
        ttk.Label(frame, text="Authentication:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.auth_method = ttk.Combobox(frame, values=["Password", "SSH Key"], width=15, state="readonly")
        self.auth_method.grid(row=3, column=1, sticky=tk.W, pady=5, padx=5)
        self.auth_method.current(0)
        self.auth_method.bind("<<ComboboxSelected>>", self.on_auth_method_change)
        
        # Password fields
        self.password_frame = ttk.Frame(frame)
        self.password_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(self.password_frame, text="Password:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(self.password_frame, width=30, show="*")
        self.password_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        # Key fields (initially hidden)
        self.key_frame = ttk.Frame(frame)
        
        ttk.Label(self.key_frame, text="Key Path:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.key_path_entry = ttk.Entry(self.key_frame, width=25)
        self.key_path_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        self.browse_key_btn = ttk.Button(self.key_frame, text="Browse", command=self.browse_key_file, width=10)
        self.browse_key_btn.grid(row=0, column=2, padx=5)
        
        ttk.Label(self.key_frame, text="Key Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.key_password_entry = ttk.Entry(self.key_frame, width=30, show="*")
        self.key_password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        self.connect_btn = ttk.Button(button_frame, text="Connect", command=self.connect_ssh, width=15)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = ttk.Button(button_frame, text="Disconnect", command=self.disconnect_ssh, width=15, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)
        
        # Connection status
        self.status_label = ttk.Label(frame, text="Not connected", foreground="red")
        self.status_label.grid(row=6, column=0, columnspan=2, pady=10)
        
        frame.columnconfigure(1, weight=1)
    
    def setup_command_tab(self):
        """Setup command execution tab"""
        frame = ttk.LabelFrame(self.command_frame, text="Command Execution", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Command input
        ttk.Label(frame, text="Command:").pack(anchor=tk.W, pady=5)
        self.command_entry = ttk.Entry(frame)
        self.command_entry.pack(fill=tk.X, pady=5)
        self.command_entry.bind("<Return>", lambda e: self.execute_ssh_command())
        
        # Quick commands
        quick_frame = ttk.Frame(frame)
        quick_frame.pack(fill=tk.X, pady=10)
        
        quick_commands = [
            ("System Info", "uname -a && df -h && free -h"),
            ("List Directory", "ls -la"),
            ("Network Info", "ifconfig || ip addr"),
            ("Processes", "ps aux | head -20"),
            ("Services", "systemctl list-units --type=service | head -20")
        ]
        
        for i, (name, cmd) in enumerate(quick_commands):
            btn = ttk.Button(quick_frame, text=name, width=15,
                           command=lambda c=cmd: self.command_entry.insert(0, c))
            btn.grid(row=i//3, column=i%3, padx=5, pady=5)
        
        # Execute button
        self.execute_btn = ttk.Button(frame, text="Execute", command=self.execute_ssh_command, state=tk.DISABLED)
        self.execute_btn.pack(pady=10)
        
        # Output area
        ttk.Label(frame, text="Output:").pack(anchor=tk.W, pady=5)
        self.output_text = scrolledtext.ScrolledText(frame, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def setup_file_transfer_tab(self):
        """Setup file transfer tab"""
        frame = ttk.LabelFrame(self.file_frame, text="File Transfer", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Upload section
        upload_frame = ttk.LabelFrame(frame, text="Upload to Remote", padding="10")
        upload_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(upload_frame, text="Local File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.local_file_entry = ttk.Entry(upload_frame, width=40)
        self.local_file_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        self.browse_local_btn = ttk.Button(upload_frame, text="Browse", command=self.browse_local_file, width=10)
        self.browse_local_btn.grid(row=0, column=2, padx=5)
        
        ttk.Label(upload_frame, text="Remote Path:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.remote_upload_entry = ttk.Entry(upload_frame, width=40)
        self.remote_upload_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        self.upload_btn = ttk.Button(upload_frame, text="Upload", command=self.upload_file, state=tk.DISABLED)
        self.upload_btn.grid(row=1, column=2, padx=5)
        
        # Download section
        download_frame = ttk.LabelFrame(frame, text="Download from Remote", padding="10")
        download_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(download_frame, text="Remote File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.remote_file_entry = ttk.Entry(download_frame, width=40)
        self.remote_file_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Label(download_frame, text="Local Path:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.local_download_entry = ttk.Entry(download_frame, width=40)
        self.local_download_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        self.browse_download_btn = ttk.Button(download_frame, text="Browse", command=self.browse_download_path, width=10)
        self.browse_download_btn.grid(row=1, column=2, padx=5)
        
        self.download_btn = ttk.Button(download_frame, text="Download", command=self.download_file, state=tk.DISABLED)
        self.download_btn.grid(row=2, column=1, pady=10)
        
        upload_frame.columnconfigure(1, weight=1)
        download_frame.columnconfigure(1, weight=1)
    
    def setup_sessions_tab(self):
        """Setup sessions management tab"""
        frame = ttk.LabelFrame(self.sessions_frame, text="Active Sessions", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Sessions list
        columns = ("ID", "Host", "Username", "Auth Type", "Connected")
        self.sessions_tree = ttk.Treeview(frame, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.sessions_tree.heading(col, text=col)
            self.sessions_tree.column(col, width=100)
        
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.sessions_tree.yview)
        self.sessions_tree.configure(yscrollcommand=scrollbar.set)
        
        self.sessions_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        self.refresh_btn = ttk.Button(button_frame, text="Refresh", command=self.update_sessions_list)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        self.switch_btn = ttk.Button(button_frame, text="Switch Session", command=self.switch_session, state=tk.DISABLED)
        self.switch_btn.pack(side=tk.LEFT, padx=5)
        
        self.close_btn = ttk.Button(button_frame, text="Close Session", command=self.close_session, state=tk.DISABLED)
        self.close_btn.pack(side=tk.LEFT, padx=5)
        
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        
        self.sessions_tree.bind("<<TreeviewSelect>>", self.on_session_select)
    
    def on_auth_method_change(self, event):
        """Handle authentication method change"""
        method = self.auth_method.get()
        if method == "Password":
            self.password_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
            self.key_frame.grid_forget()
        else:
            self.password_frame.grid_forget()
            self.key_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
    
    def browse_key_file(self):
        """Browse for SSH key file"""
        filename = filedialog.askopenfilename(
            title="Select SSH Private Key",
            filetypes=[("SSH Keys", "*.pem"), ("All files", "*.*")]
        )
        if filename:
            self.key_path_entry.delete(0, tk.END)
            self.key_path_entry.insert(0, filename)
    
    def browse_local_file(self):
        """Browse for local file to upload"""
        filename = filedialog.askopenfilename(title="Select File to Upload")
        if filename:
            self.local_file_entry.delete(0, tk.END)
            self.local_file_entry.insert(0, filename)
            
            # Suggest remote path
            basename = os.path.basename(filename)
            self.remote_upload_entry.delete(0, tk.END)
            self.remote_upload_entry.insert(0, f"./{basename}")
    
    def browse_download_path(self):
        """Browse for download location"""
        filename = filedialog.asksaveasfilename(title="Save File As")
        if filename:
            self.local_download_entry.delete(0, tk.END)
            self.local_download_entry.insert(0, filename)
    
    def connect_ssh(self):
        """Connect via SSH"""
        host = self.host_entry.get().strip()
        port = self.port_entry.get().strip()
        username = self.username_entry.get().strip()
        auth_method = self.auth_method.get()
        
        if not all([host, username]):
            messagebox.showerror("Error", "Please fill all required fields")
            return
        
        try:
            port = int(port) if port else 22
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
            return
        
        if auth_method == "Password":
            password = self.password_entry.get()
            if not password:
                messagebox.showerror("Error", "Please enter password")
                return
            
            success, message = self.ssh_manager.connect_password(host, username, password, port)
        else:
            key_path = self.key_path_entry.get().strip()
            if not key_path or not os.path.exists(key_path):
                messagebox.showerror("Error", "Please select a valid key file")
                return
            
            key_password = self.key_password_entry.get() or None
            success, message = self.ssh_manager.connect_key(host, username, key_path, port, key_password)
        
        if success:
            self.status_label.config(text=f"Connected to {host}", foreground="green")
            self.connect_btn.config(state=tk.DISABLED)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.execute_btn.config(state=tk.NORMAL)
            self.upload_btn.config(state=tk.NORMAL)
            self.download_btn.config(state=tk.NORMAL)
            self.log_output(f"SSH: {message}")
        else:
            self.status_label.config(text="Connection failed", foreground="red")
            self.log_output(f"SSH Error: {message}")
        
        self.update_sessions_list()
    
    def disconnect_ssh(self):
        """Disconnect SSH"""
        success, message = self.ssh_manager.disconnect()
        if success:
            self.status_label.config(text="Not connected", foreground="red")
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
            self.execute_btn.config(state=tk.DISABLED)
            self.upload_btn.config(state=tk.DISABLED)
            self.download_btn.config(state=tk.DISABLED)
        
        self.log_output(f"SSH: {message}")
        self.update_sessions_list()
    
    def execute_ssh_command(self):
        """Execute SSH command"""
        command = self.command_entry.get().strip()
        if not command:
            return
        
        self.log_output(f"$ {command}")
        success, output = self.ssh_manager.execute_command(command)
        
        if success:
            self.log_output(output)
        else:
            self.log_output(f"Error: {output}")
        
        self.command_entry.delete(0, tk.END)
    
    def upload_file(self):
        """Upload file to remote server"""
        local_path = self.local_file_entry.get().strip()
        remote_path = self.remote_upload_entry.get().strip()
        
        if not all([local_path, remote_path]):
            messagebox.showerror("Error", "Please specify both local and remote paths")
            return
        
        self.log_output(f"Uploading {local_path} to {remote_path}...")
        success, message = self.ssh_manager.upload_file(local_path, remote_path)
        self.log_output(message)
    
    def download_file(self):
        """Download file from remote server"""
        remote_path = self.remote_file_entry.get().strip()
        local_path = self.local_download_entry.get().strip()
        
        if not all([remote_path, local_path]):
            messagebox.showerror("Error", "Please specify both remote and local paths")
            return
        
        self.log_output(f"Downloading {remote_path} to {local_path}...")
        success, message = self.ssh_manager.download_file(remote_path, local_path)
        self.log_output(message)
    
    def update_sessions_list(self):
        """Update sessions list in treeview"""
        for item in self.sessions_tree.get_children():
            self.sessions_tree.delete(item)
        
        sessions = self.ssh_manager.get_active_sessions()
        for session in sessions:
            self.sessions_tree.insert("", tk.END, values=(
                str(session['id'])[:8],
                session['host'],
                session['username'],
                session['auth_type'],
                session['connected_at'].strftime("%H:%M:%S")
            ))
    
    def on_session_select(self, event):
        """Handle session selection"""
        selection = self.sessions_tree.selection()
        if selection:
            self.switch_btn.config(state=tk.NORMAL)
            self.close_btn.config(state=tk.NORMAL)
        else:
            self.switch_btn.config(state=tk.DISABLED)
            self.close_btn.config(state=tk.DISABLED)
    
    def switch_session(self):
        """Switch active session"""
        selection = self.sessions_tree.selection()
        if not selection:
            return
        
        item = self.sessions_tree.item(selection[0])
        session_id_str = item['values'][0]
        
        # Find session by ID (partial match)
        sessions = self.ssh_manager.get_active_sessions()
        for session in sessions:
            if str(session['id']).startswith(session_id_str):
                self.ssh_manager.current_session_id = session['id']
                self.log_output(f"Switched to session: {session['host']} ({session['username']})")
                break
    
    def close_session(self):
        """Close selected session"""
        selection = self.sessions_tree.selection()
        if not selection:
            return
        
        item = self.sessions_tree.item(selection[0])
        session_id_str = item['values'][0]
        
        # Find and close session
        sessions = self.ssh_manager.get_active_sessions()
        for session in sessions:
            if str(session['id']).startswith(session_id_str):
                self.ssh_manager.disconnect(session['id'])
                self.log_output(f"Closed session: {session['host']}")
                break
        
        self.update_sessions_list()
    
    def log_output(self, message: str):
        """Add message to output console"""
        self.output_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
        self.output_text.see(tk.END)
        self.root.update()

class TelegramBotHandler:
    """Enhanced Telegram bot handler"""
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.last_update_id = 0
        self.command_handlers = self.setup_command_handlers()
    
    def setup_command_handlers(self) -> Dict[str, callable]:
        """Setup comprehensive command handlers"""
        handlers = {
            '/start': self.handle_start,
            '/help': self.handle_help,
            '/ping_ip': self.handle_ping_ip,
            '/start_monitoring_ip': self.handle_start_monitoring_ip,
            '/stop': self.handle_stop,
            '/history': self.handle_history,
            '/add_ip': self.handle_add_ip,
            '/remove_ip': self.handle_remove_ip,
            '/list_ips': self.handle_list_ips,
            '/clear': self.handle_clear,
            '/tracert_ip': self.handle_tracert_ip,
            '/traceroute_ip': self.handle_traceroute_ip,
            '/scan_ip': self.handle_scan_ip,
            '/location_ip': self.handle_location_ip,
            '/analyze_ip': self.handle_analyze_ip,
            '/status': self.handle_status,
            '/curl': self.handle_curl,
            '/whois': self.handle_whois,
            '/dns_lookup': self.handle_dns_lookup,
            '/network_info': self.handle_network_info,
            '/system_info': self.handle_system_info,
            '/threat_summary': self.handle_threat_summary,
            '/generate_report': self.handle_generate_report,
            '/advanced_traceroute': self.handle_advanced_traceroute,
            '/generate_traffic': self.handle_generate_traffic,
            '/stop_traffic': self.handle_stop_traffic,
            '/ssh_connect': self.handle_ssh_connect,
            '/ssh_command': self.handle_ssh_command,
            '/ssh_disconnect': self.handle_ssh_disconnect,
            '/ssh_sessions': self.handle_ssh_sessions
        }
        return handlers
    
    def send_telegram_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send message to Telegram"""
        if not self.monitor.telegram_token or not self.monitor.telegram_chat_id:
            return False
            
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/sendMessage"
            
            if len(message) > 4096:
                messages = [message[i:i+4096] for i in range(0, len(message), 4096)]
                for msg in messages:
                    payload = {
                        'chat_id': self.monitor.telegram_chat_id,
                        'text': msg,
                        'parse_mode': parse_mode,
                        'disable_web_page_preview': True
                    }
                    response = requests.post(url, json=payload, timeout=30)
                    if response.status_code != 200:
                        return False
                    time.sleep(0.5)
                return True
            else:
                payload = {
                    'chat_id': self.monitor.telegram_chat_id,
                    'text': message,
                    'parse_mode': parse_mode,
                    'disable_web_page_preview': True
                }
                response = requests.post(url, json=payload, timeout=30)
                return response.status_code == 200
        except Exception as e:
            logging.error(f"Telegram send error: {e}")
            return False
    
    def handle_start(self, args: List[str]) -> str:
        """Handle /start command"""
        return """
🚀 <b>Accurate Online OS - Complete Cybersecurity Tool</b> 🚀

Welcome! Your advanced cybersecurity assistant is ready.

🔍 <b>Network Diagnostics:</b>
/ping_ip [IP] - Ping IP address
/tracert_ip [IP] - Traceroute
/advanced_traceroute [IP] - Enhanced traceroute
/scan_ip [IP] - Port scan
/location_ip [IP] - Get IP location
/analyze_ip [IP] - Analyze IP threats
/whois [domain] - WHOIS lookup
/dns_lookup [domain] - DNS lookup

🔐 <b>SSH Operations:</b>
/ssh_connect host user pass - SSH connect (password)
/ssh_command [cmd] - Execute SSH command
/ssh_disconnect - Disconnect SSH
/ssh_sessions - List SSH sessions

🌐 <b>Traffic Generation:</b>
/generate_traffic [type] [target] - Generate network traffic
/stop_traffic - Stop all traffic

📊 <b>Monitoring:</b>
/start_monitoring_ip [IP] - Start monitoring
/stop - Stop all monitoring
/add_ip [IP] - Add IP to list
/remove_ip [IP] - Remove IP
/list_ips - List monitored IPs
/threat_summary - Recent threats

💻 <b>System:</b>
/network_info - Network information
/system_info - System information
/status - System status
/history - Command history
/clear - Clear history

📡 <b>Web Tools:</b>
/curl [URL] - HTTP request
/generate_report - Generate security report

❓ Type /help for detailed usage!
        """
    
    def handle_help(self, args: List[str]) -> str:
        """Show help"""
        return """
<b>🔒 Complete Command Reference</b>

<b>🌐 Network Diagnostics:</b>
<code>/ping_ip 8.8.8.8</code>
<code>/tracert_ip google.com</code>
<code>/advanced_traceroute 1.1.1.1</code>
<code>/scan_ip 192.168.1.1</code>
<code>/location_ip 1.1.1.1</code>
<code>/whois example.com</code>
<code>/dns_lookup example.com</code>

<b>🔐 SSH Operations:</b>
<code>/ssh_connect 192.168.1.100 admin password123</code>
<code>/ssh_command ls -la</code>
<code>/ssh_disconnect</code>
<code>/ssh_sessions</code>

<b>🌐 Traffic Generation:</b>
<code>/generate_traffic tcp 192.168.1.1:80</code>
<code>/generate_traffic udp 10.0.0.1:53</code>
<code>/generate_traffic icmp 8.8.8.8</code>
<code>/stop_traffic</code>

<b>🛡️ Security Analysis:</b>
<code>/analyze_ip 192.168.1.1</code>
<code>/threat_summary</code>
<code>/generate_report</code>

<b>📊 Monitoring:</b>
<code>/start_monitoring_ip 192.168.1.1</code>
<code>/add_ip 10.0.0.1</code>
<code>/remove_ip 10.0.0.1</code>
<code>/list_ips</code>
<code>/stop</code>

<b>💻 System Info:</b>
<code>/network_info</code>
<code>/system_info</code>
<code>/status</code>

<b>🌍 Web Tools:</b>
<code>/curl https://api.github.com</code>
        """
    
    def handle_ssh_connect(self, args: List[str]) -> str:
        """Handle SSH connection"""
        if len(args) < 3:
            return "❌ Usage: <code>/ssh_connect [host] [username] [password]</code>"
        
        host = args[0]
        username = args[1]
        password = args[2]
        port = 22
        
        if len(args) > 3:
            try:
                port = int(args[3])
            except ValueError:
                return "❌ Invalid port number"
        
        success, message = self.monitor.ssh_manager.connect_password(host, username, password, port)
        return message
    
    def handle_ssh_command(self, args: List[str]) -> str:
        """Handle SSH command execution"""
        if not args:
            return "❌ Usage: <code>/ssh_command [command]</code>"
        
        command = " ".join(args)
        success, output = self.monitor.ssh_manager.execute_command(command)
        return output
    
    def handle_ssh_disconnect(self, args: List[str]) -> str:
        """Handle SSH disconnect"""
        success, message = self.monitor.ssh_manager.disconnect()
        return message
    
    def handle_ssh_sessions(self, args: List[str]) -> str:
        """List SSH sessions"""
        sessions = self.monitor.ssh_manager.get_active_sessions()
        if not sessions:
            return "📋 No active SSH sessions"
        
        response = "🔐 <b>Active SSH Sessions</b>\n\n"
        for session in sessions:
            response += f"• {session['host']} ({session['username']})\n"
            response += f"  Auth: {session['auth_type']}\n"
            response += f"  Connected: {session['connected_at'].strftime('%H:%M:%S')}\n\n"
        
        return response
    
    def handle_generate_traffic(self, args: List[str]) -> str:
        """Handle traffic generation"""
        if not args:
            return "❌ Usage: <code>/generate_traffic [tcp|udp|icmp] [target]</code>"
        
        traffic_type = args[0].lower()
        target = args[1] if len(args) > 1 else ""
        
        if not target:
            return f"❌ Please specify target for {traffic_type} traffic"
        
        port = None
        if ":" in target and traffic_type in ["tcp", "udp"]:
            target, port_str = target.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                return f"❌ Invalid port: {port_str}"
        
        self.send_telegram_message(f"🌐 Starting {traffic_type.upper()} traffic to {target}...")
        
        def generate():
            try:
                if traffic_type == "tcp" and port:
                    result = self.monitor.traffic_generator.generate_tcp_traffic(target, port, 100, 0.01)
                elif traffic_type == "udp" and port:
                    result = self.monitor.traffic_generator.generate_udp_traffic(target, port, 100, 0.01)
                elif traffic_type == "icmp":
                    result = self.monitor.traffic_generator.generate_icmp_traffic(target, 50, 0.1)
                else:
                    result = f"❌ Invalid traffic type or missing port: {traffic_type}"
                
                self.send_telegram_message(result)
            except Exception as e:
                self.send_telegram_message(f"❌ Traffic error: {str(e)}")
        
        thread = threading.Thread(target=generate, daemon=True)
        thread.start()
        
        return f"🔄 Starting {traffic_type.upper()} traffic generation..."
    
    def handle_stop_traffic(self, args: List[str]) -> str:
        """Stop traffic generation"""
        self.monitor.traffic_generator.stop_traffic()
        return "🛑 All traffic generation stopped"
    
    # Other handler methods (same as before, shortened for brevity)
    def handle_ping_ip(self, args: List[str]) -> str:
        if not args: return "❌ Usage: <code>/ping_ip [IP]</code>"
        result = self.monitor.scanner.ping_ip(args[0])
        return f"🏓 <b>Ping {args[0]}</b>\n\n<code>{result[-1000:]}</code>"
    
    def handle_start_monitoring_ip(self, args: List[str]) -> str:
        if not args: return "❌ Usage: <code>/start_monitoring_ip [IP]</code>"
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            self.monitor.monitored_ips.add(ip)
            self.monitor.save_config()
            return f"✅ Started monitoring <code>{ip}</code>"
        except ValueError: return f"❌ Invalid IP: <code>{ip}</code>"
    
    def handle_stop(self, args: List[str]) -> str:
        if not self.monitor.monitored_ips: return "⚠️ No IPs being monitored"
        ips = list(self.monitor.monitored_ips)
        self.monitor.monitored_ips.clear()
        self.monitor.save_config()
        return f"🛑 Stopped monitoring: {', '.join(ips)}"
    
    def handle_history(self, args: List[str]) -> str:
        history = self.monitor.db_manager.get_command_history(20)
        if not history: return "📝 No commands recorded"
        response = "📝 <b>Command History</b>\n\n"
        for i, (cmd, src, ts, success) in enumerate(history, 1):
            status = "✅" if success else "❌"
            response += f"{i}. {status} <code>{cmd}</code>\n   {src} | {ts}\n\n"
        return response
    
    def handle_add_ip(self, args: List[str]) -> str:
        if not args: return "❌ Usage: <code>/add_ip [IP]</code>"
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            self.monitor.monitored_ips.add(ip)
            self.monitor.save_config()
            return f"✅ Added <code>{ip}</code>"
        except ValueError: return f"❌ Invalid IP: <code>{ip}</code>"
    
    def handle_remove_ip(self, args: List[str]) -> str:
        if not args: return "❌ Usage: <code>/remove_ip [IP]</code>"
        ip = args[0]
        if ip in self.monitor.monitored_ips:
            self.monitor.monitored_ips.remove(ip)
            self.monitor.save_config()
            return f"✅ Removed <code>{ip}</code>"
        return f"❌ IP not in list: <code>{ip}</code>"
    
    def handle_list_ips(self, args: List[str]) -> str:
        if not self.monitor.monitored_ips: return "📋 No IPs being monitored"
        response = "📋 <b>Monitored IPs</b>\n\n"
        for ip in sorted(self.monitor.monitored_ips): response += f"• <code>{ip}</code>\n"
        return response
    
    def handle_clear(self, args: List[str]) -> str:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM command_history')
        conn.commit()
        conn.close()
        return "✅ Command history cleared"
    
    def handle_tracert_ip(self, args: List[str]) -> str:
        if not args: return "❌ Usage: <code>/tracert_ip [IP/domain]</code>"
        return self.monitor.scanner.traceroute(args[0])
    
    def handle_traceroute_ip(self, args: List[str]) -> str: return self.handle_tracert_ip(args)
    def handle_advanced_traceroute(self, args: List[str]) -> str: return self.handle_tracert_ip(args)
    
    def handle_scan_ip(self, args: List[str]) -> str:
        if not args: return "❌ Usage: <code>/scan_ip [IP]</code>"
        ip = args[0]
        self.send_telegram_message(f"🔍 Scanning <code>{ip}</code>...")
        result = self.monitor.scanner.port_scan(ip)
        if result['success']:
            open_ports = result.get('open_ports', [])
            response = f"🔍 <b>Scan Results: {ip}</b>\n\nOpen Ports: {len(open_ports)}\n\n"
            if open_ports:
                for p in open_ports[:10]: response += f"• Port {p['port']}: {p['service']}\n"
                if len(open_ports) > 10: response += f"\n... and {len(open_ports)-10} more"
            else: response += "🔒 No open ports found"
            return response
        return f"❌ Scan error: {result.get('error', 'Unknown')}"
    
    def handle_location_ip(self, args: List[str]) -> str:
        if not args: return "❌ Usage: <code>/location_ip [IP]</code>"
        result = self.monitor.scanner.get_ip_location(args[0])
        return f"🌍 <b>Location: {args[0]}</b>\n\n<code>{result}</code>"
    
    def handle_analyze_ip(self, args: List[str]) -> str:
        if not args: return "❌ Usage: <code>/analyze_ip [IP]</code>"
        ip = args[0]
        response = f"🔍 <b>Analysis: {ip}</b>\n\n"
        location = self.monitor.scanner.get_ip_location(ip)
        try:
            loc_data = json.loads(location)
            response += f"📍 Location: {loc_data.get('city', 'N/A')}, {loc_data.get('country', 'N/A')}\n"
            response += f"🏢 ISP: {loc_data.get('isp', 'N/A')}\n\n"
        except: pass
        threats = self.monitor.db_manager.get_recent_threats(5)
        ip_threats = [t for t in threats if t[0] == ip]
        if ip_threats:
            response += f"🚨 <b>Threats Found: {len(ip_threats)}</b>\n"
            for threat in ip_threats: response += f"• {threat[1]}: {threat[2]}\n"
        else: response += "✅ No recent threats detected"
        return response
    
    def handle_status(self, args: List[str]) -> str:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        response = "📊 <b>System Status</b>\n\n"
        response += f"✅ Bot: Online\n🔍 Monitored IPs: {len(self.monitor.monitored_ips)}\n"
        response += f"💻 CPU: {cpu}%\n🧠 Memory: {mem.percent}%\n"
        response += f"🌐 Connections: {len(psutil.net_connections())}\n"
        ssh_sessions = len(self.monitor.ssh_manager.get_active_sessions())
        response += f"🔐 SSH Sessions: {ssh_sessions}\n"
        return response
    
    def handle_curl(self, args: List[str]) -> str:
        if not args: return "❌ Usage: <code>/curl [URL]</code>"
        url = args[-1]
        try:
            response = requests.get(url, timeout=10)
            result = f"📡 <b>CURL Response</b>\n\nStatus: {response.status_code}\nSize: {len(response.content)} bytes\n\n"
            preview = response.text[:500]
            result += f"<code>{preview}</code>"
            if len(response.text) > 500: result += "..."
            return result
        except Exception as e: return f"❌ Error: {str(e)}"
    
    def handle_whois(self, args: List[str]) -> str:
        if not args: return "❌ Usage: <code>/whois [domain]</code>"
        domain = args[0]
        try:
            result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
            output = result.stdout[:1000]
            return f"🔍 <b>WHOIS: {domain}</b>\n\n<code>{output}</code>"
        except: return "❌ WHOIS lookup failed"
    
    def handle_dns_lookup(self, args: List[str]) -> str:
        if not args: return "❌ Usage: <code>/dns_lookup [domain]</code>"
        domain = args[0]
        try:
            ip = socket.gethostbyname(domain)
            return f"🌐 <b>DNS Lookup</b>\n\n{domain} → <code>{ip}</code>"
        except Exception as e: return f"❌ DNS lookup failed: {str(e)}"
    
    def handle_network_info(self, args: List[str]) -> str:
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            addrs = psutil.net_if_addrs()
            response = "🌐 <b>Network Information</b>\n\n"
            response += f"Hostname: <code>{hostname}</code>\nLocal IP: <code>{local_ip}</code>\n\n"
            response += f"<b>Network Interfaces:</b>\n"
            for iface, addresses in list(addrs.items())[:5]:
                response += f"\n{iface}:\n"
                for addr in addresses[:2]: response += f"  {addr.address}\n"
            return response
        except Exception as e: return f"❌ Error: {str(e)}"
    
    def handle_system_info(self, args: List[str]) -> str:
        response = "💻 <b>System Information</b>\n\n"
        response += f"OS: {platform.system()} {platform.release()}\n"
        response += f"CPU Cores: {psutil.cpu_count()}\nCPU Usage: {psutil.cpu_percent()}%\n"
        response += f"Memory: {psutil.virtual_memory().percent}%\nDisk: {psutil.disk_usage('/').percent}%\n"
        response += f"Boot Time: {datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M')}\n"
        return response
    
    def handle_threat_summary(self, args: List[str]) -> str:
        threats = self.monitor.db_manager.get_recent_threats(10)
        if not threats: return "✅ No recent threats detected"
        response = "🚨 <b>Recent Threats</b>\n\n"
        for ip, ttype, severity, ts in threats:
            response += f"• <code>{ip}</code>\n  Type: {ttype} | Severity: {severity}\n  Time: {ts}\n\n"
        return response
    
    def handle_generate_report(self, args: List[str]) -> str:
        threats = self.monitor.db_manager.get_recent_threats(50)
        history = self.monitor.db_manager.get_command_history(100)
        ssh_history = self.monitor.db_manager.get_ssh_history(20)
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'monitored_ips': len(self.monitor.monitored_ips),
            'total_threats': len(threats),
            'high_severity': len([t for t in threats if t[2] == 'high']),
            'medium_severity': len([t for t in threats if t[2] == 'medium']),
            'low_severity': len([t for t in threats if t[2] == 'low']),
            'commands_executed': len(history),
            'ssh_sessions': len(ssh_history),
            'active_ssh_sessions': len(self.monitor.ssh_manager.get_active_sessions())
        }
        
        filename = f"report_{int(time.time())}.json"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        with open(filepath, 'w') as f: json.dump(report, f, indent=2)
        
        response = "📊 <b>Security Report</b>\n\n"
        response += f"Monitored IPs: {report['monitored_ips']}\n"
        response += f"Total Threats: {report['total_threats']}\n"
        response += f"High Severity: {report['high_severity']}\n"
        response += f"Medium Severity: {report['medium_severity']}\n"
        response += f"Low Severity: {report['low_severity']}\n"
        response += f"Commands Executed: {report['commands_executed']}\n"
        response += f"SSH Sessions: {report['ssh_sessions']}\n"
        response += f"Active SSH Sessions: {report['active_ssh_sessions']}\n\n"
        response += f"✅ Report saved: <code>{filename}</code>"
        return response
    
    def process_telegram_commands(self):
        """Process incoming Telegram commands"""
        if not self.monitor.telegram_token: return
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/getUpdates"
            params = {'offset': self.last_update_id + 1, 'timeout': 10}
            response = requests.get(url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if data['ok'] and 'result' in data:
                    for update in data['result']:
                        self.last_update_id = update['update_id']
                        if 'message' in update and 'text' in update['message']:
                            self.process_message(update['message'])
        except Exception as e: logging.error(f"Telegram error: {e}")
    
    def process_message(self, message):
        """Process individual message"""
        text = message['text']
        chat_id = message['chat']['id']
        
        if not self.monitor.telegram_chat_id:
            self.monitor.telegram_chat_id = str(chat_id)
            self.monitor.save_config()
        
        self.monitor.db_manager.log_command(text, 'telegram', True)
        parts = text.split()
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        if command in self.command_handlers:
            try:
                def execute():
                    response = self.command_handlers[command](args)
                    self.send_telegram_message(response)
                thread = threading.Thread(target=execute, daemon=True)
                thread.start()
            except Exception as e:
                self.send_telegram_message(f"❌ Error: {str(e)}")
        else:
            self.send_telegram_message("❌ Unknown command. Type /help")

class CybersecurityMonitor:
    """Main monitor class"""
    
    def __init__(self):
        self.monitored_ips = set()
        self.monitoring_active = False
        self.telegram_token = None
        self.telegram_chat_id = None
        self.db_manager = DatabaseManager()
        self.scanner = NetworkScanner()
        self.traceroute_tool = TracerouteTool()
        self.traffic_generator = NetworkTrafficGenerator(self.db_manager)
        self.ssh_manager = SSHClientManager(self.db_manager)
        self.setup_logging()
        self.load_config()
    
    def setup_logging(self):
        """Setup logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cybersecurity.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def load_config(self):
        """Load configuration"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.telegram_token = config.get('telegram_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
                    self.monitored_ips = set(config.get('monitored_ips', []))
        except Exception as e:
            logging.error(f"Config load error: {e}")
    
    def save_config(self):
        """Save configuration"""
        try:
            config = {
                'telegram_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id,
                'monitored_ips': list(self.monitored_ips)
            }
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logging.error(f"Config save error: {e}")

def print_banner():
    """Print banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║         🛡️  ACCURATE CYBER STAR               🛡️                ║
    ║                                                                  ║
    ║      Network Monitoring • SSH Client • Traffic Generation        ║
    ║         Security Analysis • Threat Detection • Reporting         ║
    ║                                                                  ║
    ║   Community: https://github.com/Accurate-Cyber-Defense           ║
    ║              Telegram Bot: ACTIVE                                ║
    ║              Database: Ready                                     ║
    ║              SSH Client: Ready                                   ║
    ║              Traffic Generator: Ready                            ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def setup_telegram():
    """Setup Telegram configuration"""
    print("\n🔧 Telegram Bot Setup")
    print("=" * 50)
    print("\nTo use Telegram commands:")
    print("1. Create a bot with @BotFather on Telegram")
    print("2. Get your bot token")
    print("3. Start chat with your bot and send /start")
    print("4. Get your chat ID\n")
    
    token = input("Enter Telegram bot token (or press Enter to skip): ").strip()
    if token:
        chat_id = input("Enter your chat ID: ").strip()
        return token, chat_id
    return None, None

def open_traffic_gui(monitor):
    """Open the traffic generator GUI"""
    root = tk.Tk()
    app = TrafficGeneratorGUI(root, monitor.traffic_generator)
    return root

def open_ssh_gui(monitor):
    """Open the SSH client GUI"""
    root = tk.Tk()
    app = SSHClientGUI(root, monitor.ssh_manager)
    return root

def main():
    """Main function"""
    monitor = CybersecurityMonitor()
    telegram_handler = TelegramBotHandler(monitor)
    
    print_banner()
    
    # Setup Telegram if not configured
    if not monitor.telegram_token:
        token, chat_id = setup_telegram()
        if token and chat_id:
            monitor.telegram_token = token
            monitor.telegram_chat_id = chat_id
            monitor.save_config()
            print("✅ Telegram configured!")
        else:
            print("⚠️ Telegram features disabled")
    
    # Start Telegram command processor
    def telegram_processor():
        while True:
            try:
                telegram_handler.process_telegram_commands()
                time.sleep(2)
            except Exception as e:
                logging.error(f"Telegram error: {e}")
                time.sleep(10)
    
    telegram_thread = threading.Thread(target=telegram_processor, daemon=True)
    telegram_thread.start()
    
    if monitor.telegram_token and monitor.telegram_chat_id:
        print("✅ Telegram bot ACTIVE")
        print("📱 Send /start to your bot on Telegram")
        test_msg = "🔗 <b>Accurate Cyber Star - Connected!</b>\n\n✅ Bot is online\n🚀 Type /help for commands\n🔐 SSH client ready\n🌐 Traffic generation available!"
        telegram_handler.send_telegram_message(test_msg)
    
    print("\n💻 Local terminal commands available")
    print("🎛️  Type 'gui' to open GUI tools")
    print("📋 Type 'help' for command list\n")
    
    # Local command interface
    while True:
        try:
            command = input("Accurate*> ").strip()
            if not command:
                continue
            
            monitor.db_manager.log_command(command, 'local', True)
            parts = command.split()
            cmd = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []
            
            if cmd == 'exit':
                print("👋 Exiting...")
                monitor.traffic_generator.stop_traffic()
                for session_id in list(monitor.ssh_manager.connections.keys()):
                    monitor.ssh_manager.disconnect(session_id)
                break
            
            elif cmd == 'help':
                print("""
Local Commands:
  ping [ip]              - Ping IP address
  tracert [ip]           - Traceroute
  scan [ip]              - Port scan
  location [ip]          - Get IP location
  analyze [ip]           - Analyze IP
  whois [domain]         - WHOIS lookup
  dns [domain]           - DNS lookup
  
🔐 SSH Commands:
  ssh_connect [host] [user] [pass] - SSH connect (password)
  ssh_key_connect [host] [user] [key] - SSH connect (key)
  ssh_command [cmd]      - Execute SSH command
  ssh_list               - List SSH sessions
  ssh_disconnect         - Disconnect SSH
  
  start_monitoring [ip]  - Start monitoring IP
  add [ip]               - Add IP to monitoring
  remove [ip]            - Remove IP
  list                   - List monitored IPs
  stop                   - Stop monitoring
  
  generate_traffic       - Generate network traffic
  stop_traffic           - Stop traffic generation
  gui                    - Open GUI tools menu
  
  network_info           - Network information
  system_info            - System information
  status                 - System status
  history                - Command history
  ssh_history            - SSH session history
  threats                - Threat summary
  report                 - Generate report
  
  config                 - Configure Telegram
  clear                  - Clear screen
  exit                   - Exit program

All commands also available via Telegram!
                """)
            
            elif cmd == 'gui':
                print("🎛️  Available GUI Tools:")
                print("  1. Traffic Generator")
                print("  2. SSH Client")
                
                choice = input("Select tool (1-2) or 'q' to cancel: ").strip()
                if choice == '1':
                    print("🚀 Opening Traffic Generator GUI...")
                    root = open_traffic_gui(monitor)
                    root.mainloop()
                elif choice == '2':
                    print("🔐 Opening SSH Client GUI...")
                    root = open_ssh_gui(monitor)
                    root.mainloop()
            
            elif cmd == 'ssh_connect' and len(args) >= 3:
                host = args[0]
                username = args[1]
                password = args[2]
                port = 22
                
                if len(args) > 3:
                    try:
                        port = int(args[3])
                    except ValueError:
                        print("❌ Invalid port number")
                        continue
                
                success, message = monitor.ssh_manager.connect_password(host, username, password, port)
                print(message)
            
            elif cmd == 'ssh_key_connect' and len(args) >= 3:
                host = args[0]
                username = args[1]
                key_path = args[2]
                port = 22
                key_password = None
                
                if len(args) > 3:
                    port = int(args[3]) if args[3].isdigit() else 22
                if len(args) > 4:
                    key_password = args[4]
                
                success, message = monitor.ssh_manager.connect_key(host, username, key_path, port, key_password)
                print(message)
            
            elif cmd == 'ssh_command' and args:
                command = " ".join(args)
                success, output = monitor.ssh_manager.execute_command(command)
                print(output)
            
            elif cmd == 'ssh_list':
                sessions = monitor.ssh_manager.get_active_sessions()
                if sessions:
                    print("\n🔐 Active SSH Sessions:")
                    for session in sessions:
                        print(f"• {session['host']} ({session['username']})")
                        print(f"  Auth: {session['auth_type']}")
                        print(f"  Connected: {session['connected_at'].strftime('%H:%M:%S')}\n")
                else:
                    print("📋 No active SSH sessions")
            
            elif cmd == 'ssh_disconnect':
                success, message = monitor.ssh_manager.disconnect()
                print(message)
            
            elif cmd == 'ssh_history':
                history = monitor.db_manager.get_ssh_history(20)
                if history:
                    print("\n📜 SSH Session History:")
                    for host, username, port, auth_type, timestamp, successful in history:
                        status = "✅" if successful else "❌"
                        print(f"{status} {username}@{host}:{port} ({auth_type})")
                        print(f"  {timestamp}\n")
                else:
                    print("📜 No SSH session history")
            
            elif cmd == 'generate_traffic' and len(args) >= 2:
                traffic_type = args[0].lower()
                target = args[1]
                port = None
                
                if ":" in target and traffic_type in ["tcp", "udp"]:
                    target, port_str = target.split(":", 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        print(f"❌ Invalid port: {port_str}")
                        continue
                
                print(f"🌐 Generating {traffic_type.upper()} traffic to {target}...")
                
                if traffic_type == "tcp" and port:
                    result = monitor.traffic_generator.generate_tcp_traffic(target, port, 100, 0.01)
                elif traffic_type == "udp" and port:
                    result = monitor.traffic_generator.generate_udp_traffic(target, port, 100, 0.01)
                elif traffic_type == "icmp":
                    result = monitor.traffic_generator.generate_icmp_traffic(target, 50, 0.1)
                else:
                    result = f"❌ Invalid traffic type or missing port: {traffic_type}"
                
                print(result)
            
            elif cmd == 'stop_traffic':
                monitor.traffic_generator.stop_traffic()
                print("🛑 All traffic generation stopped")
            
            elif cmd == 'ping' and args:
                result = monitor.scanner.ping_ip(args[0])
                print(result)
            
            elif cmd in ['tracert', 'traceroute'] and args:
                print(f"Traceroute to {args[0]}...")
                result = monitor.scanner.traceroute(args[0])
                print(result)
            
            elif cmd == 'scan' and args:
                print(f"Scanning {args[0]}...")
                result = monitor.scanner.port_scan(args[0])
                if result['success']:
                    print(f"\n📊 Scan Results for {args[0]}:")
                    open_ports = result.get('open_ports', [])
                    print(f"Open Ports: {len(open_ports)}\n")
                    for p in open_ports:
                        print(f"  Port {p['port']}: {p['service']}")
                else:
                    print(f"❌ Error: {result.get('error', 'Unknown')}")
            
            elif cmd == 'location' and args:
                result = monitor.scanner.get_ip_location(args[0])
                print(result)
            
            elif cmd == 'analyze' and args:
                ip = args[0]
                print(f"\n🔍 Analyzing {ip}...\n")
                location = monitor.scanner.get_ip_location(ip)
                try:
                    loc_data = json.loads(location)
                    print(f"📍 Location: {loc_data.get('city', 'N/A')}, {loc_data.get('country', 'N/A')}")
                    print(f"🏢 ISP: {loc_data.get('isp', 'N/A')}\n")
                except:
                    pass
                threats = monitor.db_manager.get_recent_threats(10)
                ip_threats = [t for t in threats if t[0] == ip]
                if ip_threats:
                    print(f"🚨 Threats Found: {len(ip_threats)}")
                    for threat in ip_threats:
                        print(f"  • {threat[1]}: {threat[2]}")
                else:
                    print("✅ No recent threats detected")
            
            elif cmd == 'whois' and args:
                try:
                    result = subprocess.run(['whois', args[0]], capture_output=True, text=True, timeout=30)
                    print(result.stdout)
                except:
                    print("❌ WHOIS lookup failed")
            
            elif cmd == 'dns' and args:
                try:
                    ip = socket.gethostbyname(args[0])
                    print(f"🌐 {args[0]} → {ip}")
                except Exception as e:
                    print(f"❌ DNS lookup failed: {e}")
            
            elif cmd == 'start_monitoring' and args:
                ip = args[0]
                try:
                    ipaddress.ip_address(ip)
                    monitor.monitored_ips.add(ip)
                    monitor.save_config()
                    print(f"✅ Started monitoring {ip}")
                except ValueError:
                    print(f"❌ Invalid IP: {ip}")
            
            elif cmd == 'add' and args:
                ip = args[0]
                try:
                    ipaddress.ip_address(ip)
                    monitor.monitored_ips.add(ip)
                    monitor.save_config()
                    print(f"✅ Added {ip}")
                except ValueError:
                    print(f"❌ Invalid IP: {ip}")
            
            elif cmd == 'remove' and args:
                ip = args[0]
                if ip in monitor.monitored_ips:
                    monitor.monitored_ips.remove(ip)
                    monitor.save_config()
                    print(f"✅ Removed {ip}")
                else:
                    print(f"❌ IP not in list: {ip}")
            
            elif cmd == 'list':
                if monitor.monitored_ips:
                    print("\n📋 Monitored IPs:")
                    for ip in sorted(monitor.monitored_ips):
                        print(f"  • {ip}")
                else:
                    print("📋 No IPs being monitored")
            
            elif cmd == 'stop':
                if monitor.monitored_ips:
                    ips = list(monitor.monitored_ips)
                    monitor.monitored_ips.clear()
                    monitor.save_config()
                    print(f"🛑 Stopped monitoring: {', '.join(ips)}")
                else:
                    print("⚠️ No IPs being monitored")
            
            elif cmd == 'network_info':
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                print(f"\n🌐 Network Information:")
                print(f"  Hostname: {hostname}")
                print(f"  Local IP: {local_ip}")
                print(f"  Connections: {len(psutil.net_connections())}")
            
            elif cmd == 'system_info':
                print(f"\n💻 System Information:")
                print(f"  OS: {platform.system()} {platform.release()}")
                print(f"  CPU Cores: {psutil.cpu_count()}")
                print(f"  CPU Usage: {psutil.cpu_percent()}%")
                print(f"  Memory: {psutil.virtual_memory().percent}%")
                print(f"  Disk: {psutil.disk_usage('/').percent}%")
            
            elif cmd == 'status':
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                ssh_sessions = len(monitor.ssh_manager.get_active_sessions())
                print(f"\n📊 System Status:")
                print(f"  Bot: {'Online' if monitor.telegram_token else 'Offline'}")
                print(f"  Monitored IPs: {len(monitor.monitored_ips)}")
                print(f"  SSH Sessions: {ssh_sessions}")
                print(f"  CPU: {cpu}%")
                print(f"  Memory: {mem.percent}%")
                print(f"  Connections: {len(psutil.net_connections())}")
            
            elif cmd == 'history':
                history = monitor.db_manager.get_command_history(20)
                if history:
                    print("\n📜 Command History:")
                    for cmd, src, ts, success in history:
                        status = "✅" if success else "❌"
                        print(f"  {status} [{src}] {cmd} | {ts}")
                else:
                    print("📜 No commands recorded")
            
            elif cmd == 'threats':
                threats = monitor.db_manager.get_recent_threats(10)
                if threats:
                    print("\n🚨 Recent Threats:")
                    for ip, ttype, severity, ts in threats:
                        print(f"  • {ip}")
                        print(f"    Type: {ttype} | Severity: {severity}")
                        print(f"    Time: {ts}\n")
                else:
                    print("✅ No recent threats detected")
            
            elif cmd == 'report':
                threats = monitor.db_manager.get_recent_threats(50)
                history = monitor.db_manager.get_command_history(100)
                ssh_history = monitor.db_manager.get_ssh_history(20)
                
                report = {
                    'generated_at': datetime.now().isoformat(),
                    'monitored_ips': len(monitor.monitored_ips),
                    'total_threats': len(threats),
                    'high_severity': len([t for t in threats if t[2] == 'high']),
                    'medium_severity': len([t for t in threats if t[2] == 'medium']),
                    'low_severity': len([t for t in threats if t[2] == 'low']),
                    'commands_executed': len(history),
                    'ssh_sessions': len(ssh_history),
                    'active_ssh_sessions': len(monitor.ssh_manager.get_active_sessions())
                }
                
                filename = f"report_{int(time.time())}.json"
                os.makedirs(REPORT_DIR, exist_ok=True)
                filepath = os.path.join(REPORT_DIR, filename)
                
                with open(filepath, 'w') as f:
                    json.dump(report, f, indent=2)
                
                print(f"\n📊 Security Report:")
                print(f"  Monitored IPs: {report['monitored_ips']}")
                print(f"  Total Threats: {report['total_threats']}")
                print(f"  High Severity: {report['high_severity']}")
                print(f"  Medium Severity: {report['medium_severity']}")
                print(f"  Low Severity: {report['low_severity']}")
                print(f"  Commands Executed: {report['commands_executed']}")
                print(f"  SSH Sessions: {report['ssh_sessions']}")
                print(f"  Active SSH Sessions: {report['active_ssh_sessions']}")
                print(f"\n✅ Report saved: {filename}")
            
            elif cmd == 'config':
                token, chat_id = setup_telegram()
                if token and chat_id:
                    monitor.telegram_token = token
                    monitor.telegram_chat_id = chat_id
                    monitor.save_config()
                    print("✅ Telegram configured!")
            
            elif cmd == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner()
            
            else:
                print("Unknown command. Type 'help' for available commands.")
        
        except KeyboardInterrupt:
            print("\n👋 Exiting...")
            monitor.traffic_generator.stop_traffic()
            for session_id in list(monitor.ssh_manager.connections.keys()):
                monitor.ssh_manager.disconnect(session_id)
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            monitor.db_manager.log_command(command, 'local', False)

if __name__ == "__main__":
    # Check required dependencies
    required_packages = []
    
    try:
        import paramiko
    except ImportError:
        required_packages.append("paramiko")
    
    if NMAP_AVAILABLE is False:
        required_packages.append("python-nmap")
    
    if SCAPY_AVAILABLE is False:
        required_packages.append("scapy")
    
    if required_packages:
        print(f"\n⚠️  Some features require additional packages:")
        for package in required_packages:
            print(f"   - {package}")
        print("\nInstall missing packages with: pip install " + " ".join(required_packages))
        print("\nTool will run with limited features.\n")
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Thank you for using Accurate Online OS!")
    except Exception as e:
        print(f"❌ Application error: {e}")
        logging.exception("Application crash")