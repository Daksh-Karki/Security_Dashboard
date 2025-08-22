import psutil
import platform
import socket
import time
import random
from datetime import datetime, timedelta
import json
import os

class SystemCollector:
    """Collects system performance and security metrics"""
    
    def __init__(self):
        self.last_collection = time.time()
        self.collection_interval = 5  # seconds
        
    def collect_metrics(self):
        """Collect comprehensive system metrics"""
        try:
            current_time = time.time()
            
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            # Process metrics
            processes = list(psutil.process_iter(['pid', 'name', 'username', 'memory_percent']))
            top_processes = sorted(processes, key=lambda x: x.info['memory_percent'] or 0, reverse=True)[:10]
            
            # User sessions
            users = psutil.users()
            
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'usage_percent': cpu_percent,
                    'count': cpu_count,
                    'frequency_mhz': cpu_freq.current if cpu_freq else None
                },
                'memory': {
                    'total_gb': round(memory.total / (1024**3), 2),
                    'available_gb': round(memory.available / (1024**3), 2),
                    'used_gb': round(memory.used / (1024**3), 2),
                    'usage_percent': memory.percent,
                    'swap_total_gb': round(swap.total / (1024**3), 2),
                    'swap_used_gb': round(swap.used / (1024**3), 2)
                },
                'disk': {
                    'total_gb': round(disk.total / (1024**3), 2),
                    'used_gb': round(disk.used / (1024**3), 2),
                    'free_gb': round(disk.free / (1024**3), 2),
                    'usage_percent': disk.percent,
                    'read_bytes': disk_io.read_bytes if disk_io else 0,
                    'write_bytes': disk_io.write_bytes if disk_io else 0
                },
                'processes': {
                    'total_count': len(processes),
                    'top_by_memory': [
                        {
                            'name': p.info['name'],
                            'pid': p.info['pid'],
                            'memory_percent': p.info['memory_percent'] or 0
                        } for p in top_processes
                    ]
                },
                'users': {
                    'active_count': len(users),
                    'sessions': [
                        {
                            'username': user.name,
                            'terminal': user.terminal,
                            'host': user.host,
                            'started': datetime.fromtimestamp(user.started).isoformat()
                        } for user in users
                    ]
                },
                'system_info': {
                    'platform': platform.system(),
                    'platform_version': platform.version(),
                    'machine': platform.machine(),
                    'processor': platform.processor()
                }
            }
            
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'status': 'error'
            }

class NetworkCollector:
    """Collects network traffic and connection data"""
    
    def __init__(self):
        self.last_collection = time.time()
        self.connection_history = []
        
    def collect_traffic(self):
        """Collect network traffic statistics"""
        try:
            # Network I/O counters
            net_io = psutil.net_io_counters()
            
            # Network connections
            connections = psutil.net_connections()
            
            # Network interfaces
            interfaces = psutil.net_if_stats()
            interface_addresses = psutil.net_if_addrs()
            
            # Categorize connections
            connection_types = {
                'established': 0,
                'listening': 0,
                'time_wait': 0,
                'close_wait': 0,
                'other': 0
            }
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    connection_types['established'] += 1
                elif conn.status == 'LISTEN':
                    connection_types['listening'] += 1
                elif conn.status == 'TIME_WAIT':
                    connection_types['time_wait'] += 1
                elif conn.status == 'CLOSE_WAIT':
                    connection_types['close_wait'] += 1
                else:
                    connection_types['other'] += 1
            
            # Get active network interfaces
            active_interfaces = []
            for interface, stats in interfaces.items():
                if stats.isup:
                    addresses = interface_addresses.get(interface, [])
                    ip_addresses = [addr.address for addr in addresses if addr.family == socket.AF_INET]
                    if ip_addresses:
                        active_interfaces.append({
                            'name': interface,
                            'ip_addresses': ip_addresses,
                            'speed_mbps': stats.speed if stats.speed > 0 else 'Unknown'
                        })
            
            return {
                'timestamp': datetime.now().isoformat(),
                'traffic': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv,
                    'errors_in': net_io.errin,
                    'errors_out': net_io.errout,
                    'drops_in': net_io.dropin,
                    'drops_out': net_io.dropout
                },
                'connections': {
                    'total': len(connections),
                    'by_status': connection_types
                },
                'interfaces': active_interfaces,
                'local_ip': self._get_local_ip()
            }
            
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'status': 'error'
            }
    
    def _get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

class LogCollector:
    """Collects and analyzes security-related logs"""
    
    def __init__(self):
        self.log_sources = []
        self.last_check = time.time()
        self.check_interval = 10  # seconds
        
    def collect_logs(self):
        """Collect security logs from various sources"""
        try:
            current_time = time.time()
            if current_time - self.last_check < self.check_interval:
                return []
            
            self.last_check = current_time
            logs = []
            
            # Simulate log collection (in real implementation, this would read actual log files)
            logs.extend(self._collect_system_logs())
            logs.extend(self._collect_security_logs())
            logs.extend(self._collect_network_logs())
            
            return logs
            
        except Exception as e:
            return [{
                'timestamp': datetime.now().isoformat(),
                'level': 'ERROR',
                'source': 'log_collector',
                'message': f'Error collecting logs: {str(e)}'
            }]
    
    def _collect_system_logs(self):
        """Collect system-related logs"""
        logs = []
        
        try:
            # Check for failed login attempts
            failed_logins = random.randint(0, 3)  # Simulate random failed logins
            for i in range(failed_logins):
                logs.append({
                    'timestamp': datetime.now().isoformat(),
                    'level': 'WARNING',
                    'source': 'system_auth',
                    'message': f'Failed login attempt for user {chr(97 + i)}',
                    'severity': 'medium'
                })
            
            # Check for system resource warnings
            memory = psutil.virtual_memory()
            if memory.percent > 80:
                logs.append({
                    'timestamp': datetime.now().isoformat(),
                    'level': 'WARNING',
                    'source': 'system_monitor',
                    'message': f'High memory usage: {memory.percent}%',
                    'severity': 'medium'
                })
            
            # Check for disk space warnings
            disk = psutil.disk_usage('/')
            if disk.percent > 85:
                logs.append({
                    'timestamp': datetime.now().isoformat(),
                    'level': 'WARNING',
                    'source': 'system_monitor',
                    'message': f'High disk usage: {disk.percent}%',
                    'severity': 'medium'
                })
                
        except Exception as e:
            logs.append({
                'timestamp': datetime.now().isoformat(),
                'level': 'ERROR',
                'source': 'system_logs',
                'message': f'Error collecting system logs: {str(e)}',
                'severity': 'high'
            })
        
        return logs
    
    def _collect_security_logs(self):
        """Collect security-related logs"""
        logs = []
        
        try:
            # Simulate security events
            security_events = [
                'Firewall rule triggered',
                'Suspicious network activity detected',
                'New user account created',
                'Privilege escalation attempt',
                'Malware scan completed'
            ]
            
            # Randomly select events
            num_events = random.randint(0, 2)
            for _ in range(num_events):
                event = random.choice(security_events)
                level = random.choice(['INFO', 'WARNING', 'ALERT'])
                severity = 'low' if level == 'INFO' else 'medium' if level == 'WARNING' else 'high'
                
                logs.append({
                    'timestamp': datetime.now().isoformat(),
                    'level': level,
                    'source': 'security_monitor',
                    'message': event,
                    'severity': severity
                })
                
        except Exception as e:
            logs.append({
                'timestamp': datetime.now().isoformat(),
                'level': 'ERROR',
                'source': 'security_logs',
                'message': f'Error collecting security logs: {str(e)}',
                'severity': 'high'
            })
        
        return logs
    
    def _collect_network_logs(self):
        """Collect network-related logs"""
        logs = []
        
        try:
            # Check for unusual network activity
            connections = psutil.net_connections()
            if len(connections) > 1000:
                logs.append({
                    'timestamp': datetime.now().isoformat(),
                    'level': 'WARNING',
                    'source': 'network_monitor',
                    'message': f'High number of network connections: {len(connections)}',
                    'severity': 'medium'
                })
            
            # Check for listening ports
            listening_ports = [c.laddr.port for c in connections if c.status == 'LISTEN']
            if len(listening_ports) > 20:
                logs.append({
                    'timestamp': datetime.now().isoformat(),
                    'level': 'INFO',
                    'source': 'network_monitor',
                    'message': f'Multiple listening ports: {len(listening_ports)}',
                    'severity': 'low'
                })
                
        except Exception as e:
            logs.append({
                'timestamp': datetime.now().isoformat(),
                'level': 'ERROR',
                'source': 'network_logs',
                'message': f'Error collecting network logs: {str(e)}',
                'severity': 'high'
            })
        
        return logs

