import psutil
import platform
import socket
import time
from datetime import datetime
import json

class SecurityMonitor:
    """Main security monitoring class that coordinates all security aspects"""
    
    def __init__(self):
        self.start_time = time.time()
        self.alert_thresholds = {
            'cpu_usage': 80.0,
            'memory_usage': 85.0,
            'disk_usage': 90.0,
            'network_connections': 1000,
            'failed_login_attempts': 5
        }
        
    def get_system_health(self):
        """Get overall system health status"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            health_score = 100
            
            # CPU health
            if cpu_percent > self.alert_thresholds['cpu_usage']:
                health_score -= 20
                
            # Memory health
            if memory.percent > self.alert_thresholds['memory_usage']:
                health_score -= 20
                
            # Disk health
            if disk.percent > self.alert_thresholds['disk_usage']:
                health_score -= 20
            
            return {
                'timestamp': datetime.now().isoformat(),
                'health_score': max(health_score, 0),
                'cpu_usage': cpu_percent,
                'memory_usage': memory.percent,
                'disk_usage': disk.percent,
                'status': 'healthy' if health_score > 70 else 'warning' if health_score > 40 else 'critical'
            }
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'health_score': 0,
                'status': 'error',
                'error': str(e)
            }
    
    def get_network_status(self):
        """Get network connectivity and status"""
        try:
            # Check network interfaces
            interfaces = psutil.net_if_addrs()
            active_interfaces = []
            
            for interface, addresses in interfaces.items():
                for addr in addresses:
                    if addr.family == socket.AF_INET:  # IPv4
                        active_interfaces.append({
                            'interface': interface,
                            'ip': addr.address,
                            'netmask': addr.netmask
                        })
            
            # Check network connections
            connections = psutil.net_connections()
            established_connections = len([c for c in connections if c.status == 'ESTABLISHED'])
            
            return {
                'timestamp': datetime.now().isoformat(),
                'active_interfaces': active_interfaces,
                'total_connections': len(connections),
                'established_connections': established_connections,
                'status': 'active' if active_interfaces else 'inactive'
            }
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'status': 'error',
                'error': str(e)
            }
    
    def get_security_summary(self):
        """Get security summary and statistics"""
        try:
            # Get running processes
            processes = list(psutil.process_iter(['pid', 'name', 'username']))
            
            # Get user sessions
            users = psutil.users()
            
            # Get boot time
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = time.time() - psutil.boot_time()
            
            return {
                'timestamp': datetime.now().isoformat(),
                'total_processes': len(processes),
                'active_users': len(users),
                'boot_time': boot_time.isoformat(),
                'uptime_seconds': uptime,
                'uptime_formatted': self._format_uptime(uptime)
            }
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }
    
    def _format_uptime(self, seconds):
        """Format uptime in human readable format"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    
    def check_security_vulnerabilities(self):
        """Check for common security vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for open ports
            connections = psutil.net_connections()
            open_ports = set()
            
            for conn in connections:
                if conn.status == 'LISTEN':
                    open_ports.add(conn.laddr.port)
            
            # Check for suspicious ports
            suspicious_ports = {22, 23, 3389, 5900, 8080, 8443}  # SSH, Telnet, RDP, VNC, HTTP/HTTPS
            for port in open_ports:
                if port in suspicious_ports:
                    vulnerabilities.append({
                        'type': 'open_port',
                        'severity': 'medium',
                        'description': f'Port {port} is open and listening',
                        'port': port
                    })
            
            # Check for high privilege processes
            processes = list(psutil.process_iter(['pid', 'name', 'username']))
            for proc in processes:
                try:
                    if proc.info['username'] == 'root' or proc.info['username'] == 'SYSTEM':
                        vulnerabilities.append({
                            'type': 'high_privilege_process',
                            'severity': 'low',
                            'description': f'Process {proc.info["name"]} running with high privileges',
                            'process': proc.info
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
        except Exception as e:
            vulnerabilities.append({
                'type': 'error',
                'severity': 'unknown',
                'description': f'Error checking vulnerabilities: {str(e)}'
            })
        
        return vulnerabilities

