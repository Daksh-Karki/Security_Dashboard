import time
import random
from datetime import datetime, timedelta
import json

class ThreatDetector:
    """Advanced threat detection engine that analyzes security data"""
    
    def __init__(self):
        self.threat_patterns = {
            'brute_force': {
                'failed_logins_threshold': 5,
                'time_window_minutes': 10,
                'severity': 'high'
            },
            'resource_abuse': {
                'cpu_threshold': 95,        # Increased from 90 to 95
                'memory_threshold': 98,     # Increased from 95 to 98
                'disk_threshold': 95,
                'severity': 'medium'
            },
            'network_anomaly': {
                'connection_threshold': 1500,
                'port_scan_threshold': 50,
                'severity': 'high'
            },
            'suspicious_process': {
                'unknown_process_threshold': 10,
                'high_privilege_threshold': 5,
                'severity': 'medium'
            }
        }
        
        self.detected_threats = []
        self.analysis_history = []
        self.last_alert_time = {}  # Track when last alert of each type was sent
        self.alert_cooldown = 60   # 60 seconds cooldown between same type alerts
        
    def analyze_data(self, security_data):
        """Analyze security data for potential threats"""
        try:
            threats = []
            current_time = datetime.now()
            
            # Analyze system metrics
            if security_data.get('system_metrics'):
                latest_system = security_data['system_metrics'][-1]
                system_threats = self._analyze_system_metrics(latest_system)
                threats.extend(system_threats)
            
            # Analyze network traffic
            if security_data.get('network_traffic'):
                latest_network = security_data['network_traffic'][-1]
                network_threats = self._analyze_network_traffic(latest_network)
                threats.extend(network_threats)
            
            # Analyze security events
            if security_data.get('security_events'):
                event_threats = self._analyze_security_events(security_data['security_events'])
                threats.extend(event_threats)
            
            # Analyze historical patterns
            pattern_threats = self._analyze_patterns(security_data)
            threats.extend(pattern_threats)
            
            # Update analysis history
            self.analysis_history.append({
                'timestamp': current_time.isoformat(),
                'threats_found': len(threats),
                'analysis_duration_ms': random.randint(50, 200)  # Simulate analysis time
            })
            
            # Keep only last 100 analysis records
            if len(self.analysis_history) > 100:
                self.analysis_history = self.analysis_history[-100:]
            
            return threats
            
        except Exception as e:
            return [{
                'id': f'threat_error_{int(time.time())}',
                'timestamp': datetime.now().isoformat(),
                'type': 'analysis_error',
                'severity': 'critical',
                'description': f'Error in threat analysis: {str(e)}',
                'source': 'threat_detector',
                'status': 'detected'
            }]
    
    def _analyze_system_metrics(self, system_data):
        """Analyze system metrics for threats"""
        threats = []
        
        try:
            # Check CPU usage
            if system_data.get('cpu', {}).get('usage_percent', 0) > self.threat_patterns['resource_abuse']['cpu_threshold']:
                threats.append({
                    'id': f'cpu_abuse_{int(time.time())}',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'resource_abuse',
                    'severity': self.threat_patterns['resource_abuse']['severity'],
                    'description': f'High CPU usage detected: {system_data["cpu"]["usage_percent"]}%',
                    'source': 'system_monitor',
                    'details': {
                        'cpu_usage': system_data['cpu']['usage_percent'],
                        'threshold': self.threat_patterns['resource_abuse']['cpu_threshold']
                    },
                    'status': 'detected'
                })
            
            # Check memory usage
            if system_data.get('memory', {}).get('usage_percent', 0) > self.threat_patterns['resource_abuse']['memory_threshold']:
                threats.append({
                    'id': f'memory_abuse_{int(time.time())}',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'resource_abuse',
                    'severity': self.threat_patterns['resource_abuse']['severity'],
                    'description': f'High memory usage detected: {system_data["memory"]["usage_percent"]}%',
                    'source': 'system_monitor',
                    'details': {
                        'memory_usage': system_data['memory']['usage_percent'],
                        'threshold': self.threat_patterns['resource_abuse']['memory_threshold']
                    },
                    'status': 'detected'
                })
            
            # Check disk usage
            if system_data.get('disk', {}).get('usage_percent', 0) > self.threat_patterns['resource_abuse']['disk_threshold']:
                threats.append({
                    'id': f'disk_abuse_{int(time.time())}',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'resource_abuse',
                    'severity': self.threat_patterns['resource_abuse']['severity'],
                    'description': f'High disk usage detected: {system_data["disk"]["usage_percent"]}%',
                    'source': 'system_monitor',
                    'details': {
                        'disk_usage': system_data['disk']['usage_percent'],
                        'threshold': self.threat_patterns['resource_abuse']['disk_threshold']
                    },
                    'status': 'detected'
                })
            
            # Check for suspicious processes
            if system_data.get('processes', {}).get('total_count', 0) > 500:
                if self._should_send_alert('process_anomaly'):
                    threats.append({
                        'id': f'process_anomaly_{int(time.time())}',
                        'timestamp': datetime.now().isoformat(),
                        'type': 'suspicious_process',
                        'severity': self.threat_patterns['suspicious_process']['severity'],
                        'description': f'Unusually high number of processes: {system_data["processes"]["total_count"]}',
                        'source': 'system_monitor',
                        'details': {
                            'process_count': system_data['processes']['total_count'],
                            'threshold': 500
                        },
                        'status': 'detected'
                    })
                
        except Exception as e:
            threats.append({
                'id': f'system_analysis_error_{int(time.time())}',
                'timestamp': datetime.now().isoformat(),
                'type': 'analysis_error',
                'severity': 'medium',
                'description': f'Error analyzing system metrics: {str(e)}',
                'source': 'threat_detector',
                'status': 'detected'
            })
        
        return threats
    
    def _analyze_network_traffic(self, network_data):
        """Analyze network traffic for threats"""
        threats = []
        
        try:
            # Check for excessive connections
            if network_data.get('connections', {}).get('total', 0) > self.threat_patterns['network_anomaly']['connection_threshold']:
                threats.append({
                    'id': f'network_anomaly_{int(time.time())}',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'network_anomaly',
                    'severity': self.threat_patterns['network_anomaly']['severity'],
                    'description': f'Excessive network connections detected: {network_data["connections"]["total"]}',
                    'source': 'network_monitor',
                    'details': {
                        'connection_count': network_data['connections']['total'],
                        'threshold': self.threat_patterns['network_anomaly']['connection_threshold']
                    },
                    'status': 'detected'
                })
            
            # Check for listening ports
            listening_ports = network_data.get('connections', {}).get('by_status', {}).get('listening', 0)
            if listening_ports > self.threat_patterns['network_anomaly']['port_scan_threshold']:
                threats.append({
                    'id': f'port_scan_{int(time.time())}',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'network_anomaly',
                    'severity': self.threat_patterns['network_anomaly']['severity'],
                    'description': f'High number of listening ports: {listening_ports}',
                    'source': 'network_monitor',
                    'details': {
                        'listening_ports': listening_ports,
                        'threshold': self.threat_patterns['network_anomaly']['port_scan_threshold']
                    },
                    'status': 'detected'
                })
            
            # Check for network errors
            traffic = network_data.get('traffic', {})
            if traffic.get('errors_in', 0) > 100 or traffic.get('errors_out', 0) > 100:
                threats.append({
                    'id': f'network_errors_{int(time.time())}',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'network_anomaly',
                    'severity': 'medium',
                    'description': f'High network error rate detected',
                    'source': 'network_monitor',
                    'details': {
                        'errors_in': traffic.get('errors_in', 0),
                        'errors_out': traffic.get('errors_out', 0)
                    },
                    'status': 'detected'
                })
                
        except Exception as e:
            threats.append({
                'id': f'network_analysis_error_{int(time.time())}',
                'timestamp': datetime.now().isoformat(),
                'type': 'analysis_error',
                'severity': 'medium',
                'description': f'Error analyzing network traffic: {str(e)}',
                'source': 'threat_detector',
                'status': 'detected'
            })
        
        return threats
    
    def _analyze_security_events(self, events):
        """Analyze security events for threats"""
        threats = []
        
        try:
            # Count events by severity
            high_severity = [e for e in events if e.get('severity') == 'high']
            medium_severity = [e for e in events if e.get('severity') == 'medium']
            
            # Check for high severity events
            if len(high_severity) > 0:
                threats.append({
                    'id': f'high_severity_events_{int(time.time())}',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'security_event',
                    'severity': 'high',
                    'description': f'Multiple high severity security events detected: {len(high_severity)}',
                    'source': 'security_monitor',
                    'details': {
                        'high_severity_count': len(high_severity),
                        'events': high_severity[:5]  # Show first 5 events
                    },
                    'status': 'detected'
                })
            
            # Check for failed login patterns
            failed_logins = [e for e in events if 'Failed login attempt' in e.get('message', '')]
            if len(failed_logins) >= self.threat_patterns['brute_force']['failed_logins_threshold']:
                threats.append({
                    'id': f'brute_force_{int(time.time())}',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'brute_force',
                    'severity': self.threat_patterns['brute_force']['severity'],
                    'description': f'Potential brute force attack detected: {len(failed_logins)} failed login attempts',
                    'source': 'security_monitor',
                    'details': {
                        'failed_attempts': len(failed_logins),
                        'threshold': self.threat_patterns['brute_force']['failed_logins_threshold']
                    },
                    'status': 'detected'
                })
                
        except Exception as e:
            threats.append({
                'id': f'event_analysis_error_{int(time.time())}',
                'timestamp': datetime.now().isoformat(),
                'type': 'analysis_error',
                'severity': 'medium',
                'description': f'Error analyzing security events: {str(e)}',
                'source': 'threat_detector',
                'status': 'detected'
            })
        
        return threats
    
    def _analyze_patterns(self, security_data):
        """Analyze historical patterns for threats"""
        threats = []
        
        try:
            # Check for rapid resource consumption
            if len(security_data.get('system_metrics', [])) >= 3:
                recent_metrics = security_data['system_metrics'][-3:]
                cpu_trend = [m.get('cpu', {}).get('usage_percent', 0) for m in recent_metrics]
                
                # Check if CPU usage is rapidly increasing
                if len(cpu_trend) >= 2 and cpu_trend[-1] - cpu_trend[0] > 30:
                    threats.append({
                        'id': f'rapid_cpu_increase_{int(time.time())}',
                        'timestamp': datetime.now().isoformat(),
                        'type': 'resource_abuse',
                        'severity': 'medium',
                        'description': 'Rapid CPU usage increase detected',
                        'source': 'pattern_analyzer',
                        'details': {
                            'cpu_trend': cpu_trend,
                            'increase': cpu_trend[-1] - cpu_trend[0]
                        },
                        'status': 'detected'
                    })
            
            # Check for network traffic spikes
            if len(security_data.get('network_traffic', [])) >= 3:
                recent_traffic = security_data['network_traffic'][-3:]
                connection_counts = [t.get('connections', {}).get('total', 0) for t in recent_traffic]
                
                if len(connection_counts) >= 2 and connection_counts[-1] - connection_counts[0] > 500:
                    threats.append({
                        'id': f'network_spike_{int(time.time())}',
                        'timestamp': datetime.now().isoformat(),
                        'type': 'network_anomaly',
                        'severity': 'medium',
                        'description': 'Sudden network traffic spike detected',
                        'source': 'pattern_analyzer',
                        'details': {
                            'connection_trend': connection_counts,
                            'spike': connection_counts[-1] - connection_counts[0]
                        },
                        'status': 'detected'
                    })
                    
        except Exception as e:
            threats.append({
                'id': f'pattern_analysis_error_{int(time.time())}',
                'timestamp': datetime.now().isoformat(),
                'type': 'analysis_error',
                'severity': 'low',
                'description': f'Error analyzing patterns: {str(e)}',
                'source': 'threat_detector',
                'status': 'detected'
            })
        
        return threats
    
    def get_threat_statistics(self):
        """Get statistics about detected threats"""
        try:
            if not self.detected_threats:
                return {
                    'total_threats': 0,
                    'by_type': {},
                    'by_severity': {},
                    'by_source': {}
                }
            
            # Count by type
            by_type = {}
            by_severity = {}
            by_source = {}
            
            for threat in self.detected_threats:
                # Count by type
                threat_type = threat.get('type', 'unknown')
                by_type[threat_type] = by_type.get(threat_type, 0) + 1
                
                # Count by severity
                severity = threat.get('severity', 'unknown')
                by_severity[severity] = by_severity.get(severity, 0) + 1
                
                # Count by source
                source = threat.get('source', 'unknown')
                by_source[source] = by_source.get(source, 0) + 1
            
            return {
                'total_threats': len(self.detected_threats),
                'by_type': by_type,
                'by_severity': by_severity,
                'by_source': by_source,
                'last_analysis': self.analysis_history[-1] if self.analysis_history else None
            }
            
        except Exception as e:
            return {
                'total_threats': 0,
                'error': str(e)
            }

    def _should_send_alert(self, alert_type):
        """Check if enough time has passed to send another alert of this type"""
        current_time = time.time()
        if alert_type not in self.last_alert_time:
            self.last_alert_time[alert_type] = current_time
            return True
        
        if current_time - self.last_alert_time[alert_type] >= self.alert_cooldown:
            self.last_alert_time[alert_type] = current_time
            return True
        
        return False
