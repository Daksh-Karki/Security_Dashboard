import time
import json
from datetime import datetime, timedelta
import random

class AlertManager:
    """Manages security alerts and notifications"""
    
    def __init__(self):
        self.alerts = []
        self.alert_history = []
        self.alert_rules = {
            'resource_abuse': {
                'auto_resolve': True,
                'resolve_threshold': 70,  # Auto-resolve when resource usage drops below this
                'escalation_time': 300,   # Escalate after 5 minutes
                'notification_channels': ['dashboard', 'log']
            },
            'network_anomaly': {
                'auto_resolve': False,
                'escalation_time': 180,   # Escalate after 3 minutes
                'notification_channels': ['dashboard', 'log', 'email']
            },
            'brute_force': {
                'auto_resolve': False,
                'escalation_time': 60,    # Escalate after 1 minute
                'notification_channels': ['dashboard', 'log', 'email', 'sms']
            },
            'security_event': {
                'auto_resolve': False,
                'escalation_time': 120,   # Escalate after 2 minutes
                'notification_channels': ['dashboard', 'log', 'email']
            }
        }
        
        self.severity_levels = {
            'low': {'priority': 1, 'color': '#28a745', 'icon': 'info-circle'},
            'medium': {'priority': 2, 'color': '#ffc107', 'icon': 'exclamation-triangle'},
            'high': {'priority': 3, 'color': '#fd7e14', 'icon': 'exclamation-circle'},
            'critical': {'priority': 4, 'color': '#dc3545', 'icon': 'times-circle'}
        }
        
    def create_alert(self, threat):
        """Create a new security alert from a detected threat"""
        try:
            alert_id = f"alert_{int(time.time())}_{random.randint(1000, 9999)}"
            
            alert = {
                'id': alert_id,
                'threat_id': threat.get('id'),
                'timestamp': datetime.now().isoformat(),
                'type': threat.get('type', 'unknown'),
                'severity': threat.get('severity', 'medium'),
                'description': threat.get('description', 'Unknown threat detected'),
                'source': threat.get('source', 'unknown'),
                'status': 'active',
                'details': threat.get('details', {}),
                'priority': self.severity_levels.get(threat.get('severity', 'medium'), {}).get('priority', 1),
                'color': self.severity_levels.get(threat.get('severity', 'medium'), {}).get('color', '#6c757d'),
                'icon': self.severity_levels.get(threat.get('severity', 'medium'), {}).get('icon', 'question-circle'),
                'escalation_time': datetime.now() + timedelta(seconds=self.alert_rules.get(threat.get('type', 'unknown'), {}).get('escalation_time', 300)),
                'auto_resolve': self.alert_rules.get(threat.get('type', 'unknown'), {}).get('auto_resolve', False),
                'notification_channels': self.alert_rules.get(threat.get('type', 'unknown'), {}).get('notification_channels', ['dashboard']),
                'acknowledged': False,
                'acknowledged_by': None,
                'acknowledged_at': None,
                'resolved': False,
                'resolved_at': None,
                'resolution_notes': None
            }
            
            # Add to active alerts
            self.alerts.append(alert)
            
            # Add to history
            self.alert_history.append(alert.copy())
            
            # Keep only last 1000 alerts in history
            if len(self.alert_history) > 1000:
                self.alert_history = self.alert_history[-1000:]
            
            print(f"🚨 New alert created: {alert['description']} (Severity: {alert['severity']})")
            
            return alert
            
        except Exception as e:
            print(f"Error creating alert: {e}")
            return None
    
    def acknowledge_alert(self, alert_id, user):
        """Acknowledge an alert"""
        try:
            alert = self._find_alert(alert_id)
            if alert:
                alert['acknowledged'] = True
                alert['acknowledged_by'] = user
                alert['acknowledged_at'] = datetime.now().isoformat()
                print(f"✅ Alert {alert_id} acknowledged by {user}")
                return True
            return False
        except Exception as e:
            print(f"Error acknowledging alert: {e}")
            return False
    
    def resolve_alert(self, alert_id, user, notes=None):
        """Resolve an alert"""
        try:
            alert = self._find_alert(alert_id)
            if alert:
                alert['resolved'] = True
                alert['resolved_at'] = datetime.now().isoformat()
                alert['resolution_notes'] = notes
                alert['status'] = 'resolved'
                
                # Move to history and remove from active alerts
                self.alerts.remove(alert)
                
                print(f"✅ Alert {alert_id} resolved by {user}")
                return True
            return False
        except Exception as e:
            print(f"Error resolving alert: {e}")
            return False
    
    def escalate_alert(self, alert_id):
        """Escalate an alert"""
        try:
            alert = self._find_alert(alert_id)
            if alert and alert['status'] == 'active':
                alert['status'] = 'escalated'
                alert['escalation_time'] = datetime.now().isoformat()
                print(f"⚠️ Alert {alert_id} escalated")
                return True
            return False
        except Exception as e:
            print(f"Error escalating alert: {e}")
            return False
    
    def auto_resolve_alerts(self, current_metrics):
        """Automatically resolve alerts based on current system state"""
        try:
            resolved_count = 0
            
            for alert in self.alerts[:]:  # Copy list to avoid modification during iteration
                if not alert['auto_resolve']:
                    continue
                
                if alert['type'] == 'resource_abuse':
                    # Check if resource usage has dropped below threshold
                    if self._check_resource_resolution(alert, current_metrics):
                        self.resolve_alert(alert['id'], 'system_auto_resolve', 'Resource usage normalized')
                        resolved_count += 1
                
                elif alert['type'] == 'network_anomaly':
                    # Check if network activity has normalized
                    if self._check_network_resolution(alert, current_metrics):
                        self.resolve_alert(alert['id'], 'system_auto_resolve', 'Network activity normalized')
                        resolved_count += 1
            
            if resolved_count > 0:
                print(f"🔄 Auto-resolved {resolved_count} alerts")
                
        except Exception as e:
            print(f"Error in auto-resolve: {e}")
    
    def _check_resource_resolution(self, alert, current_metrics):
        """Check if resource abuse alert should be auto-resolved"""
        try:
            if not current_metrics.get('system_metrics'):
                return False
            
            latest_metrics = current_metrics['system_metrics'][-1]
            threshold = self.alert_rules['resource_abuse']['resolve_threshold']
            
            # Check CPU usage
            if alert['description'].startswith('High CPU usage'):
                current_cpu = latest_metrics.get('cpu', {}).get('usage_percent', 0)
                return current_cpu < threshold
            
            # Check memory usage
            elif alert['description'].startswith('High memory usage'):
                current_memory = latest_metrics.get('memory', {}).get('usage_percent', 0)
                return current_memory < threshold
            
            # Check disk usage
            elif alert['description'].startswith('High disk usage'):
                current_disk = latest_metrics.get('disk', {}).get('usage_percent', 0)
                return current_disk < threshold
            
            return False
            
        except Exception as e:
            print(f"Error checking resource resolution: {e}")
            return False
    
    def _check_network_resolution(self, alert, current_metrics):
        """Check if network anomaly alert should be auto-resolved"""
        try:
            if not current_metrics.get('network_traffic'):
                return False
            
            latest_network = current_metrics['network_traffic'][-1]
            
            # Check connection count
            if alert['description'].startswith('Excessive network connections'):
                current_connections = latest_network.get('connections', {}).get('total', 0)
                return current_connections < 1000  # Below threshold
            
            # Check listening ports
            elif alert['description'].startswith('High number of listening ports'):
                current_listening = latest_network.get('connections', {}).get('by_status', {}).get('listening', 0)
                return current_listening < 30  # Below threshold
            
            return False
            
        except Exception as e:
            print(f"Error checking network resolution: {e}")
            return False
    
    def _find_alert(self, alert_id):
        """Find an alert by ID"""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                return alert
        return None
    
    def get_active_alerts(self):
        """Get all active alerts"""
        return [alert for alert in self.alerts if alert['status'] == 'active']
    
    def get_alerts_by_severity(self, severity):
        """Get alerts filtered by severity"""
        return [alert for alert in self.alerts if alert['severity'] == severity]
    
    def get_alerts_by_type(self, alert_type):
        """Get alerts filtered by type"""
        return [alert for alert in self.alerts if alert['type'] == alert_type]
    
    def get_alert_statistics(self):
        """Get statistics about alerts"""
        try:
            total_alerts = len(self.alerts)
            active_alerts = len([a for a in self.alerts if a['status'] == 'active'])
            escalated_alerts = len([a for a in self.alerts if a['status'] == 'escalated'])
            
            # Count by severity
            severity_counts = {}
            for alert in self.alerts:
                severity = alert['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by type
            type_counts = {}
            for alert in self.alerts:
                alert_type = alert['type']
                type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
            
            # Count by status
            status_counts = {}
            for alert in self.alerts:
                status = alert['status']
                status_counts[status] = status_counts.get(status, 0) + 1
            
            return {
                'total_alerts': total_alerts,
                'active_alerts': active_alerts,
                'escalated_alerts': escalated_alerts,
                'by_severity': severity_counts,
                'by_type': type_counts,
                'by_status': status_counts,
                'total_history': len(self.alert_history)
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'total_alerts': 0
            }
    
    def cleanup_old_alerts(self, days=30):
        """Clean up old alerts from history"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            original_count = len(self.alert_history)
            
            self.alert_history = [
                alert for alert in self.alert_history
                if datetime.fromisoformat(alert['timestamp']) > cutoff_date
            ]
            
            removed_count = original_count - len(self.alert_history)
            if removed_count > 0:
                print(f"🧹 Cleaned up {removed_count} old alerts from history")
                
        except Exception as e:
            print(f"Error cleaning up old alerts: {e}")
    
    def export_alerts(self, format='json'):
        """Export alerts to different formats"""
        try:
            if format.lower() == 'json':
                return json.dumps(self.alerts, indent=2, default=str)
            elif format.lower() == 'csv':
                # Simple CSV export
                if not self.alerts:
                    return "No alerts to export"
                
                headers = list(self.alerts[0].keys())
                csv_lines = [','.join(headers)]
                
                for alert in self.alerts:
                    row = [str(alert.get(header, '')) for header in headers]
                    csv_lines.append(','.join(row))
                
                return '\n'.join(csv_lines)
            else:
                return "Unsupported format. Use 'json' or 'csv'"
                
        except Exception as e:
            return f"Error exporting alerts: {str(e)}"

