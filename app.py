from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
import json
import os
from datetime import datetime, timedelta
import random

# Import our security modules
from security_monitor import SecurityMonitor
from data_collectors import SystemCollector, NetworkCollector, LogCollector
from threat_detector import ThreatDetector
from alert_manager import AlertManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize security components
security_monitor = SecurityMonitor()
system_collector = SystemCollector()
network_collector = NetworkCollector()
log_collector = LogCollector()
threat_detector = ThreatDetector()
alert_manager = AlertManager()

# Global data storage
security_data = {
    'system_metrics': [],
    'network_traffic': [],
    'security_events': [],
    'threat_alerts': [],
    'response_metrics': []
}

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/security-status')
def get_security_status():
    """Get current security status overview"""
    return jsonify({
        'status': 'active',
        'last_update': datetime.now().isoformat(),
        'total_threats': len(security_data['threat_alerts']),
        'active_alerts': len([a for a in security_data['threat_alerts'] if a['status'] == 'active']),
        'system_health': security_monitor.get_system_health(),
        'network_status': security_monitor.get_network_status()
    })

@app.route('/api/metrics')
def get_metrics():
    """Get all security metrics"""
    return jsonify(security_data)

@app.route('/api/threats')
def get_threats():
    """Get threat information"""
    return jsonify(security_data['threat_alerts'])

@app.route('/api/threats/<threat_id>/acknowledge', methods=['POST'])
def acknowledge_threat(threat_id):
    """Acknowledge a threat"""
    try:
        threat = next((t for t in security_data['threat_alerts'] if t['id'] == threat_id), None)
        if threat:
            threat['status'] = 'acknowledged'
            threat['acknowledged_at'] = datetime.now().isoformat()
            socketio.emit('metrics_update', security_data)
            return jsonify({'success': True, 'message': 'Threat acknowledged'})
        return jsonify({'success': False, 'message': 'Threat not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/threats/<threat_id>/resolve', methods=['POST'])
def resolve_threat(threat_id):
    """Resolve a threat"""
    try:
        threat = next((t for t in security_data['threat_alerts'] if t['id'] == threat_id), None)
        if threat:
            threat['status'] = 'resolved'
            threat['resolved_at'] = datetime.now().isoformat()
            socketio.emit('metrics_update', security_data)
            return jsonify({'success': True, 'message': 'Threat resolved'})
        return jsonify({'success': False, 'message': 'Threat not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/threats/<threat_id>/escalate', methods=['POST'])
def escalate_threat(threat_id):
    """Escalate a threat"""
    try:
        threat = next((t for t in security_data['threat_alerts'] if t['id'] == threat_id), None)
        if threat:
            threat['status'] = 'escalated'
            threat['escalated_at'] = datetime.now().isoformat()
            socketio.emit('metrics_update', security_data)
            return jsonify({'success': True, 'message': 'Threat escalated'})
        return jsonify({'success': False, 'message': 'Threat not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/system-health')
def get_system_health():
    """Get system health metrics"""
    return jsonify(security_data['system_metrics'])

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    emit('status', {'data': 'Connected to Security Dashboard'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

def background_data_collection():
    """Background task for continuous data collection"""
    while True:
        try:
            # Collect system metrics
            system_data = system_collector.collect_metrics()
            security_data['system_metrics'].append(system_data)
            
            # Keep only last 100 entries
            if len(security_data['system_metrics']) > 100:
                security_data['system_metrics'] = security_data['system_metrics'][-100:]
            
            # Collect network data
            network_data = network_collector.collect_traffic()
            security_data['network_traffic'].append(network_data)
            
            if len(security_data['network_traffic']) > 100:
                security_data['network_traffic'] = security_data['network_traffic'][-100:]
            
            # Collect log data
            log_data = log_collector.collect_logs()
            if log_data:
                security_data['security_events'].extend(log_data)
                if len(security_data['security_events']) > 200:
                    security_data['security_events'] = security_data['security_events'][-200:]
            
            # Threat detection
            threats = threat_detector.analyze_data(security_data)
            if threats:
                for threat in threats:
                    alert = alert_manager.create_alert(threat)
                    security_data['threat_alerts'].append(alert)
                    # Emit real-time alert
                    socketio.emit('threat_alert', alert)
            
            # Emit updated metrics
            socketio.emit('metrics_update', security_data)
            
            time.sleep(5)  # Update every 5 seconds
            
        except Exception as e:
            print(f"Error in background collection: {e}")
            time.sleep(10)

def start_background_tasks():
    """Start background monitoring tasks"""
    data_thread = threading.Thread(target=background_data_collection, daemon=True)
    data_thread.start()

if __name__ == '__main__':
    start_background_tasks()
    print("🚀 Security Dashboard starting...")
    print("📊 Dashboard available at: http://localhost:5000")
    print("🔒 Monitoring IT infrastructure security...")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)

