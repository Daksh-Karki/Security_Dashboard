# 🚀 IT Security Dashboard

A comprehensive, real-time Python dashboard for monitoring IT infrastructure security with integrated threat detection, alerting, and visualization capabilities.

## ✨ Features

### 🔒 **Real-time Security Monitoring**
- **System Health Tracking**: CPU, memory, disk usage monitoring
- **Network Security**: Traffic analysis, connection monitoring, port scanning detection
- **Process Monitoring**: Suspicious process detection and resource abuse prevention
- **User Session Tracking**: Active user monitoring and authentication events

### 🚨 **Advanced Threat Detection**
- **Resource Abuse Detection**: High CPU/memory/disk usage alerts
- **Network Anomaly Detection**: Excessive connections, port scanning, traffic spikes
- **Brute Force Detection**: Failed login attempt monitoring
- **Pattern Analysis**: Historical trend analysis for threat identification

### 📊 **Interactive Visualizations**
- **Real-time Charts**: Live performance trends and threat distribution
- **System Metrics**: CPU, memory, and disk usage visualizations
- **Network Analytics**: Traffic patterns and connection status
- **Alert Dashboard**: Severity-based alert categorization and management

### 🔔 **Smart Alerting System**
- **Multi-level Severity**: Low, Medium, High, Critical threat levels
- **Auto-resolution**: Automatic threat resolution for transient issues
- **Escalation Rules**: Configurable alert escalation policies
- **Notification Channels**: Dashboard, logs, email, and SMS support

### 🌐 **Modern Web Interface**
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Real-time Updates**: WebSocket-based live data streaming
- **Interactive Navigation**: Tabbed interface for different security aspects
- **Modern UI/UX**: Bootstrap 5 with custom styling and animations

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- Windows 10/11 (tested on Windows 10.0.26100)
- Administrator privileges (for system monitoring)

### Step 1: Clone or Download
```bash
# If using git
git clone <repository-url>
cd Cyber_Dashboard

# Or download and extract the ZIP file
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run the Dashboard
```bash
python app.py
```

### Step 4: Access Dashboard
Open your web browser and navigate to:
```
http://localhost:5000
```

## 📁 Project Structure

```
Cyber_Dashboard/
├── app.py                 # Main Flask application
├── security_monitor.py    # Core security monitoring engine
├── data_collectors.py     # System, network, and log data collection
├── threat_detector.py     # Advanced threat detection algorithms
├── alert_manager.py       # Alert management and notification system
├── templates/
│   └── dashboard.html     # Modern web dashboard interface
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🔧 Configuration

### Alert Thresholds
Modify thresholds in `security_monitor.py`:
```python
self.alert_thresholds = {
    'cpu_usage': 80.0,        # CPU usage alert threshold
    'memory_usage': 85.0,     # Memory usage alert threshold
    'disk_usage': 90.0,       # Disk usage alert threshold
    'network_connections': 1000, # Network connection threshold
    'failed_login_attempts': 5   # Failed login threshold
}
```

### Threat Detection Rules
Configure threat patterns in `threat_detector.py`:
```python
self.threat_patterns = {
    'brute_force': {
        'failed_logins_threshold': 5,
        'time_window_minutes': 10,
        'severity': 'high'
    },
    # ... more patterns
}
```

### Alert Rules
Customize alert behavior in `alert_manager.py`:
```python
self.alert_rules = {
    'resource_abuse': {
        'auto_resolve': True,
        'resolve_threshold': 70,
        'escalation_time': 300,
        'notification_channels': ['dashboard', 'log']
    },
    # ... more rules
}
```

## 📊 Dashboard Sections

### 1. **Overview Dashboard**
- System health score
- Active threat count
- Real-time performance metrics
- Performance trend charts
- Recent security alerts

### 2. **Threats Section**
- Active security threats
- Threat severity distribution
- Threat type categorization
- Threat source analysis

### 3. **System Section**
- CPU and memory usage charts
- Disk usage visualization
- Top memory-consuming processes
- System resource trends

### 4. **Network Section**
- Network traffic patterns
- Connection status distribution
- Network interface information
- Traffic anomaly detection

### 5. **Logs Section**
- Security event logs
- Event severity levels
- Real-time log streaming
- Log source categorization

## 🚨 Security Features

### **Real-time Monitoring**
- Continuous system metric collection (every 5 seconds)
- Live network traffic analysis
- Real-time security event processing
- Instant threat detection and alerting

### **Threat Intelligence**
- Pattern-based threat detection
- Historical trend analysis
- Anomaly identification
- Risk scoring and prioritization

### **Automated Response**
- Auto-resolution of transient threats
- Configurable escalation policies
- Alert acknowledgment workflows
- Threat lifecycle management

## 🔍 Monitoring Capabilities

### **System Resources**
- CPU utilization and frequency
- Memory usage and swap status
- Disk space and I/O operations
- Process count and memory usage

### **Network Security**
- Active network connections
- Listening ports and services
- Network interface status
- Traffic patterns and anomalies

### **Security Events**
- Authentication attempts
- System resource warnings
- Network security alerts
- Process behavior monitoring

## 🎨 UI/UX Features

### **Modern Design**
- Glassmorphism design elements
- Responsive Bootstrap 5 framework
- Custom CSS animations and transitions
- Professional color scheme

### **Interactive Elements**
- Real-time data updates
- Interactive charts and graphs
- Toast notifications for alerts
- Smooth navigation transitions

### **Accessibility**
- Responsive design for all devices
- High contrast color schemes
- Clear visual hierarchy
- Intuitive navigation

## 🚀 Performance Features

### **Efficient Data Collection**
- Optimized data collection intervals
- Memory-efficient data storage
- Background processing
- Real-time data streaming

### **Scalable Architecture**
- Modular component design
- Configurable monitoring parameters
- Extensible threat detection
- Plugin-ready architecture

## 🔧 Troubleshooting

### **Common Issues**

1. **Permission Errors**
   - Run as Administrator
   - Check Windows Defender settings
   - Verify firewall permissions

2. **Port Already in Use**
   - Change port in `app.py`
   - Check for other services using port 5000

3. **Missing Dependencies**
   - Verify Python version (3.8+)
   - Reinstall requirements: `pip install -r requirements.txt`

4. **Dashboard Not Loading**
   - Check console for error messages
   - Verify all modules are imported correctly
   - Check browser console for JavaScript errors

### **Performance Tuning**

1. **Reduce Update Frequency**
   - Modify sleep intervals in background tasks
   - Adjust data collection intervals

2. **Memory Optimization**
   - Reduce data retention periods
   - Limit chart data points

3. **Network Monitoring**
   - Adjust connection thresholds
   - Configure network interface filters

## 🔮 Future Enhancements

### **Planned Features**
- Machine learning threat detection
- Integration with SIEM systems
- Advanced reporting and analytics
- Mobile app development
- Multi-tenant support

### **Integration Possibilities**
- Active Directory integration
- SIEM system connectors
- Cloud security monitoring
- IoT device security
- Container security monitoring

## 📝 License

This project is developed for educational and professional use. Please ensure compliance with your organization's security policies and local regulations.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 📞 Support

For support or questions:
1. Check the troubleshooting section
2. Review console error messages
3. Verify system requirements
4. Check Windows event logs

---

**⚠️ Security Notice**: This dashboard provides security monitoring capabilities. Ensure proper access controls and network security measures are in place before deployment in production environments.

**🔒 Privacy**: The dashboard collects system metrics and security data. Review data collection practices and ensure compliance with privacy regulations.

