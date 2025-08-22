# Configuration file for IT Security Dashboard
# Modify these settings according to your requirements

# Dashboard Configuration
DASHBOARD_CONFIG = {
    'host': '0.0.0.0',           # Dashboard host (0.0.0.0 for all interfaces)
    'port': 5000,                 # Dashboard port
    'debug': True,                 # Debug mode (set to False in production)
    'secret_key': 'your-secret-key-here',  # Change this in production
    'update_interval': 5,          # Data collection interval in seconds
    'max_data_points': 100,       # Maximum data points to keep in memory
    'max_log_entries': 200,       # Maximum log entries to keep
    'max_alerts': 1000            # Maximum alerts to keep in history
}

# Security Monitoring Configuration
SECURITY_CONFIG = {
    'alert_thresholds': {
        'cpu_usage': 80.0,        # CPU usage alert threshold (%)
        'memory_usage': 85.0,     # Memory usage alert threshold (%)
        'disk_usage': 90.0,       # Disk usage alert threshold (%)
        'network_connections': 1000, # Network connection threshold
        'failed_login_attempts': 5   # Failed login threshold
    },
    
    'threat_patterns': {
        'brute_force': {
            'failed_logins_threshold': 5,
            'time_window_minutes': 10,
            'severity': 'high'
        },
        'resource_abuse': {
            'cpu_threshold': 90,
            'memory_threshold': 95,
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
}

# Alert Configuration
ALERT_CONFIG = {
    'alert_rules': {
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
    },
    
    'severity_levels': {
        'low': {
            'priority': 1,
            'color': '#28a745',
            'icon': 'info-circle'
        },
        'medium': {
            'priority': 2,
            'color': '#ffc107',
            'icon': 'exclamation-triangle'
        },
        'high': {
            'priority': 3,
            'color': '#fd7e14',
            'icon': 'exclamation-circle'
        },
        'critical': {
            'priority': 4,
            'color': '#dc3545',
            'icon': 'times-circle'
        }
    }
}

# Data Collection Configuration
DATA_COLLECTION_CONFIG = {
    'system_metrics': {
        'enabled': True,
        'interval': 5,              # Collection interval in seconds
        'collect_processes': True,   # Collect process information
        'collect_users': True,       # Collect user session information
        'max_processes': 10          # Maximum processes to track
    },
    
    'network_traffic': {
        'enabled': True,
        'interval': 5,              # Collection interval in seconds
        'collect_interfaces': True,  # Collect network interface information
        'collect_connections': True, # Collect connection information
        'max_connections': 1000      # Maximum connections to track
    },
    
    'security_logs': {
        'enabled': True,
        'interval': 10,             # Collection interval in seconds
        'collect_system_logs': True, # Collect system-related logs
        'collect_security_logs': True, # Collect security-related logs
        'collect_network_logs': True,  # Collect network-related logs
        'max_log_entries': 200      # Maximum log entries to keep
    }
}

# Network Monitoring Configuration
NETWORK_CONFIG = {
    'suspicious_ports': {22, 23, 3389, 5900, 8080, 8443},  # SSH, Telnet, RDP, VNC, HTTP/HTTPS
    'monitor_local_ports': True,    # Monitor local listening ports
    'monitor_connections': True,    # Monitor active connections
    'connection_timeout': 300,      # Connection timeout in seconds
    'max_interface_speed': 1000     # Maximum interface speed in Mbps
}

# UI Configuration
UI_CONFIG = {
    'theme': 'default',             # Dashboard theme
    'refresh_rate': 5000,           # UI refresh rate in milliseconds
    'chart_animation': True,        # Enable chart animations
    'real_time_updates': True,      # Enable real-time updates
    'max_chart_data_points': 20,    # Maximum data points in charts
    'toast_notifications': True,    # Enable toast notifications
    'auto_refresh': True            # Enable automatic page refresh
}

# Logging Configuration
LOGGING_CONFIG = {
    'level': 'INFO',                # Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    'file_logging': False,          # Enable file logging
    'log_file': 'security_dashboard.log',  # Log file name
    'max_file_size': 10,            # Maximum log file size in MB
    'backup_count': 5,              # Number of backup log files
    'console_logging': True,        # Enable console logging
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
}

# Performance Configuration
PERFORMANCE_CONFIG = {
    'enable_caching': True,         # Enable data caching
    'cache_ttl': 300,               # Cache time-to-live in seconds
    'max_memory_usage': 512,        # Maximum memory usage in MB
    'garbage_collection': True,     # Enable automatic garbage collection
    'gc_interval': 60,              # Garbage collection interval in seconds
    'optimize_charts': True,        # Optimize chart rendering
    'lazy_loading': True            # Enable lazy loading for large datasets
}

# Security Configuration
SECURITY_SETTINGS = {
    'enable_cors': True,            # Enable Cross-Origin Resource Sharing
    'allowed_origins': ['*'],       # Allowed CORS origins
    'rate_limiting': False,         # Enable rate limiting
    'max_requests_per_minute': 100, # Maximum requests per minute
    'session_timeout': 3600,        # Session timeout in seconds
    'secure_headers': True,         # Enable security headers
    'csrf_protection': False        # Enable CSRF protection
}

# Notification Configuration
NOTIFICATION_CONFIG = {
    'email': {
        'enabled': False,
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'username': 'your-email@gmail.com',
        'password': 'your-app-password',
        'use_tls': True
    },
    'sms': {
        'enabled': False,
        'provider': 'twilio',
        'account_sid': 'your-account-sid',
        'auth_token': 'your-auth-token',
        'from_number': 'your-twilio-number'
    },
    'webhook': {
        'enabled': False,
        'url': 'https://your-webhook-url.com/security-alerts',
        'method': 'POST',
        'headers': {'Content-Type': 'application/json'}
    }
}

# Export Configuration
EXPORT_CONFIG = {
    'formats': ['json', 'csv'],     # Supported export formats
    'max_export_size': 1000,        # Maximum records to export
    'include_sensitive_data': False, # Include sensitive data in exports
    'compression': False,            # Enable export compression
    'auto_export': False,            # Enable automatic export
    'export_interval': 3600         # Export interval in seconds
}

# Development Configuration
DEV_CONFIG = {
    'enable_debug_mode': True,      # Enable debug mode
    'show_error_details': True,     # Show detailed error information
    'enable_profiling': False,      # Enable performance profiling
    'log_sql_queries': False,       # Log SQL queries (if using database)
    'enable_test_endpoints': False, # Enable test endpoints
    'mock_data': False              # Use mock data for testing
}

