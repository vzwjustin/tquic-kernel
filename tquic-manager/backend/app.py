#!/usr/bin/env python3
"""
TQUIC Manager Backend API
Provides REST endpoints for managing TQUIC kernel settings
"""

from flask import Flask, jsonify, request, send_from_directory
import subprocess
import re
import os
import hmac

# Get the directory paths
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
FRONTEND_DIR = os.path.join(PROJECT_DIR, 'frontend')

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')

def run_command(args):
    """Execute a command and return combined output plus return code."""
    try:
        result = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=5
        )
        output = (result.stdout or "").strip()
        err = (result.stderr or "").strip()
        if output and err:
            output = f"{output}\n{err}"
        elif err:
            output = err
        return output, result.returncode
    except subprocess.TimeoutExpired:
        return "", -1

def is_loopback_request():
    """Check whether the request is from localhost."""
    return request.remote_addr in ('127.0.0.1', '::1')

def authorize_write_request():
    """Authorize settings mutation requests."""
    token = os.environ.get('TQUIC_MANAGER_API_TOKEN', '').strip()
    if token:
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return False, 'Missing bearer token'
        presented = auth[len('Bearer '):].strip()
        if not hmac.compare_digest(presented, token):
            return False, 'Invalid bearer token'
        return True, ''

    allow_remote = os.environ.get('TQUIC_MANAGER_ALLOW_REMOTE_WRITE', '0') == '1'
    if allow_remote or is_loopback_request():
        return True, ''

    return False, 'Remote write disabled; use localhost or configure token'

def get_tquic_settings():
    """Get all TQUIC sysctl settings"""
    output, code = run_command(["sysctl", "-a"])
    if code != 0:
        return {}
    
    settings = {}
    for line in output.split('\n'):
        if not line.startswith('net.tquic.'):
            continue
        if '=' in line:
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()
            # Try to convert to appropriate type
            if value.isdigit():
                value = int(value)
            elif value.replace('.', '', 1).isdigit():
                value = float(value)
            settings[key] = value
    
    return settings

def get_tquic_modules():
    """Get loaded TQUIC modules"""
    output, code = run_command(["lsmod"])
    if code != 0:
        return []
    
    modules = []
    for line in output.split('\n'):
        if line.strip():
            parts = line.split()
            if len(parts) >= 3 and 'tquic' in parts[0]:
                modules.append({
                    'name': parts[0],
                    'size': parts[1],
                    'used_by': parts[2]
                })
    
    return modules

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current TQUIC status and all settings"""
    settings = get_tquic_settings()
    modules = get_tquic_modules()
    
    return jsonify({
        'success': True,
        'settings': settings,
        'modules': modules,
        'enabled': settings.get('net.tquic.enabled', 0) == 1
    })

@app.route('/api/modules', methods=['GET'])
def get_modules():
    """Get loaded TQUIC modules"""
    modules = get_tquic_modules()
    return jsonify({
        'success': True,
        'modules': modules
    })

@app.route('/api/settings', methods=['POST'])
def update_setting():
    """Update a single TQUIC setting"""
    data = request.get_json()
    
    if not data or 'key' not in data or 'value' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing key or value'
        }), 400
    
    key = data['key']
    value = data['value']

    authorized, auth_error = authorize_write_request()
    if not authorized:
        return jsonify({
            'success': False,
            'error': auth_error
        }), 403
    
    # Validate key starts with net.tquic.
    if not isinstance(key, str) or not re.fullmatch(r'net\.tquic\.[A-Za-z0-9_.-]+', key):
        return jsonify({
            'success': False,
            'error': 'Invalid key - must start with net.tquic.'
        }), 400

    value_str = str(value).strip()
    if not value_str or len(value_str) > 128:
        return jsonify({
            'success': False,
            'error': 'Invalid value length'
        }), 400
    if re.search(r'[\x00-\x1f\x7f]', value_str):
        return jsonify({
            'success': False,
            'error': 'Invalid value characters'
        }), 400
    
    # Set the sysctl value
    output, code = run_command(["sysctl", "-w", f"{key}={value_str}"])
    
    if code != 0:
        return jsonify({
            'success': False,
            'error': f'Failed to set {key}: {output}'
        }), 500
    
    return jsonify({
        'success': True,
        'key': key,
        'value': value
    })

@app.route('/api/toggle', methods=['POST'])
def toggle_tquic():
    """Enable or disable TQUIC"""
    data = request.get_json()
    
    if not data or 'enabled' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing enabled parameter'
        }), 400

    authorized, auth_error = authorize_write_request()
    if not authorized:
        return jsonify({
            'success': False,
            'error': auth_error
        }), 403
    
    enabled = 1 if data['enabled'] else 0
    
    output, code = run_command(["sysctl", "-w", f"net.tquic.enabled={enabled}"])
    
    if code != 0:
        return jsonify({
            'success': False,
            'error': f'Failed to toggle TQUIC: {output}'
        }), 500
    
    return jsonify({
        'success': True,
        'enabled': enabled == 1
    })

@app.route('/')
def index():
    """Serve the main frontend page"""
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'status': 'healthy'
    })

if __name__ == '__main__':
    # Check if running as root
    if os.geteuid() != 0:
        print("WARNING: Not running as root. sysctl modifications may fail.")
        print("Consider running with: sudo python3 app.py")
    
    bind_host = os.environ.get('TQUIC_MANAGER_BIND', '127.0.0.1')
    try:
        bind_port = int(os.environ.get('TQUIC_MANAGER_PORT', '5000'))
    except ValueError:
        bind_port = 5000
    app.run(host=bind_host, port=bind_port, debug=False)
