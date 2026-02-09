#!/usr/bin/env python3
"""
TQUIC Manager Backend API
Provides REST endpoints for managing TQUIC kernel settings
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import subprocess
import re
import os

# Get the directory paths
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
FRONTEND_DIR = os.path.join(PROJECT_DIR, 'frontend')

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')
CORS(app)

def run_command(cmd):
    """Execute a shell command and return output"""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True,
            timeout=5
        )
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", -1

def get_tquic_settings():
    """Get all TQUIC sysctl settings"""
    output, code = run_command("sysctl -a 2>/dev/null | grep '^net.tquic.'")
    if code != 0:
        return {}
    
    settings = {}
    for line in output.split('\n'):
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
    output, code = run_command("lsmod | grep tquic")
    if code != 0:
        return []
    
    modules = []
    for line in output.split('\n'):
        if line.strip():
            parts = line.split()
            if len(parts) >= 3:
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
    
    # Validate key starts with net.tquic.
    if not key.startswith('net.tquic.'):
        return jsonify({
            'success': False,
            'error': 'Invalid key - must start with net.tquic.'
        }), 400
    
    # Set the sysctl value
    cmd = f"sysctl -w {key}={value}"
    output, code = run_command(cmd)
    
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
    
    enabled = 1 if data['enabled'] else 0
    
    cmd = f"sysctl -w net.tquic.enabled={enabled}"
    output, code = run_command(cmd)
    
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
    
    app.run(host='0.0.0.0', port=5000, debug=False)
