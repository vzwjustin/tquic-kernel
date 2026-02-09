# TQUIC Manager

A modern web-based interface for managing TQUIC kernel settings.

## Features

- Real-time monitoring of TQUIC status
- Easy enable/disable toggle
- Configure all TQUIC sysctl parameters
- View loaded congestion control modules
- Modern, responsive UI

## Quick Start

### Start the Manager
```bash
./scripts/start.sh
```

### Stop the Manager
```bash
./scripts/stop.sh
```

The web interface will be available at `http://<server-ip>:5000`

## Requirements

- Python 3.8+
- Flask
- Root/sudo access for sysctl modifications
