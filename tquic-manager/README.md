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

The web interface is available at `http://127.0.0.1:5000` by default.

To bind on a different interface:
```bash
export TQUIC_MANAGER_BIND=0.0.0.0
export TQUIC_MANAGER_PORT=5000
```

## Requirements

- Python 3.8+
- Flask
- Root/sudo access for sysctl modifications

## Security Notes

- By default, setting changes are only accepted from localhost.
- For remote writes, set `TQUIC_MANAGER_ALLOW_REMOTE_WRITE=1` or configure
  `TQUIC_MANAGER_API_TOKEN` and send `Authorization: Bearer <token>`.
