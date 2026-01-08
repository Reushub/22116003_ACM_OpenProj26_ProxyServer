# ACM_Open_Project_26_ProxyServer

  Drive Link for video and transcript : https://drive.google.com/drive/folders/119iMOvudhWoHmU1cLAHQHjOJbWYzFHa8?usp=drive_link

## Features

- **HTTP and HTTPS** support using standard HTTP requests and `CONNECT` tunneling.
- Domain blocking via a configurable `config/blocked_domains.txt` file with wildcard support such as `*.example.com`.
- Loop detection to prevent proxying requests back through the same proxy (`localhost`, `127.0.0.1`, etc.).
- Request safety limits for headers and body (default maximum body size: 100 MB).
- Rotating file logs using `logging.handlers.RotatingFileHandler` with configurable size and backup count.
- Structured per-request logging: timestamp, client, target, action, status, bytes transferred, and latency.
- Multithreaded: one thread per client connection.

## Requirements

- Python 3.8 or newer.
- Only standard library modules:
  - `socket`, `select`, `threading`
  - `logging`, `logging.handlers`
  - `sys`, `signal`, `time`, `datetime`, `pathlib`

## Configuration

At the top of the script you can adjust:

- **Host and port**
  - `HOST = '127.0.0.1'`
  - `PORT = 8888`
  - Set `HOST = '0.0.0.0'` to accept connections from other machines.

- **Limits and timeouts**
  - `BUFFER_SIZE = 8192` – socket buffer size.
  - `TIMEOUT = 20` – per-connection timeout in seconds.
  - `MAX_BODY_SIZE = 100 * 1024 * 1024` – maximum request body size (100 MB).

- **Logging**
  - `LOG_FILE = 'logs/proxy.log'` – main log file (directory created automatically).
  - `MAX_LOG_SIZE = 10 * 1024 * 1024` – rotate when log exceeds 10 MB.
  - `LOG_BACKUP_COUNT = 5` – keep up to 5 rotated log files.
  - Logs go both to file and to stdout (console).

- **Blocked domains**
  - `BLOCKED_FILE = 'config/blocked_domains.txt'`
  - One entry per line; lines starting with `#` are comments.
  - Supported patterns:
    - Exact domains, e.g. `example.com`
    - Wildcards, e.g. `*.example.com` for all subdomains


