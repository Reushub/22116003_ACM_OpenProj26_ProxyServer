import socket
import threading
import logging
from logging.handlers import RotatingFileHandler
import sys
import signal
import time
from datetime import datetime
from pathlib import Path


HOST = '127.0.0.1'  # Localhost only can be changed according to neec
PORT = 8888
BUFFER_SIZE = 8192
TIMEOUT = 20
MAX_BODY_SIZE = 100 * 1024 * 1024  

# File paths
LOG_FILE = 'logs/proxy.log'
BLOCKED_FILE = 'config/blocked_domains.txt'

# Log rotation settings
MAX_LOG_SIZE = 10 * 1024 * 1024 
LOG_BACKUP_COUNT = 5              

# Logging setup
Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)

# File handler with rotation
file_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=MAX_LOG_SIZE,
    backupCount=LOG_BACKUP_COUNT
)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(
    logging.Formatter('%(message)s') 
)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(
    logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
)

# Configure root logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)



class ProxyServer:
    def __init__(self):
        self.running = False
        self.blocked = self.load_blocked_domains()
        self.stats = {
            'total': 0,
            'blocked': 0,
            'allowed': 0,
            'loops': 0,
            'errors': 0
        }
        
        # Loop detection
        self.own_addresses = {'localhost', '127.0.0.1', '::1'}
        try:
            hostname = socket.gethostname()
            self.own_addresses.add(socket.gethostbyname(hostname))
        except:
            pass
        
        logging.info(f"Proxy initialized - Log rotation: {MAX_LOG_SIZE/(1024*1024):.0f}MB × {LOG_BACKUP_COUNT} files")
    
    def load_blocked_domains(self):

        blocked = set()
        
        if Path(BLOCKED_FILE).exists():
            with open(BLOCKED_FILE, 'r') as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith('#'):
                        blocked.add(line)
            logging.info(f"Loaded {len(blocked)} blocked domains")
        return blocked
    
    def is_blocked(self, host):
        host = host.lower()
        
        if host in self.blocked:
            return True

        for blocked in self.blocked:
            if blocked.startswith('*.') and host.endswith(blocked[2:]):
                return True
                
        return False
    
    def is_loop(self, host, port):
        return host.lower() in self.own_addresses and port == PORT
    
    def read_request(self, client):

        header_data = b''
        while b'\r\n\r\n' not in header_data:
            chunk = client.recv(BUFFER_SIZE)
            if not chunk:
                raise ConnectionError("Client disconnected")
            header_data += chunk
            if len(header_data) > 100000:  
                raise ValueError("Headers too large")
        
        header_end = header_data.index(b'\r\n\r\n') + 4
        headers_only = header_data[:header_end]
        body_received = header_data[header_end:]

        headers = {}
        lines = header_data.split(b'\r\n')
        request_line = lines[0].decode('utf-8', errors='ignore')
        
        for line in lines[1:]:
            if not line:
                break
            line_str = line.decode('utf-8', errors='ignore')
            if ':' in line_str:
                key, val = line_str.split(':', 1)
                headers[key.strip().lower()] = val.strip()
        
        parts = request_line.split()
        method = parts[0] if parts else 'UNKNOWN'
        
        content_length = 0
        if 'content-length' in headers:
            try:
                content_length = int(headers['content-length'])
                if content_length < 0:
                    raise ValueError("Negative Content-Length")
                if content_length > MAX_BODY_SIZE:
                    raise ValueError(f"Body too large: {content_length} bytes")
            except ValueError as e:
                raise ValueError(f"Invalid Content-Length: {e}")
        
        body = body_received
        while len(body) < content_length:
            remaining = content_length - len(body)
            chunk = client.recv(min(BUFFER_SIZE, remaining))
            if not chunk:
                raise ConnectionError(
                    f"Connection closed. Got {len(body)}/{content_length} bytes"
                )
            body += chunk
   
        complete_request = headers_only + body
        return complete_request, headers, method, content_length
    
    def parse_request(self, data):
        lines = data.split(b'\r\n')
        request_line = lines[0].decode('utf-8', errors='ignore')
        parts = request_line.split()
        
        if len(parts) < 2:
            return None, None, None, None
        
        method, uri = parts[0], parts[1]
        host, port = None, 80
        
        headers = {}
        for line in lines[1:]:
            if not line:
                break
            line_str = line.decode('utf-8', errors='ignore')
            if ':' in line_str:
                key, val = line_str.split(':', 1)
                headers[key.strip().lower()] = val.strip()
        
        if uri.startswith('http://'):
            uri = uri[7:]
            if '/' in uri:
                host = uri[:uri.index('/')]
            else:
                host = uri
            if ':' in host:
                host, port = host.rsplit(':', 1)
                port = int(port)
        elif uri.startswith('https://'):
            port = 443
            uri = uri[8:]
            if '/' in uri:
                host = uri[:uri.index('/')]
            else:
                host = uri
            if ':' in host:
                host, port = host.rsplit(':', 1)
                port = int(port)
        elif 'host' in headers:
            host = headers['host']
            if ':' in host:
                host, port = host.rsplit(':', 1)
                port = int(port)
        
        if method == 'CONNECT' and ':' in uri:
            host, port = uri.rsplit(':', 1)
            port = int(port)
        
        return method, host, port, data
    
    def send_error(self, sock, code, message):
        response = f"HTTP/1.1 {code} {message}\r\n"
        response += "Connection: close\r\n\r\n"
        response += f"<html><body><h1>{code} {message}</h1></body></html>"
        try:
            sock.sendall(response.encode())
        except:
            pass
    
    def handle_connect(self, client, host, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.settimeout(TIMEOUT)
            server.connect((host, port))
            
            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            import select
            client.setblocking(False)
            server.setblocking(False)
            sockets = [client, server]
            
            total_bytes = 0
            
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 1)
                if exceptional:
                    break
                
                for sock in readable:
                    try:
                        data = sock.recv(BUFFER_SIZE)
                        if not data:
                            return total_bytes
                        
                        if sock is client:
                            server.sendall(data)
                        else:
                            client.sendall(data)
                        
                        total_bytes += len(data)
                    except:
                        return total_bytes
            
            return total_bytes
        except:
            self.send_error(client, 502, "Bad Gateway")
            return 0
    
    def handle_http(self, client, request, host, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.settimeout(TIMEOUT)
            server.connect((host, port))
            
            server.sendall(request)
            
            total_bytes = 0
            status_code = None
            first_line = True
            
            while True:
                data = server.recv(BUFFER_SIZE)
                if not data:
                    break
                
                if first_line and b'\r\n' in data:
                    response_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                    parts = response_line.split()
                    if len(parts) >= 2 and parts[0].startswith('HTTP/'):
                        try:
                            status_code = int(parts[1])
                        except:
                            pass
                    first_line = False
                
                client.sendall(data)
                total_bytes += len(data)
            
            server.close()
            return (status_code or 200, total_bytes)
        
        except:
            self.send_error(client, 502, "Bad Gateway")
            return (502, 0)
    
    def log_request(self, client_ip, client_port, host, port, request_line, action, status_code, bytes_transferred, elapsed_time):

        log_entry = (
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
            f"{client_ip}:{client_port} | {host}:{port} | "
            f"{request_line[:60]} | {action} | {status_code or '-'} | "
            f"{bytes_transferred}B | {elapsed_time:.2f}s"
        )
        
        if action in ["ERROR", "TIMEOUT", "LOOP_DETECTED"]:
            logging.error(log_entry)
        elif action == "BLOCKED":
            logging.warning(log_entry)
        else:
            logging.info(log_entry)
    
    def handle_client(self, client, addr):
        client.settimeout(TIMEOUT)
        
        start_time = time.time()
        bytes_transferred = 0
        action = "UNKNOWN"
        status_code = None
        request_line = ""
        host = "UNKNOWN"
        port = 0
        
        try:
            request, headers, method, content_length = self.read_request(client)
            
            request_line = request.split(b'\r\n')[0].decode('utf-8', errors='ignore')
            
            method, host, port, _ = self.parse_request(request)
            
            if not host:
                action = "REJECTED"
                status_code = 400
                self.send_error(client, 400, "Bad Request")
                return
            
            self.stats['total'] += 1
            
            if self.is_loop(host, port):
                action = "LOOP_DETECTED"
                status_code = 508
                self.send_error(client, 508, "Loop Detected")
                self.stats['loops'] += 1
                return
            
            if self.is_blocked(host):
                action = "BLOCKED"
                status_code = 403
                self.send_error(client, 403, "Forbidden")
                self.stats['blocked'] += 1
                return
            
            action = "ALLOWED"
            self.stats['allowed'] += 1
            
            if method == 'CONNECT':
                status_code = 200
                bytes_transferred = self.handle_connect(client, host, port)
            else:
                status_code, bytes_transferred = self.handle_http(
                    client, request, host, port
                )
        
        except ValueError as e:
            action = "ERROR"
            status_code = 400
            self.stats['errors'] += 1
            self.send_error(client, 400, f"Bad Request: {e}")
        except ConnectionError:
            action = "ERROR"
            status_code = 502
            self.stats['errors'] += 1
        except socket.timeout:
            action = "TIMEOUT"
            status_code = 504
            self.stats['errors'] += 1
        except Exception as e:
            action = "ERROR"
            status_code = 500
            self.stats['errors'] += 1
        finally:
            elapsed = time.time() - start_time
            client.close()
            
            self.log_request(
                client_ip=addr[0],
                client_port=addr[1],
                host=host,
                port=port,
                request_line=request_line,
                action=action,
                status_code=status_code,
                bytes_transferred=bytes_transferred,
                elapsed_time=elapsed
            )
    
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(100)
        self.running = True
        
        logging.info("="*60)
        logging.info(f"Proxy server started on {HOST}:{PORT}")
        logging.info(f"Blocked domains: {len(self.blocked)}")
        logging.info(f"Log file: {LOG_FILE} (max {MAX_LOG_SIZE/(1024*1024):.0f}MB × {LOG_BACKUP_COUNT})")
        logging.info("="*60)
        
        try:
            while self.running:
                client, addr = server.accept()
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client, addr),
                    daemon=True
                )
                thread.start()
        except KeyboardInterrupt:
            logging.info("Shutting down...")
        finally:
            server.close()
            self.print_stats()
    
    def print_stats(self):
        logging.info("="*60)
        logging.info("PROXY SERVER STATISTICS")
        logging.info("="*60)
        logging.info(f"Total requests: {self.stats['total']}")
        logging.info(f"Allowed: {self.stats['allowed']}")
        logging.info(f"Blocked: {self.stats['blocked']}")
        logging.info(f"Loops detected: {self.stats['loops']}")
        logging.info(f"Errors: {self.stats['errors']}")
        logging.info("="*60)


def main():
    def signal_handler(sig, frame):
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    proxy = ProxyServer()
    
    try:
        proxy.start()
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received")
    except Exception as e:
        logging.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
