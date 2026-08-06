import socket
import threading
import ipaddress
import os
import sys
import signal
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from common import (
    DEFAULT_PORT, DEFAULT_PSK, create_tun_interface, 
    server_handshake, caesar_encrypt, caesar_decrypt, 
    pack_frame, recv_frame, Reassembler
)

class ClientManager:
    def __init__(self, subnet="10.8.0.0/24"):
        self.lock = threading.RLock()
        self.network = ipaddress.ip_network(subnet)
        self.hosts = [str(ip) for ip in self.network.hosts()]
        self.server_ip = self.hosts[0]
        self.available_ips = set(self.hosts[1:])
        self.active_clients = {}

    def allocate_ip(self, client_id):
        with self.lock:
            if not self.available_ips:
                return None
            ip = sorted(list(self.available_ips))[0]
            self.available_ips.remove(ip)
            self.active_clients[client_id] = ip
            return ip

    def release_ip(self, client_id):
        with self.lock:
            if client_id in self.active_clients:
                ip = self.active_clients.pop(client_id)
                self.available_ips.add(ip)

    def get_active_count(self):
        with self.lock:
            return len(self.active_clients)

class StatusHandler(BaseHTTPRequestHandler):
    client_mgr = None

    def do_GET(self):
        if self.path == "/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            data = {"active_connections": StatusHandler.client_mgr.get_active_count()}
            self.wfile.write(json.dumps(data).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def start_status_api(client_mgr, port=9200):
    StatusHandler.client_mgr = client_mgr
    server = HTTPServer(("0.0.0.0", port), StatusHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

def forward_tun_to_socket(tun_fd, client_sockets, lock, shift):
    while True:
        try:
            packet = os.read(tun_fd, 2048)
            if not packet:
                break
            encrypted = caesar_encrypt(packet, shift)
            frame = pack_frame(4, 1, 1, 0, 1, encrypted)
            with lock:
                for sock in list(client_sockets.values()):
                    try:
                        sock.sendall(frame)
                    except:
                        pass
        except Exception:
            break

def handle_vpn_client(client_sock, addr, client_mgr, tun_fd):
    client_id = f"{addr[0]}:{addr[1]}"
    try:
        shift = server_handshake(client_sock, DEFAULT_PSK)
        assigned_ip = client_mgr.allocate_ip(client_id)
        print(f"[+] Client {client_id} authenticated. Assigned VIP: {assigned_ip}")

        reassembler = Reassembler()
        while True:
            meta, payload = recv_frame(client_sock)
            if not meta:
                break
            decrypted = caesar_decrypt(payload, shift)
            packet = reassembler.add_fragment(meta["packet_id"], meta["frag_idx"], meta["frag_count"], decrypted)
            if packet:
                os.write(tun_fd, packet)

    except Exception as e:
        print(f"[!] Error handling client {client_id}: {e}")
    finally:
        client_mgr.release_ip(client_id)
        client_sock.close()
        print(f"[-] Client {client_id} disconnected")

def main():
    client_mgr = ClientManager("10.8.0.0/24")
    start_status_api(client_mgr)
    
    tun_fd, dev_name = create_tun_interface("tun0")
    os.system(f"ip addr add {client_mgr.server_ip}/24 dev {dev_name}")
    os.system(f"ip link set dev {dev_name} up")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", DEFAULT_PORT))
    server_sock.listen(10)

    def sig_handler(sig, frame):
        print("\n[*] Server shutting down gracefully...")
        server_sock.close()
        try:
            os.close(tun_fd)
        except:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    print(f"[*] Server initialized on {DEFAULT_PORT} with interface {dev_name}")

    while True:
        try:
            sock, addr = server_sock.accept()
            t = threading.Thread(target=handle_vpn_client, args=(sock, addr, client_mgr, tun_fd))
            t.daemon = True
            t.start()
        except OSError:
            break

if __name__ == "__main__":
    main()
