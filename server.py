import socket
import threading
import ipaddress
import os
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
