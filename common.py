import os
import sys
import socket
import struct
import hmac
import hashlib
import time
import threading
import select
import subprocess
import ipaddress
import argparse
import fcntl

MAGIC_BYTES = b"VPN1"
PROTOCOL_VERSION = 1

MSG_TYPE_HANDSHAKE_INIT = 1
MSG_TYPE_HANDSHAKE_RESP = 2
MSG_TYPE_HANDSHAKE_FIN  = 3
MSG_TYPE_DATA           = 4
MSG_TYPE_KEEPALIVE      = 5

DEFAULT_PORT = 9000
DEFAULT_PSK = b"MySecretPreSharedKey"
BUFFER_SIZE = 65535
FRAGMENT_TIMEOUT = 15.0

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

HEADER_FORMAT = "!4sBBIIHH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def create_tun_interface(dev_name="tun0"):
    try:
        tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    except OSError as e:
        print(f"[!] Error opening /dev/net/tun: {e}")
        sys.exit(1)

    dev_bytes = dev_name.encode('utf-8')[:15]
    ifr = struct.pack("16sH", dev_bytes, IFF_TUN | IFF_NO_PI)
    
    try:
        fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    except OSError as e:
        print(f"[!] ioctl TUNSETIFF failed: {e}")
        os.close(tun_fd)
        sys.exit(1)

    return tun_fd, dev_name

def caesar_encrypt(data: bytes, shift: int) -> bytes:
    shift = shift % 256
    return bytes((b + shift) % 256 for b in data)

def caesar_decrypt(data: bytes, shift: int) -> bytes:
    shift = shift % 256
    return bytes((b - shift) % 256 for b in data)

def pack_frame(msg_type: int, session_id: int, packet_id: int, frag_idx: int, frag_count: int, payload: bytes) -> bytes:
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC_BYTES,
        PROTOCOL_VERSION,
        msg_type,
        session_id,
        packet_id,
        frag_idx,
        frag_count
    )
    frame_data = header + payload
    length_prefix = struct.pack("!I", len(frame_data))
    return length_prefix + frame_data

def unpack_frame(raw_bytes: bytes):
    if len(raw_bytes) < HEADER_SIZE:
        return None, None
    
    magic, version, msg_type, session_id, packet_id, frag_idx, frag_count = struct.unpack(
        HEADER_FORMAT, raw_bytes[:HEADER_SIZE]
    )
    
    if magic != MAGIC_BYTES or version != PROTOCOL_VERSION:
        raise ValueError("Invalid protocol magic or version")
        
    payload = raw_bytes[HEADER_SIZE:]
    meta = {
        "msg_type": msg_type,
        "session_id": session_id,
        "packet_id": packet_id,
        "frag_idx": frag_idx,
        "frag_count": frag_count
    }
    return meta, payload

def _derive_shift(psk: bytes, client_nonce: bytes, server_nonce: bytes) -> int:
    hasher = hashlib.sha256()
    hasher.update(psk)
    hasher.update(client_nonce)
    hasher.update(server_nonce)
    digest = hasher.digest()
    return digest[0]

def recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def recv_frame(sock):
    raw_len = recv_exact(sock, 4)
    if not raw_len:
        return None, None
    length = struct.unpack("!I", raw_len)[0]
    raw_frame = recv_exact(sock, length)
    if not raw_frame:
        return None, None
    return unpack_frame(raw_frame)

def client_handshake(sock, psk: bytes):
    client_nonce = os.urandom(16)
    init_frame = pack_frame(MSG_TYPE_HANDSHAKE_INIT, 0, 0, 0, 1, client_nonce)
    sock.sendall(init_frame)

    meta, payload = recv_frame(sock)
    if not meta or meta["msg_type"] != MSG_TYPE_HANDSHAKE_RESP:
        raise PermissionError("Handshake failed at INIT stage")

    server_nonce = payload[:16]
    server_hmac = payload[16:48]

    expected_hmac = hmac.new(psk, client_nonce + server_nonce, hashlib.sha256).digest()
    if not hmac.compare_digest(server_hmac, expected_hmac):
        raise PermissionError("Server HMAC verification failed")

    client_hmac = hmac.new(psk, server_nonce + client_nonce, hashlib.sha256).digest()
    fin_frame = pack_frame(MSG_TYPE_HANDSHAKE_FIN, 0, 0, 0, 1, client_hmac)
    sock.sendall(fin_frame)

    shift = _derive_shift(psk, client_nonce, server_nonce)
    return shift

def server_handshake(sock, psk: bytes):
    meta, payload = recv_frame(sock)
    if not meta or meta["msg_type"] != MSG_TYPE_HANDSHAKE_INIT:
        raise PermissionError("Expected HANDSHAKE_INIT")

    client_nonce = payload
    server_nonce = os.urandom(16)
    server_hmac = hmac.new(psk, client_nonce + server_nonce, hashlib.sha256).digest()

    resp_frame = pack_frame(MSG_TYPE_HANDSHAKE_RESP, 0, 0, 0, 1, server_nonce + server_hmac)
    sock.sendall(resp_frame)

    meta_fin, payload_fin = recv_frame(sock)
    if not meta_fin or meta_fin["msg_type"] != MSG_TYPE_HANDSHAKE_FIN:
        raise PermissionError("Expected HANDSHAKE_FIN")

    client_hmac = payload_fin
    expected_hmac = hmac.new(psk, server_nonce + client_nonce, hashlib.sha256).digest()
    if not hmac.compare_digest(client_hmac, expected_hmac):
        raise PermissionError("Client HMAC verification failed")

    shift = _derive_shift(psk, client_nonce, server_nonce)
    return shift
