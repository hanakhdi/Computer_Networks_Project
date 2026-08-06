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
