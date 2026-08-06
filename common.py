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
