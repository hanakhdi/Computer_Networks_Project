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