import socket
from common import DEFAULT_PORT

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", DEFAULT_PORT))
    sock.sendall(b"Hello Server")
    resp = sock.recv(1024)
    print(f"[*] Server responded: {resp}")
    sock.close()

if __name__ == "__main__":
    main()