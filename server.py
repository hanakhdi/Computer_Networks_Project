import socket
import threading
from common import DEFAULT_PORT

def handle_client(client_sock, addr):
    print(f"[*] Connection accepted from {addr}")
    try:
        data = client_sock.recv(1024)
        if data:
            client_sock.sendall(b"ACK: " + data)
    finally:
        client_sock.close()

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", DEFAULT_PORT))
    server_sock.listen(5)
    print(f"[*] Server listening on port {DEFAULT_PORT}")

    while True:
        client_sock, addr = server_sock.accept()
        t = threading.Thread(target=handle_client, args=(client_sock, addr))
        t.daemon = True
        t.start()

if __name__ == "__main__":
    main()