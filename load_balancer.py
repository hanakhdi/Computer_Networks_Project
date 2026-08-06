import socket
import threading
import urllib.request
import json
import argparse

def query_backend(ip, status_port=9200):
    try:
        url = f"http://{ip}:{status_port}/status"
        req = urllib.request.urlopen(url, timeout=2)
        if req.status == 200:
            data = json.loads(req.read().decode('utf-8'))
            return data.get("active_connections", 0)
    except:
        return None
    return None

def select_best_backend(backends):
    best_backend = None
    min_conns = float('inf')
    for b in backends:
        conns = query_backend(b)
        if conns is not None and conns < min_conns:
            min_conns = conns
            best_backend = b
    return best_backend

def proxy_traffic(source_sock, target_ip, target_port=9000):
    try:
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.connect((target_ip, target_port))

        def pipe(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except:
                pass

        t1 = threading.Thread(target=pipe, args=(source_sock, target_sock), daemon=True)
        t2 = threading.Thread(target=pipe, args=(target_sock, source_sock), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    finally:
        source_sock.close()

def main():
    parser = argparse.ArgumentParser(description="VPN Load Balancer")
    parser.add_argument("--listen-port", type=int, default=9000)
    parser.add_argument("--backends", nargs="+", required=True, help="List of backend IP addresses")
    args = parser.parse_args()

    lb_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lb_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lb_sock.bind(("0.0.0.0", args.listen_port))
    lb_sock.listen(10)
    print(f"[*] Load Balancer running on port {args.listen_port}...")

    while True:
        client_sock, _ = lb_sock.accept()
        best_backend = select_best_backend(args.backends)
        if best_backend:
            t = threading.Thread(target=proxy_traffic, args=(client_sock, best_backend), daemon=True)
            t.start()
        else:
            client_sock.close()

if __name__ == "__main__":
    main()