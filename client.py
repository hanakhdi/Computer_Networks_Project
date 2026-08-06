import os
import sys
import socket
import threading
import argparse
from common import (
    DEFAULT_PORT, DEFAULT_PSK, create_tun_interface, 
    client_handshake, caesar_encrypt, caesar_decrypt, 
    pack_frame, recv_frame, Reassembler, RouteManager
)

def tun_to_socket_loop(tun_fd, sock, shift):
    while True:
        try:
            packet = os.read(tun_fd, 2048)
            if not packet:
                break
            encrypted = caesar_encrypt(packet, shift)
            frame = pack_frame(4, 1, 1, 0, 1, encrypted)
            sock.sendall(frame)
        except Exception:
            break

def socket_to_tun_loop(sock, tun_fd, shift):
    reassembler = Reassembler()
    while True:
        try:
            meta, payload = recv_frame(sock)
            if not meta:
                break
            decrypted = caesar_decrypt(payload, shift)
            packet = reassembler.add_fragment(meta["packet_id"], meta["frag_idx"], meta["frag_count"], decrypted)
            if packet:
                os.write(tun_fd, packet)
        except Exception:
            break

def main():
    parser = argparse.ArgumentParser(description="VPN Client")
    parser.add_argument("--server", required=True, help="Server IP address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port")
    parser.add_argument("--psk", default=DEFAULT_PSK.decode(), help="Pre-shared key")
    parser.add_argument("--route", action="append", help="Subnet route to add (e.g. 192.168.1.0/24)")
    parser.add_argument("--full-tunnel", action="store_true", help="Redirect all traffic")
    args = parser.parse_args()

    tun_fd, dev_name = create_tun_interface("tun1")
    os.system(f"ip addr add 10.8.0.2/24 dev {dev_name}")
    os.system(f"ip link set dev {dev_name} up")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.server, args.port))

    shift = client_handshake(sock, args.psk.encode())
    print("[+] Handshake successful. Caesar shift:", shift)

    route_mgr = RouteManager()
    if args.full_tunnel:
        route_mgr.setup_full_tunnel(args.server, dev_name)
    elif args.route:
        for r in args.route:
            route_mgr.add_route(r, dev_name)

    t1 = threading.Thread(target=tun_to_socket_loop, args=(tun_fd, sock, shift), daemon=True)
    t2 = threading.Thread(target=socket_to_tun_loop, args=(sock, tun_fd, shift), daemon=True)
    t1.start()
    t2.start()

    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print("\n[*] Shutting down client...")
    finally:
        route_mgr.cleanup()
        sock.close()

if __name__ == "__main__":
    main()
