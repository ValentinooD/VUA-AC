#!/usr/bin/env python3

import socket
import threading
import argparse

from authentication import authenticate_client, init_auth, destroy_session
from server.network import net_init_connection


def handle_client(client_socket):
    session = authenticate_client(client_socket)

    if not session:
        return

    print(f"[+] User {session.username} has successfully authenticated.")

    try:
        # Blocking function. Exchanges information to prepare communication.
        net_init_connection(session)

        while True:
            data = session.socket.recv(4096)
            if not data:
                break

            message_str = data.decode('utf-8')
            print(f"[>] {session.username} -> {session.target.username}: {message_str}")
            session.target.socket.sendall(message_str.encode('utf-8'))

    except Exception:
        pass
    finally:
        print(f"[-] User {session.username} disconnected.")
        destroy_session(session)
        client_socket.close()


def start_server(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()

    print(f"[*] Server listening on port {host}:{port}")
    try:
        while True:
            client_socket, _ = server.accept()
            threading.Thread(target=handle_client, args=(client_socket,)).start()
    except Exception:
        pass
    finally:
        server.close()
        print(f"[*] Shut down")


def main():
    init_auth(args.db)
    start_server(args.host, int(args.port))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Server")
    parser.add_argument(
        '-d', '--db',
        required=True,
        help="Database file"
    )
    parser.add_argument(
        '--host',
        default="127.0.0.1",
        help="Server host"
    )
    parser.add_argument(
        '-p', '--port',
        default=8080,
        help="Port to host on"
    )

    args = parser.parse_args()
    main()
