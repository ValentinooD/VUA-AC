import argparse
import socket
import threading

from network import *
from authentication import net_authenticate # authentication is kept separate

import crypto


def network_init_client_connection(host, port, username, password):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    if not net_authenticate(client, username, password):
        client.close()
        return

    print(f"[*] Authenticated as {username}")

    crypto.init_crypto()

    # Exchanging context
    my_ctx = crypto.create_communication_ctx(username)
    raw_ctx = net_exchange_comm_ctx(client, my_ctx)
    comm_ctx = crypto.from_raw_ctx_packet(raw_ctx)
    crypto.create_shared_secret_from_comm_ctx()

    # Waiting for OK
    net_await_ready_communication(client)

    # Start messaging threads after everything has been exchanged
    receive_thread = threading.Thread(target=net_loop_recv_message, args=(client, comm_ctx,))
    receive_thread.daemon = True
    receive_thread.start()

    #TODO: COUNTER TO VERIFY INTERGRITY

    net_loop_send(client)
    client.close()


def main():
    if not args.username:
        args.username = input("Enter username: ").strip()

    if not args.password:
        args.password = input("Enter password: ").strip()

    network_init_client_connection(args.host, int(args.port), args.username, args.password)
    print("\n[!] Disconnected from server.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Client")
    parser.add_argument(
        '--host',
        default="127.0.0.1",
        help="Server host (default: 127.0.0.1)"
    )
    parser.add_argument(
        '--port',
        default=8080,
        help="Port to host on (default: 8080)"
    )
    parser.add_argument(
        '-u', '--username', '--user',
        help="Username of user to authenticate as"
    )
    parser.add_argument(
        '-p', '--password',
        help="Password of user to authenticate as"
    )

    args = parser.parse_args()
    main()
