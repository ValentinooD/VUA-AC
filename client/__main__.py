import argparse
import socket
import threading

from network import *
from authentication import net_authenticate # authentication is kept separate

import crypto
import config


def network_init_client_connection(host, port, username, password):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    if not net_authenticate(client, username, password):
        print("[!] Authentication failed.")
        client.close()
        return

    print(f"[*] Authenticated as {username}")

    config.init_config(username)
    crypto.init_crypto()

    # Exchanging context
    my_ctx = crypto.create_communication_ctx(username)
    raw_ctx = net_exchange_comm_ctx(client, my_ctx)
    comm_ctx = crypto.comm_ctx_from_raw_ctx_packet(raw_ctx)

    if comm_ctx.user not in config.known_hosts:
        print(f"[*] First time chatting with {comm_ctx.user}. Their public key has been saved.")
        config.add_known_host(comm_ctx.user, comm_ctx.identity)


    if not crypto.is_identity_ok(comm_ctx):
        print(f"[!] The public key received from the user has changed.")
        ok = input(f"[*] Do you wish the save the new public key? [y/N] ")
        if ok.lower() == "y":
            config.add_known_host(comm_ctx.user, comm_ctx.identity)
            print(f"[*] Saved new public key from {comm_ctx.user}.")
        else:
            client.close()
            return

    if not crypto.is_signature_ok(comm_ctx):
        print(f"[!] The signature received from the user could not be verified!")
        client.close()
        return
    else:
        print(f"[*] The signature was verified.")

    crypto.create_shared_secret_from_comm_ctx()

    # Waiting for OK
    net_await_ready_communication(client)
    print(f"[*] You are now chatting with {comm_ctx.user}")

    # Start messaging threads after everything has been exchanged
    receive_thread = threading.Thread(target=net_loop_recv_message, args=(client, comm_ctx,))
    receive_thread.daemon = True
    receive_thread.start()

    net_loop_send(client)
    client.close()


def main():
    if args.new_identity:
        config.new_identity()

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
    parser.add_argument(
        '--new-identity',
        default=False,
        action="store_true",
        help="Create new identity keys for the user"
    )

    args = parser.parse_args()
    main()
