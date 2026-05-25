import sys
import packet
import crypto


def net_loop_recv_message(client_socket, comm_ctx):
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                print("\n[-] Disconnected from server.")
                sys.exit()

            recv_str = data.decode('utf-8')
            text = crypto.decrypt_message(recv_str)

            print(f"\n[MSG] {comm_ctx.user}: {text}")

            print("> ", end="", flush=True)
        except Exception:
            break


def net_loop_send(client):
    while True:
        try:
            msg = input("> ")
            if msg.lower() == '/exit':
                break

            if msg:
                pkt = crypto.create_message_packet(msg)
                client.sendall(pkt.json_str().encode('utf-8'))

        except KeyboardInterrupt:
            break


def net_exchange_comm_ctx(client_socket, my_ctx):
    client_socket.sendall(my_ctx.json_str().encode('utf-8'))
    ctx = client_socket.recv(4096)
    if not ctx:
       return None
    return ctx.decode('utf-8')


def net_await_ready_communication(client_socket):
    client_socket.sendall(packet.SERV_MESSAGE_READY)

    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                print("\n[!] Disconnected from server.")
                sys.exit()

            if data == packet.SERV_MESSAGE_READY:
                break
            else:
                print(f"[!] Unexpected packet {data}")

        except Exception:
            print("\n[!] Disconnected from server because an error occurred while awaiting communication.")
            sys.exit(1)

