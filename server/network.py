import packet
from authentication import authenticate_client, init_auth, destroy_session, sessions


def assign_forwards():
    first_alone = None
    for session in sessions:
        if session.target is None and first_alone is None:
            first_alone = session
            continue

        if session.target is None and first_alone is not None:
            session.target = first_alone
            first_alone.target = session

            print(f"[*] Assigned {session.username} to {session.target.username}")
            print(f"[*] Assigned {first_alone.username} to {first_alone.target.username}")


def net_init_connection(session):
    # First the client sends their comm_ctx
    data = session.socket.recv(4096)
    if not data:
        raise Exception("Received no data")
    session.comm_ctx = data

    print(session.comm_ctx)

    # Attempt to assign forwards, if fails just wait for the other thread to do it
    assign_forwards()

    # Make thread wait until forward is assigned
    while not session.target:
        pass

    # Forward comm_ctx
    session.target.socket.sendall(session.comm_ctx)
    print(f"[*] Sent communication context from {session.username} to {session.target.username}")

    # Wait for client to be ready
    while True:
        data = session.socket.recv(4096)
        if not data:
            raise Exception("Received no data")

        if data == packet.SERV_MESSAGE_READY:
            session.ready = True
            break

    print(f"[*] User {session.username} is waiting for target {session.target.username} to be ready.")
    # Wait for target to also be ready
    while not session.target.ready:
        pass

    # When target is ready, notify the client
    session.socket.sendall(packet.SERV_MESSAGE_READY)
    print(f"[*] Notified {session.username} that the communication is ready")

