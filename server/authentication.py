import secrets
import hmac
import hashlib
import database
import packet

sessions = []
database_connection = None


class CryptoChallenge:
    def __init__(self, username, password_hash, salt):
        self.username = username
        self.hash = password_hash
        self.salt = salt
        self.challenge = secrets.token_bytes(32) # get very good and secure secret :thubmsup:
        self.is_valid = False

    def get_challenge_payload(self):
        # First byte is length of salt then we concatenate the salt and challenge
        return bytes([len(self.salt)]) + self.salt + self.challenge

    def check_valid(self, response):
        expected = hmac.new(self.hash, self.challenge, hashlib.sha256).digest()
        self.is_valid = hmac.compare_digest(expected, response)
        return self.is_valid


def authenticate_session(session):
    sessions.append(session)


def is_authenticated(username):
    return any(session.username == username for session in sessions)


def destroy_session(session):
    sessions.remove(session)


def init_auth(db_path):
    global database_connection
    database_connection = database.DatabaseConnection(db_path)


def get_crypto_challenge(username):
    user = database.get_user_data(database_connection, username)
    if user is None:
        return None

    return CryptoChallenge(user["username"], user["password_hash"], user["salt"])


def create_session(crypto_challenge, username, socket):
    user = database.get_user_data(database_connection, username)

    # Checking again, developer may be retarded
    if crypto_challenge is None or not crypto_challenge.is_valid:
        return None

    return packet.SessionContext(user["username"], socket)


def authenticate_client(client_socket):
    try:
        username = client_socket.recv(1024).decode('utf-8').strip().lower()

        if is_authenticated(username):
            client_socket.sendall(packet.AUTH_FAIL_INVALID_USER)
            return None

        crypto = get_crypto_challenge(username)
        if crypto is None:
            return None

        client_socket.sendall(crypto.get_challenge_payload())

        # Blocking function. We are waiting for the user to respond.
        client_response = client_socket.recv(1024)

        if crypto.check_valid(client_response):
            session = create_session(crypto, username, client_socket)
            authenticate_session(session)
            client_socket.sendall(packet.AUTH_SUCCESS_LOGGED_IN)

            return session
        else:
            client_socket.sendall(packet.AUTH_FAIL_BAD_CREDENTIALS)
            return None

    except Exception as e:
        print(f"[!] Auth Error: {e}")
        client_socket.close()
        raise e
