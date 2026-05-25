AUTH_FAIL_INVALID_USER = b"AUTH_FAIL: Invalid user or already logged in."
AUTH_FAIL_BAD_CREDENTIALS = b"AUTH_FAIL: Bad Credentials"

AUTH_SUCCESS_LOGGED_IN = b"AUTH_SUCCESS: Logged in"

SERV_MESSAGE_READY = b"READY"


class SessionContext:
    def __init__(self, username, socket):
        self.username = username
        self.socket = socket
        self.target = None
        self.comm_ctx = None # Waits on server before being forwarded
        self.ready = False

