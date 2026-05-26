import json
import base64

AUTH_SUCCESS = b"AUTH_SUCCESS"
AUTH_FAIL = b"AUTH_FAIL"

SERV_MESSAGE_READY = b"READY"


# {"user": "user-a", "pub": "PUBLIC-KEY", "identity": "IDENTITY", "signature": "SIGNATURE"}
class CommunicationContext:
    def __init__(self, json_data=None):
        self.json_data = json_data
        self.counter = 0

        if json_data is not None:
            self.user = json_data["user"]
            self.pub = json_data["pub"]
            self.identity = json_data["identity"]
            self.signature = json_data["signature"]

    def json_str(self):
        self.json_data = {
            "user": self.user,
            "pub": self.pub,
            "identity": self.identity,
            "signature": self.signature

        }
        return json.dumps(self.json_data)


# {"content": "ENCRYPTED", counter: 123, "nonce": "NONCE"}
class Message:
    def __init__(self, json_data):
        self.json_data = json_data
        if json_data is not None:
            self.content = self.json_data["content"]
            self.counter = self.json_data["counter"]
            self.nonce = self.json_data["nonce"]

    def json_str(self):
        self.json_data = {
            "content": self.content,
            "counter": self.counter,
            "nonce": self.nonce
        }
        return json.dumps(self.json_data)



def is_fail(packet_bytes):
    return packet_bytes.startswith(AUTH_FAIL)


def is_success(packet_bytes):
    return packet_bytes.startswith(AUTH_SUCCESS)




