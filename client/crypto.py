import packet
import json
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes

comm_ctx = None

my_private_key = None
my_public_key = None
my_public_key_as_bytes = None
my_counter = 0

shared_secret = None
session_key = None
aesgcm_cipher = None


def init_crypto():
    global my_private_key, my_public_key, my_public_key_as_bytes

    my_private_key = x25519.X25519PrivateKey.generate()
    my_public_key = my_private_key.public_key()

    my_public_key_as_bytes = my_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def create_communication_ctx(username):
    ctx = packet.CommunicationContext(None)
    ctx.user = username

    if my_public_key is not None:
        ctx.pub = my_public_key_as_bytes

    return ctx


def comm_ctx_from_raw_ctx_packet(data):
    global comm_ctx

    json_data = json.loads(data)
    json_data['pub'] = base64.b64decode(json_data['pub'])

    comm_ctx = packet.CommunicationContext(json_data)

    return comm_ctx


def create_shared_secret_from_comm_ctx():
    global session_key, shared_secret, aesgcm_cipher

    peer_pub_key = x25519.X25519PublicKey.from_public_bytes(comm_ctx.pub)
    shared_secret = my_private_key.exchange(peer_pub_key)

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"e2ee-session-key",
    ).derive(shared_secret)

    aesgcm_cipher = AESGCM(session_key)

    return session_key


def pad_content(msg):
    block_size = 64 # Minimum size. Ideal should be 128, lowered to 64 for demonstration's sake

    while len(msg) > block_size:
        block_size = block_size * 2

    pad = block_size - len(msg)
    return msg + (pad * b'\x00')


def encrypt_message(content):
    msg = pad_content(content.encode('utf-8'))

    nonce = os.urandom(12)
    ciphertext = aesgcm_cipher.encrypt(nonce, msg, str(comm_ctx.counter).encode('utf-8'))

    return ciphertext, nonce


def decrypt_message(raw_json_str):
    global my_counter

    data = json.loads(raw_json_str)
    nonce = base64.b64decode(data['nonce'])
    ciphertext = base64.b64decode(data['content'])
    counter = int(data['counter'])

    if counter <= my_counter:
        print(f"[!] Decryption failed: Replay attack attempted received_counter <= my_counter ({counter} < {my_counter})")
        return None

    try:
        text = aesgcm_cipher.decrypt(nonce, ciphertext, str(counter).encode('utf-8'))
        text = text.rstrip(b'\x00') # Remove padding

        my_counter = counter

        return text.decode('utf-8')
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
        return None


def create_message_packet(content):
    comm_ctx.counter = comm_ctx.counter + 1

    cipher, nonce = encrypt_message(content)

    msg = packet.Message(None)
    msg.content = cipher
    msg.nonce = nonce
    msg.counter = comm_ctx.counter

    return msg

