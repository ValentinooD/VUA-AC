import hashlib
import hmac
import packet


def extract_crypto_data(data):
    salt_length = data[0]
    salt = data[1: 1 + salt_length]
    challenge = data[1 + salt_length:]
    return salt, challenge


def hmac_sha256(salt, challenge, password):
    derived_password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
    return hmac.new(derived_password_hash, challenge, hashlib.sha256).digest()


def net_authenticate(client, username, password):
    # Send username
    client.sendall(username.encode('utf-8'))

    # Receive crypto data
    crypto_data = client.recv(1024)
    if packet.is_fail(crypto_data):
        print(crypto_data.decode('utf-8'))
        return False

    salt, challenge = extract_crypto_data(crypto_data)
    response = hmac_sha256(salt, challenge, password)

    client.sendall(response)

    status = client.recv(1024)
    return packet.is_success(status)




