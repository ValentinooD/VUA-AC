import json
import os


configuration = {}
identity_file_name = None
priv_identity = None
pub_identity = None
known_hosts = {}

force_new_identity = False


def init_config(username):
    global identity_file_name, configuration, pub_identity, known_hosts, priv_identity
    identity_file_name = username + ".config.json"

    if not os.path.exists(identity_file_name) or force_new_identity:
        configuration = {"priv_identity": "", "pub_identity": "", "known_hosts": {}}
        write_config()

    with open(identity_file_name, 'r') as f:
        s = f.readlines()
        configuration = json.loads(s[0])

    priv_identity = configuration['priv_identity']
    pub_identity = configuration['pub_identity']
    known_hosts = configuration['known_hosts']


def write_config():
    with open(identity_file_name, 'w') as f:
        f.write(json.dumps(configuration))


def set_my_identity(priv_key, pub_key):
    global priv_identity, pub_identity

    priv_identity = priv_key.hex()
    pub_identity = pub_key.hex()

    configuration['priv_identity'] = priv_identity
    configuration['pub_identity'] = pub_identity

    write_config()


def add_known_host(user, their_pub_key):
    global known_hosts
    known_hosts[user] = their_pub_key
    configuration['known_hosts'] = known_hosts
    write_config()


def new_identity():
    global force_new_identity
    force_new_identity = True
    print(f"[!] Will create new identity keys for the current user!")