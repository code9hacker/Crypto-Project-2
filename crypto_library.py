import bcrypt
import pysftp
from argon2 import PasswordHasher
from pylibsrtp import Policy, Session
from tls import (tls_config_new, tls_client, tls_configure, tls_connect, tls_write,
                tls_read, tls_config_free, tls_close, tls_free)
from urllib3 import HTTPSConnectionPool
import certifi
import base64
import M2Crypto
import hashlib

import json
from base64 import b64encode, b64decode
from crypto.Cipher import AES
from crypto.Util.Padding import pad, unpad
from crypto.Random import get_random_bytes

import string
import random


def get_password_hash(password: bytes) -> str:
    # minimum memory size m = 37 MiB
    # minimum number of iterations t = 1
    # degree of parallelism p = 1
    ph = PasswordHasher()
    return ph.hash(password)


def check_password_hash(password: bytes, hashed: bytes) -> bool:
    ph = PasswordHasher()
    return ph.verify(hashed, password)


# Need to use work factor of 10 as per OWASP
def get_password_hash_old(password: bytes) -> bytes:
    salt = bcrypt.gensalt(10)
    hashed = bcrypt.hashpw(password, salt)
    return hashed


def check_password_hash_old(password: bytes, hashed: bytes) -> bool:
    return bcrypt.checkpw(password, hashed)


def generate_temp_password(length):
    characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")
    random.shuffle(characters)
    password = []
    for i in range(length):
        password.append(random.choice(characters))

    random.shuffle(password)

    return password, get_password_hash(bytes(password))


def rtp_protect(rtp: bytes) -> bytes:
    key = (b'\x00' * 30)
    tx_policy = Policy(key=key, ssrc_type=Policy.SSRC_ANY_OUTBOUND)
    tx_session = Session(policy=tx_policy)
    return tx_session.protect(rtp)


def rtp_unprotect(srtp: bytes) -> bytes:
    key = (b'\x00' * 30)
    rx_policy = Policy(key=key, ssrc_type=Policy.SSRC_ANY_INBOUND)
    rx_session = Session(policy=rx_policy)
    return rx_session.unprotect(srtp)


def upload_file(file: str):
    with pysftp.Connection('hostname', username = "sftp-username", password = "sftp-secret") as sftp:
        with sftp.cd('public'):
            sftp.put(file)


def retrieve_file(file: str):
    with pysftp.Connection('hostname', username = "sftp-username", password = "sftp-secret") as sftp:
        with sftp.cd('public'):
            sftp.get(file)


def encrypt_data(data):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ct})
    return result


def decrypt_data(key, json_data_input):
    try:
        b64 = json.loads(json_data_input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt
    except (ValueError, KeyError):
        print("Incorrect decryption")


# Query eg = "HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n"
def send_request(host: str, port: int, query: str) -> str:
    cfg = tls_config_new()
    ctx = tls_client()
    tls_configure(ctx, cfg)

    tls_connect(ctx, host, port)
    tls_write(ctx, query.encode())
    r = tls_read(ctx)

    tls_config_free(cfg)
    tls_close(ctx)
    tls_free(ctx)

    return r.decode()


class TestHTTPSConnectionPool(HTTPSConnectionPool):
    def _validate_conn(self, conn):
        super(TestHTTPSConnectionPool, self)._validate_conn(conn)
        pinset = [
            'c22be239f483c08957bc106219cc2d3ac1a308dfbbdd0a365f17b9351234cf00'
            ]
        if not conn.is_verified:
            return False

        der = conn.sock.getpeercert(binary_form=True)
        x509 = M2Crypto.X509.load_cert_string(der, M2Crypto.X509.FORMAT_DER)
        mem = M2Crypto.BIO.MemoryBuffer()
        public_key = x509.get_pubkey().get_rsa().save_pub_key_bio(mem)
        pk_der = mem.getvalue().split("\n")[1:-2]
        pk_base64 = ''.join(pk_der)
        pk_raw = base64.b64decode(pk_base64)
        pk_sha265 = hashlib.sha256(pk_raw).hexdigest()

        if pk_sha265 in pinset:
            pass
        else:
            raise Exception("Public Key not found in pinset!")


def send_get_request(host, port, url) -> str:
    pool = TestHTTPSConnectionPool(
        host,
        port,
        cert_reqs='CERT_REQUIRED',
        ca_certs=certifi.where())

    request = pool.urlopen('GET', url)
    return request.data
