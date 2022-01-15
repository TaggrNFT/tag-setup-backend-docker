import hashlib
import base64
import binascii

from config import MASTER_KEY, PBKDF_ROUNDS, TAG_HASH_KEY, TAG_SECRET_KEY


def derive_tag_key(tag_hash: bytes, key_no: int) -> bytes:
    try:
        master_k = MASTER_KEY[key_no]
    except IndexError:
        raise RuntimeError('Invalid key number: ' + str(key_no))

    return hashlib.pbkdf2_hmac('sha512', master_k, b"key" + tag_hash + bytes([key_no]), PBKDF_ROUNDS, 16)


def calculate_tag_hash(uid: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha512', TAG_HASH_KEY, b"taghash" + uid, PBKDF_ROUNDS, 16)


def calculate_tag_secret(tag_hash: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha512', TAG_SECRET_KEY, b"tagsecret" + tag_hash, PBKDF_ROUNDS, 9)).decode('ascii')


def derive_uid_checksum(uid: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha512', TAG_HASH_KEY, b"uidchk" + uid, PBKDF_ROUNDS, 2)


def derive_uid_pwd(checksum: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha512', TAG_HASH_KEY, b"uidpwd" + checksum, PBKDF_ROUNDS, 7)


def wrap_uid(uid: bytes) -> str:
    if len(uid) != 7:
        raise RuntimeError('Invalid real UID length')

    checksum = derive_uid_checksum(uid)
    pwd = derive_uid_pwd(checksum)
    enc_uid = bytes(a ^ b for a, b in zip(uid, pwd))
    wrapped_uid = (enc_uid + checksum).hex().upper()
    return ':'.join([wrapped_uid[i:i+2] for i in range(0, len(wrapped_uid), 2)])


def unwrap_uid(wrapped_uid: str) -> bytes:
    wrapped_uid = wrapped_uid.replace(':', '')
    wrapped_uid = binascii.unhexlify(wrapped_uid)

    if len(wrapped_uid) != 9:
        raise RuntimeError('Invalid wrapped UID length')

    enc_uid = wrapped_uid[0:7]
    checksum = wrapped_uid[7:9]
    pwd = derive_uid_pwd(checksum)
    real_uid = bytes(a ^ b for a, b in zip(enc_uid, pwd))

    if derive_uid_checksum(real_uid) != checksum:
        raise RuntimeError('Invalid wrapped UID')

    return real_uid

