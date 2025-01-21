import base64
import hashlib
import json
import os
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import padding as as_padding
from cryptography.hazmat.primitives.asymmetric import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

KEY = "hObYhjwuydkwodwhaiJWiwdaoadIjdAI".encode("UTF-8")


# def encrypt_password(password):
#     iv = os.urandom(16)
#
#     cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
#
#     padder = padding.PKCS7(algorithms.AES.block_size).padder()
#     padded_password = padder.update(password.encode()) + padder.finalize()
#
#     encryptor = cipher.encryptor()
#     encrypted_password = encryptor.update(padded_password) + encryptor.finalize()
#
#     return base64.b64encode(iv + encrypted_password).decode()
#
#
# def decrypt_password(encrypted_password):
#     encrypted_data = base64.b64decode(encrypted_password)
#
#     iv = encrypted_data[:16]
#     ciphertext = encrypted_data[16:]
#
#     cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
#
#     decryptor = cipher.decryptor()
#     padded_password = decryptor.update(ciphertext) + decryptor.finalize()
#
#     unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
#     password = unpadder.update(padded_password) + unpadder.finalize()
#
#     return password.decode()
#


def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        sym_padding.PSS(
            mgf=sym_padding.MGF1(hashes.SHA256()),
            salt_length=sym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            sym_padding.PSS(
                mgf=sym_padding.MGF1(hashes.SHA256()),
                salt_length=sym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except:
        return False


def alg_encryption(alg: dict):
    # WARN: change ECB to CBC
    serialized_alg = json.dumps(alg).encode("utf-8")
    cipher_alg = Cipher(algorithms.AES(KEY), modes.ECB(), backend=default_backend())
    encryptor_alg = cipher_alg.encryptor()
    padder_alg = padding.PKCS7(128).padder()
    padded_alg = padder_alg.update(serialized_alg) + padder_alg.finalize()
    return encryptor_alg.update(padded_alg) + encryptor_alg.finalize()


def decrypt_alg(encrypted_alg: bytes):
    # WARN: change ECB to CBC
    cipher_alg = Cipher(algorithms.AES(KEY), modes.ECB(), backend=default_backend())
    decryptor_alg = cipher_alg.decryptor()

    decrypted_data = decryptor_alg.update(encrypted_alg) + decryptor_alg.finalize()

    unpadder_alg = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder_alg.update(decrypted_data) + unpadder_alg.finalize()

    alg = json.loads(unpadded_data.decode("utf-8"))

    return alg


def aes_key_wrap(key, backend=default_backend()):
    cipher = Cipher(algorithms.AES(KEY), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    wrapped_key = encryptor.update(key) + encryptor.finalize()
    return wrapped_key


def aes_key_unwrap(wrapped_key, backend=default_backend()):
    cipher = Cipher(algorithms.AES(KEY), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    key = decryptor.update(wrapped_key) + decryptor.finalize()
    return key


def generate_file_handle(data: bytes):
    file_handle = hashlib.sha256(data).hexdigest()
    return file_handle


def encrypt(plaintext, key_length=32):
    random_key = os.urandom(key_length)

    iv = os.urandom(16)

    cipher = Cipher(
        algorithms.AES(random_key), modes.CBC(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    wrapped_key = aes_key_wrap(random_key, backend=default_backend())

    file_handle = generate_file_handle(plaintext)

    hmac_obj = hmac.HMAC(random_key, hashes.SHA256(), backend=default_backend())
    hmac_obj.update(encrypted_data)
    integrity_control = hmac_obj.finalize()

    alg = {
        "encryption": {
            "algorithm": "AES",
            "mode": "CBC",
            "Padder": "PKCS7",
            "iv": base64.b64encode(iv).decode("utf-8"),
        },
        "integrity_control": {
            "method": "HMAC",
            "hash_algorithm": "SHA256",
            "MAC": base64.b64encode(integrity_control).decode("utf-8"),
        },
    }

    return {
        "encrypted_data": encrypted_data,
        "file_handle": file_handle,
        "wrapped_key": wrapped_key,
        "alg": alg_encryption(alg),
    }


def decrypt(encrypted_data: bytes, wrapped_key: bytes, alg: bytes):
    alg_decrypt = decrypt_alg(alg)

    encryption_data = alg_decrypt.get("encryption")
    integrity_data = alg_decrypt.get("integrity_control")
    iv = encryption_data.get("iv").encode("UTF-8")
    iv = base64.b64decode(iv)
    key = aes_key_unwrap(wrapped_key)
    mac = integrity_data.get("MAC").encode("UTF-8")
    mac = base64.b64decode(mac)

    algorithm = None
    mode = None
    hash = None
    block_size = None

    if integrity_data.get("hash_algorithm") == "SHA256":
        hash = hashes.SHA256()
    elif integrity_data.get("hash_algorithm") == "SHA512":
        hash = hashes.SHA512()
    else:
        return 404

    h = hmac.HMAC(key, hash, backend=default_backend())
    h.update(encrypted_data)
    try:
        h.verify(mac)
        print("Integrity check passed.")
    except Exception as e:
        print("integrity check failed")
        return -1

    if encryption_data.get("algorithm") == "AES":
        algorithm = algorithms.AES(key)
        block_size = 128
    elif encryption_data.get("algorithm") == "ChaCha20":
        algorithm = algorithms.TripleDES(key)
        block_size = 64
    else:
        return 404

    if encryption_data.get("mode") == "CBC":
        mode = modes.CBC(iv)
    elif encryption_data.get("mode") == "ECB":
        mode = modes.ECB()
    elif encryption_data.get("mode") == "OFB":
        mode = modes.OFB(iv)
    elif encryption_data.get("mode") == "CFB":
        mode = modes.CFB(iv)
    elif encryption_data.get("mode") == "CTR":
        mode = modes.CTR(iv)
    else:
        return 404

    cipher = Cipher(algorithm, mode, backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    content = unpadded_data

    return content


def encrypt_json_asym(data, public_key):
    json_data = json.dumps(data).encode("utf-8")

    checksum = hashlib.sha256(json_data).hexdigest()

    timestamp = int(time.time())

    payload = {
        "data": json_data.decode(),
        "checksum": checksum,
        "timestamp": timestamp,
    }

    payload_bytes = json.dumps(payload).encode("utf-8")

    pub_key = load_pem_public_key(public_key.encode(), backend=default_backend())

    max_chunk_size = pub_key.key_size // 8 - 66

    chunks = [
        payload_bytes[i : i + max_chunk_size]
        for i in range(0, len(payload_bytes), max_chunk_size)
    ]

    encrypted_chunks = []
    for chunk in chunks:
        encrypted_chunk = pub_key.encrypt(
            chunk,
            as_padding.OAEP(
                mgf=as_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        encrypted_chunks.append(base64.b64encode(encrypted_chunk).decode())

    return encrypted_chunks


def decrypt_json_asym(encrypted_chunks, private_key, time_threshold=30):
    # print(type(encrypted_chunks))
    decrypted_payload = b""
    for encrypted_chunk in encrypted_chunks:
        chunk_bytes = base64.b64decode(encrypted_chunk)
        decrypted_chunk = private_key.decrypt(
            chunk_bytes,
            as_padding.OAEP(
                mgf=as_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        decrypted_payload += decrypted_chunk

    payload = json.loads(decrypted_payload)
    data = payload.get("data")
    original_checksum = payload.get("checksum")
    timestamp = payload.get("timestamp")

    recomputed_checksum = hashlib.sha256(data.encode()).hexdigest()
    if recomputed_checksum != original_checksum:
        raise ValueError("Data integrity check failed: Checksum does not match.")

    current_time = int(time.time())
    if current_time - timestamp > time_threshold:
        raise ValueError("Timestamp check failed: Message is too old.")

    # Return the original data if all checks pass
    return json.loads(data)


def encrypt_json_sym(data, symmetric_key):
    json_data = json.dumps(data).encode("utf-8")
    checksum = hashlib.sha256(json_data).hexdigest()
    timestamp = int(time.time())

    # Prepare the payload
    payload = {
        "data": json_data.decode(),
        "checksum": checksum,
        "timestamp": timestamp,
    }
    payload_bytes = json.dumps(payload).encode("utf-8")

    # Generate an IV (Initialization Vector)
    iv = os.urandom(16)

    # Create AES-CBC cipher
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pad the payload to make it compatible with AES block size (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_payload = padder.update(payload_bytes) + padder.finalize()

    # Encrypt the padded payload
    encrypted_payload = encryptor.update(padded_payload) + encryptor.finalize()

    # Encode the encrypted payload and IV as base64 for transmission
    message = base64.b64encode(iv + encrypted_payload).decode("utf-8")

    return message


def decrypt_json_sym(encrypted_data, symmetric_key):
    data = base64.b64decode(encrypted_data)

    iv = data[:16]
    ciphertext = data[16:]

    # Create AES-CBC cipher
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_payload = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext_bytes = unpadder.update(padded_payload) + unpadder.finalize()

    # Convert the plaintext bytes back into the original payload (JSON format)
    plaintext = plaintext_bytes.decode("utf-8")
    payload = json.loads(plaintext)

    return payload
