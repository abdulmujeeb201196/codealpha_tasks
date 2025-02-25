import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ENCRYPTION_KEY = os.urandom(32)  # Store securely
IV_LENGTH = 16  # AES block size

def encrypt_file(input_path: str, output_path: str):
    iv = os.urandom(IV_LENGTH)
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()

    with open(input_path, "rb") as f:
        plaintext = f.read()
        padding = 16 - len(plaintext) % 16
        plaintext += bytes([padding] * padding)

    with open(output_path, "wb") as f:
        f.write(iv + encryptor.update(plaintext) + encryptor.finalize())

def decrypt_file(input_path: str, output_path: str):
    with open(input_path, "rb") as f:
        iv = f.read(IV_LENGTH)
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    padding = plaintext[-1]
    with open(output_path, "wb") as f:
        f.write(plaintext[:-padding])
