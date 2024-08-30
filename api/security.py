from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

from .conf import SECRET_ENCRYPTION_KEY
 
def encrypt(plaintext, initialization_vector):
    # Getting encryption key in bytes.
    key = bytes(SECRET_ENCRYPTION_KEY, "utf-8")
    # Convert plaintext to bytes.
    plaintext_bytes = bytes(plaintext, "utf-8")

    # Building an AES cipher using generated IV.
    cipher = Cipher(algorithms.AES(key),
                        modes.CBC(initialization_vector),
                        default_backend())

    # Block ciphers require the plain text to be a size multiple of their block size so padding may be needed.
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_text = padder.update(plaintext_bytes)
    padded_text += padder.finalize()

    # Encrypting the correct length padded plaintext.
    encryptor = cipher.encryptor()
    encrypted_text_bytes = encryptor.update(padded_text) + encryptor.finalize()

    # Converting encrypted bytes to hexidecimal.
    encrypted_text = encrypted_text_bytes.hex()

    return encrypted_text

def decrypt(encrypted_text, initialization_vector):
    # Getting encryption key in bytes.
    key = bytes(SECRET_ENCRYPTION_KEY, "utf-8")
    # Convert encrypted text from hex to bytes.
    encrypted_text_bytes = bytes.fromhex(encrypted_text)

    # Building an AES cipher using generated IV.
    cipher = Cipher(algorithms.AES(key),
                        modes.CBC(initialization_vector),
                        default_backend())

    # Decrypting the encrypted text.
    decryptor = cipher.decryptor()
    padded_text = decryptor.update(encrypted_text_bytes) + decryptor.finalize()

    # Removing any padding that was added to the original plaintext.
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_text = unpadder.update(padded_text)
    unpadded_text += unpadder.finalize()

    # Converting bytes to string.
    plaintext = str(unpadded_text, 'utf-8')

    return plaintext

def kdf_hash(password, salt):
    # Building a key derivation function hash using scrypt.
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    # Converting password to bytes.
    password_bytes = bytes(password, "utf-8")
    # Hashing password.
    hashed_password = kdf.derive(password_bytes)
    # Returning hexidecimal hashed password.
    return hashed_password.hex()

def basic_hash(email):
    # Converting email to bytes.
    email_bytes = bytes(email, "utf-8")
    # Building a SHA2 hash.
    digest = hashes.Hash(hashes.SHA256())
    # Hashing the email.
    digest.update(email_bytes)
    hashed_email = digest.finalize()
    # Returning hexidecimal hashed email.
    return hashed_email.hex()
