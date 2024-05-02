from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def generate_des_key():
    return get_random_bytes(8)

def encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(ciphertext).decode()

def decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, DES.block_size).decode()

# Generate DES key
des_key = generate_des_key()

# Example plaintext
plaintext = "Hello, World!"

# Encryption
encrypted_text = encrypt(plaintext, des_key)
print("Encrypted:", encrypted_text)

# Decryption
decrypted_text = decrypt(encrypted_text, des_key)
print("Decrypted:", decrypted_text)
