import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(32)
iv = os.urandom(16)
print("key: ", key)
print("iv: ", iv)


cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()

ct = encryptor.update(b"a secret message") + encryptor.finalize()
decryptor = cipher.decryptor()

pt = decryptor.update(ct) + decryptor.finalize()

print(pt)
