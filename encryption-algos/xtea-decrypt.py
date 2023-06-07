from ctypes import c_uint32
from binascii import unhexlify
from math import ceil


# edit here
CIPHERTEXT = b''
KEY = b''


def bytes_to_vector(b: bytearray):
    return [int.from_bytes(b[:4], byteorder='big'), int.from_bytes(b[4:8], byteorder='big')]


def _decrypt(v, key):
    v1, v0 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x9E3779B9
    total = c_uint32(delta * 32)
    for _ in range(32):
        v1.value -= (((v0.value << 4) ^ (v0.value >> 5)) +
                     v0.value) ^ (total.value + key[(total.value >> 11) & 3])
        total.value -= delta
        v0.value -= (((v1.value << 4) ^ (v1.value >> 5)) +
                     v1.value) ^ (total.value + key[total.value & 3])
    return v0.value, v1.value


def decrypt(ciphertext: bytearray, key: bytearray):
    blocks = ceil(len(ciphertext) / 4.0)
    plaintext = ''
    for index in range(0, blocks, 2):
        # transform into vector
        v = bytes_to_vector(ciphertext[index*4:])
        p1, p2 = _decrypt(v, key)
        plaintext += unhexlify(hex(p1)[2:]).decode()[::-1]
        plaintext += unhexlify(hex(p2)[2:]).decode()[::-1]
    return plaintext


plaintext = decrypt(CIPHERTEXT, KEY)
print(plaintext)
