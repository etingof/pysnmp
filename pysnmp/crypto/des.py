"""
Crypto logic for RFC3414.

https://tools.ietf.org/html/rfc3414
"""
from pysnmp.crypto import backend, CRYPTODOME, CRYPTOGRPAHY, des3, generic_decrypt, generic_encrypt

if backend == CRYPTODOME:
    from Cryptodome.Cipher import DES


def _cryptodome_cipher(key, iv):
    """Build a Pycryptodome DES Cipher object.

    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: DES Cipher instance
    """
    return DES.new(key, DES.MODE_CBC, iv)


_CIPHER_FACTORY_MAP = {
    CRYPTODOME: _cryptodome_cipher
}

# Cryptography does not support DES directly because it is a seriously old, insecure,
# and deprecated algorithm. However, triple DES is just three rounds of DES (encrypt,
# decrypt, encrypt) done by taking a key three times the size of a DES key and breaking
# it into three pieces. So triple DES with des_key * 3 is equivalent to DES.
# Pycryptodome's triple DES implementation will actually throw an error if it receives
# a key that reduces to DES.


def encrypt(plaintext, key, iv):
    """Encrypt data using DES on the available backend.

    :param bytes plaintext: Plaintext data to encrypt
    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: Encrypted ciphertext
    :rtype: bytes
    """
    if backend == CRYPTOGRPAHY:
        return des3.encrypt(plaintext, key * 3, iv)
    return generic_encrypt(_CIPHER_FACTORY_MAP, plaintext, key, iv)


def decrypt(ciphertext, key, iv):
    """Decrypt data using DES on the available backend.

    :param bytes ciphertext: Ciphertext data to decrypt
    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: Decrypted plaintext
    :rtype: bytes
    """
    if backend == CRYPTOGRPAHY:
        return des3.decrypt(ciphertext, key * 3, iv)
    return generic_decrypt(_CIPHER_FACTORY_MAP, ciphertext, key, iv)
