""""""
from pysnmp.crypto import backend, CRYPTODOME, CRYPTOGRPAHY, generic_decrypt, generic_encrypt, raise_backend_error

if backend == CRYPTOGRPAHY:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
elif backend == CRYPTODOME:
    from Cryptodome.Cipher import DES3


def _cryptodome_cipher(key, iv):
    """"""
    return DES3.new(key, DES3.MODE_CBC, iv)


def _cryptography_cipher(key, iv):
    """"""
    return Cipher(
        algorithm=algorithms.TripleDES(key),
        mode=modes.CBC(iv),
        backend=default_backend()
    )


_CIPHER_FACTORY_MAP = {
    CRYPTOGRPAHY: _cryptography_cipher,
    CRYPTODOME: _cryptodome_cipher,
    None: raise_backend_error
}


def encrypt(plaintext, key, iv):
    """"""
    return generic_encrypt(_CIPHER_FACTORY_MAP, plaintext, key, iv)


def decrypt(plaintext, key, iv):
    """"""
    return generic_decrypt(_CIPHER_FACTORY_MAP, plaintext, key, iv)
