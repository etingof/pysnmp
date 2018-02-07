""""""
from pysnmp.crypto import backend, CRYPTODOME, CRYPTOGRPAHY, des3, generic_decrypt, generic_encrypt, raise_backend_error

if backend == CRYPTODOME:
    from Cryptodome.Cipher import DES


def _cryptodome_cipher(key, iv):
    """"""
    return DES.new(key, DES.MODE_CBC, iv)


_CIPHER_FACTORY_MAP = {
    CRYPTODOME: _cryptodome_cipher,
    None: raise_backend_error
}


def encrypt(plaintext, key, iv):
    """"""
    if backend == CRYPTOGRPAHY:
        return des3.encrypt(plaintext, key * 3, iv)
    return generic_encrypt(_CIPHER_FACTORY_MAP, plaintext, key, iv)


def decrypt(plaintext, key, iv):
    """"""
    if backend == CRYPTOGRPAHY:
        return des3.decrypt(plaintext, key * 3, iv)
    return generic_decrypt(_CIPHER_FACTORY_MAP, plaintext, key, iv)
