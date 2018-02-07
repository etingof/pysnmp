"""Backend-independent cryptographic implementations to allow migration to pyca/cryptography
without immediately dropping support for legacy minor Python versions.
"""
from pysnmp.proto import errind, error
CRYPTOGRPAHY = 'cryptography'
CRYPTODOME = 'Cryptodome'
try:
    import cryptography
    backend = CRYPTOGRPAHY
except ImportError:
    try:
        import Cryptodome
        backend = CRYPTODOME
    except ImportError:
        backend = None


def raise_backend_error(*args, **kwargs):
    raise error.StatusInformation(
        errorIndication=errind.decryptionError
    )


def _cryptodome_encrypt(cipher_factory, plaintext, key, iv):
    """"""
    encryptor = cipher_factory(key, iv)
    return encryptor.encrypt(plaintext)


def _cryptodome_decrypt(cipher_factory, ciphertext, key, iv):
    """"""
    decryptor = cipher_factory(key, iv)
    return decryptor.decrypt(ciphertext)


def _cryptography_encrypt(cipher_factory, plaintext, key, iv):
    """"""
    encryptor = cipher_factory(key, iv).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def _cryptography_decrypt(cipher_factory, ciphertext, key, iv):
    """"""
    decryptor = cipher_factory(key, iv).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


_DECRYPT_MAP = {
    CRYPTOGRPAHY: _cryptography_decrypt,
    CRYPTODOME: _cryptodome_decrypt,
    None: raise_backend_error
}
_ENCRYPT_MAP = {
    CRYPTOGRPAHY: _cryptography_encrypt,
    CRYPTODOME: _cryptodome_encrypt,
    None: raise_backend_error
}


def generic_encrypt(cipher_factory_map, plaintext, key, iv):
    """"""
    return _ENCRYPT_MAP[backend](cipher_factory_map[backend], plaintext, key, iv)


def generic_decrypt(cipher_factory_map, plaintext, key, iv):
    """"""
    return _DECRYPT_MAP[backend](cipher_factory_map[backend], plaintext, key, iv)
