"""Backend-selecting cryptographic logic to allow migration to pyca/cryptography
without immediately dropping support for legacy minor Python versions.

On installation, the correct backend dependency is selected based on the Python
version. Versions that are supported by pyca/cryptography use that backend; all
other versions (currently 2.4, 2.5, 2.6, 3.2, and 3.3) fall back to Pycryptodome.
"""
from pysnmp.proto import errind, error
CRYPTOGRPAHY = 'cryptography'
CRYPTODOME = 'Cryptodome'

# Determine the available backend. Always prefer cryptography if it is available.
try:
    import cryptography
    backend = CRYPTOGRPAHY
except ImportError:
    try:
        import Cryptodome
        backend = CRYPTODOME
    except ImportError:
        backend = None


def _cryptodome_encrypt(cipher_factory, plaintext, key, iv):
    """Use a Pycryptodome cipher factory to encrypt data.

    :param cipher_factory: Factory callable that builds a Pycryptodome Cipher instance based
    on the key and IV
    :type cipher_factory: callable
    :param bytes plaintext: Plaintext data to encrypt
    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: Encrypted ciphertext
    :rtype: bytes
    """
    encryptor = cipher_factory(key, iv)
    return encryptor.encrypt(plaintext)


def _cryptodome_decrypt(cipher_factory, ciphertext, key, iv):
    """Use a Pycryptodome cipher factory to decrypt data.

    :param cipher_factory: Factory callable that builds a Pycryptodome Cipher instance based
    on the key and IV
    :type cipher_factory: callable
    :param bytes ciphertext: Ciphertext data to decrypt
    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: Decrypted plaintext
    :rtype: bytes
    """
    decryptor = cipher_factory(key, iv)
    return decryptor.decrypt(ciphertext)


def _cryptography_encrypt(cipher_factory, plaintext, key, iv):
    """Use a cryptography cipher factory to encrypt data.

    :param cipher_factory: Factory callable that builds a cryptography Cipher instance based
    on the key and IV
    :type cipher_factory: callable
    :param bytes plaintext: Plaintext data to encrypt
    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: Encrypted ciphertext
    :rtype: bytes
    """
    encryptor = cipher_factory(key, iv).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def _cryptography_decrypt(cipher_factory, ciphertext, key, iv):
    """Use a cryptography cipher factory to decrypt data.

    :param cipher_factory: Factory callable that builds a cryptography Cipher instance based
    on the key and IV
    :type cipher_factory: callable
    :param bytes ciphertext: Ciphertext data to decrypt
    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: Decrypted plaintext
    :rtype: bytes
    """
    decryptor = cipher_factory(key, iv).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


_DECRYPT_MAP = {
    CRYPTOGRPAHY: _cryptography_decrypt,
    CRYPTODOME: _cryptodome_decrypt
}
_ENCRYPT_MAP = {
    CRYPTOGRPAHY: _cryptography_encrypt,
    CRYPTODOME: _cryptodome_encrypt
}


def generic_encrypt(cipher_factory_map, plaintext, key, iv):
    """Encrypt data using the available backend.

    :param dict cipher_factory_map: Dictionary that maps the backend name to a cipher factory
    callable for that backend
    :param bytes plaintext: Plaintext data to encrypt
    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: Encrypted ciphertext
    :rtype: bytes
    """
    if backend is None:
        raise error.StatusInformation(
            errorIndication=errind.encryptionError
        )
    return _ENCRYPT_MAP[backend](cipher_factory_map[backend], plaintext, key, iv)


def generic_decrypt(cipher_factory_map, ciphertext, key, iv):
    """Decrypt data using the available backend.

    :param dict cipher_factory_map: Dictionary that maps the backend name to a cipher factory
    callable for that backend
    :param bytes ciphertext: Ciphertext data to decrypt
    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: Decrypted plaintext
    :rtype: bytes
    """
    if backend is None:
        raise error.StatusInformation(
            errorIndication=errind.decryptionError
        )
    return _DECRYPT_MAP[backend](cipher_factory_map[backend], ciphertext, key, iv)
