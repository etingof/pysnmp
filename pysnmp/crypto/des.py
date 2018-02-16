"""
Crypto logic for RFC3414.

https://tools.ietf.org/html/rfc3414
"""
from pysnmp.crypto import backend, CRYPTODOME, CRYPTOGRAPHY, generic_decrypt, generic_encrypt

if backend == CRYPTOGRAPHY:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
elif backend == CRYPTODOME:
    from Cryptodome.Cipher import DES


def _cryptodome_cipher(key, iv):
    """Build a Pycryptodome DES Cipher object.

    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: DES Cipher instance
    """
    return DES.new(key, DES.MODE_CBC, iv)


def _cryptography_cipher(key, iv):
    """Build a cryptography DES(-like) Cipher object.

    .. note::

        pyca/cryptography does not support DES directly because it is a seriously old, insecure,
        and deprecated algorithm. However, triple DES is just three rounds of DES (encrypt,
        decrypt, encrypt) done by taking a key three times the size of a DES key and breaking
        it into three pieces. So triple DES with des_key * 3 is equivalent to DES.

    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: TripleDES Cipher instance providing DES behavior by using provided DES key
    :rtype: cryptography.hazmat.primitives.ciphers.Cipher
    """
    return Cipher(
        algorithm=algorithms.TripleDES(key * 3),
        mode=modes.CBC(iv),
        backend=default_backend()
    )


_CIPHER_FACTORY_MAP = {
    CRYPTOGRAPHY: _cryptography_cipher,
    CRYPTODOME: _cryptodome_cipher
}


def encrypt(plaintext, key, iv):
    """Encrypt data using DES on the available backend.

    :param bytes plaintext: Plaintext data to encrypt
    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: Encrypted ciphertext
    :rtype: bytes
    """
    return generic_encrypt(_CIPHER_FACTORY_MAP, plaintext, key, iv)


def decrypt(ciphertext, key, iv):
    """Decrypt data using DES on the available backend.

    :param bytes ciphertext: Ciphertext data to decrypt
    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: Decrypted plaintext
    :rtype: bytes
    """
    return generic_decrypt(_CIPHER_FACTORY_MAP, ciphertext, key, iv)
