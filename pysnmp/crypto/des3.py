"""
Crypto logic for Reeder 3DES-EDE for USM (Internet draft).

https://tools.ietf.org/html/draft-reeder-snmpv3-usm-3desede-00
"""
from pysnmp.crypto import backend, CRYPTODOME, CRYPTOGRAPHY, generic_decrypt, generic_encrypt

if backend == CRYPTOGRAPHY:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
elif backend == CRYPTODOME:
    from Cryptodome.Cipher import DES3


def _cryptodome_cipher(key, iv):
    """Build a Pycryptodome DES3 Cipher object.

    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: DES3 Cipher instance
    """
    return DES3.new(key, DES3.MODE_CBC, iv)


def _cryptography_cipher(key, iv):
    """Build a cryptography TripleDES Cipher object.

    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: TripleDES Cipher instance
    :rtype: cryptography.hazmat.primitives.ciphers.Cipher
    """
    return Cipher(
        algorithm=algorithms.TripleDES(key),
        mode=modes.CBC(iv),
        backend=default_backend()
    )


_CIPHER_FACTORY_MAP = {
    CRYPTOGRAPHY: _cryptography_cipher,
    CRYPTODOME: _cryptodome_cipher
}


def encrypt(plaintext, key, iv):
    """Encrypt data using triple DES on the available backend.

    :param bytes plaintext: Plaintext data to encrypt
    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: Encrypted ciphertext
    :rtype: bytes
    """
    return generic_encrypt(_CIPHER_FACTORY_MAP, plaintext, key, iv)


def decrypt(ciphertext, key, iv):
    """Decrypt data using triple DES on the available backend.

    :param bytes ciphertext: Ciphertext data to decrypt
    :param bytes key: Encryption key
    :param bytes IV: Initialization vector
    :returns: Decrypted plaintext
    :rtype: bytes
    """
    return generic_decrypt(_CIPHER_FACTORY_MAP, ciphertext, key, iv)
