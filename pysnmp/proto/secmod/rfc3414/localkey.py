#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
try:
    from hashlib import md5, sha1

except ImportError:
    import md5
    import sha

    md5 = md5.new
    sha1 = sha.new

from pyasn1.type import univ


def hashPassphrase(passphrase, hashFunc):
    passphrase = univ.OctetString(passphrase).asOctets()
    # noinspection PyDeprecation,PyCallingNonCallable
    hasher = hashFunc()
    ringBuffer = passphrase * (64 // len(passphrase) + 1)
    # noinspection PyTypeChecker
    ringBufferLen = len(ringBuffer)
    count = 0
    mark = 0
    while count < 16384:
        e = mark + 64
        if e < ringBufferLen:
            hasher.update(ringBuffer[mark:e])
            mark = e
        else:
            hasher.update(
                ringBuffer[mark:ringBufferLen] + ringBuffer[0:e - ringBufferLen]
            )
            mark = e - ringBufferLen
        count += 1
    return hasher.digest()


def passwordToKey(passphrase, snmpEngineId, hashFunc):
    return localizeKey(hashPassphrase(passphrase, hashFunc), snmpEngineId, hashFunc)


def localizeKey(passKey, snmpEngineId, hashFunc):
    passKey = univ.OctetString(passKey).asOctets()
    # noinspection PyDeprecation,PyCallingNonCallable
    return hashFunc(passKey + snmpEngineId.asOctets() + passKey).digest()


# RFC3414: A.2.1
def hashPassphraseMD5(passphrase):
    return hashPassphrase(passphrase, md5)


# RFC3414: A.2.2
def hashPassphraseSHA(passphrase):
    return hashPassphrase(passphrase, sha1)


def passwordToKeyMD5(passphrase, snmpEngineId):
    return localizeKey(hashPassphraseMD5(passphrase), snmpEngineId, md5)


def passwordToKeySHA(passphrase, snmpEngineId):
    return localizeKey(hashPassphraseMD5(passphrase), snmpEngineId, sha1)


def localizeKeyMD5(passKey, snmpEngineId):
    return localizeKey(passKey, snmpEngineId, md5)


def localizeKeySHA(passKey, snmpEngineId):
    return localizeKey(passKey, snmpEngineId, sha1)
