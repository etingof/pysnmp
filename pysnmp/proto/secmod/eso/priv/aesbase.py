#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.proto.secmod.rfc3826.priv import aes
from pysnmp.proto.secmod.rfc3414.auth import hmacmd5, hmacsha
from pysnmp.proto.secmod.rfc7860.auth import hmacsha2
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.proto import error
from math import ceil

try:
    from hashlib import md5, sha1
except ImportError:
    import md5
    import sha

    md5 = md5.new
    sha1 = sha.new


class AbstractAesBlumenthal(aes.Aes):
    serviceID = ()
    keySize = 0

    # 3.1.2.1
    def localizeKey(self, authProtocol, privKey, snmpEngineID):
        if authProtocol == hmacmd5.HmacMd5.serviceID:
            hashAlgo = md5
        elif authProtocol == hmacsha.HmacSha.serviceID:
            hashAlgo = sha1
        elif authProtocol in hmacsha2.HmacSha2.hashAlgorithms:
            hashAlgo = hmacsha2.HmacSha2.hashAlgorithms[authProtocol]
        else:
            raise error.ProtocolError(
                'Unknown auth protocol %s' % (authProtocol,)
            )

        localPrivKey = localkey.localizeKey(privKey, snmpEngineID, hashAlgo)

        # now extend this key if too short by repeating steps that includes the hashPassphrase step
        for count in range(1, int(ceil(self.keySize * 1.0 / len(localPrivKey)))):
            localPrivKey += hashAlgo(localPrivKey).digest()

        return localPrivKey[:self.keySize]


class AbstractAesReeder(aes.Aes):
    """AES encryption with non-standard key localization.

    Many vendors (including Cisco) do not use:

    https://tools.itef.org/pdf/draft_bluementhal-aes-usm-04.txt

    for key localization instead, they use the procedure for 3DES key localization
    specified in:

    https://tools.itef.org/pdf/draft_reeder_snmpv3-usm-3desede-00.pdf

    The difference between the two is that the Reeder draft does key extension by repeating
    the steps in the password to key algorithm (hash phrase, then localize with SNMPEngine ID).
    """
    serviceID = ()
    keySize = 0

    # 2.1 of https://tools.itef.org/pdf/draft_bluementhal-aes-usm-04.txt
    def localizeKey(self, authProtocol, privKey, snmpEngineID):
        if authProtocol == hmacmd5.HmacMd5.serviceID:
            hashAlgo = md5
        elif authProtocol == hmacsha.HmacSha.serviceID:
            hashAlgo = sha1
        elif authProtocol in hmacsha2.HmacSha2.hashAlgorithms:
            hashAlgo = hmacsha2.HmacSha2.hashAlgorithms[authProtocol]
        else:
            raise error.ProtocolError(
                'Unknown auth protocol %s' % (authProtocol,)
            )

        localPrivKey = localkey.localizeKey(privKey, snmpEngineID, hashAlgo)

        # now extend this key if too short by repeating steps that includes the hashPassphrase step
        while len(localPrivKey) < self.keySize:
            # this is the difference between reeder and bluementhal
            newKey = localkey.hashPassphrase(localPrivKey, hashAlgo)
            localPrivKey += localkey.localizeKey(newKey, snmpEngineID, hashAlgo)

        return localPrivKey[:self.keySize]
