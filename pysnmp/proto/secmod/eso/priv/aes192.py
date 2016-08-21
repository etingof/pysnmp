#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysnmp.sf.net/license.html
#
from pysnmp.proto.secmod.eso.priv import aesbase


class Aes192(aesbase.AbstractAes):
    """AES 192 bit encryption (Internet draft)

       Reeder AES encryption:

       http://tools.ietf.org/html/draft-blumenthal-aes-usm-04
    """
    serviceID = (1, 3, 6, 1, 4, 1, 9, 12, 6, 1, 1)  # cusmAESCfb192PrivProtocol
    keySize = 24


class AesReeder192(aesbase.AbstractAesReeder):
    """AES 192 bit encryption (Internet draft)

    Reeder AES encryption with non-standard key localization algorithm
    borrowed from Reeder 3DES draft:

    http://tools.ietf.org/html/draft-blumenthal-aes-usm-04
    https://tools.ietf.org/html/draft-reeder-snmpv3-usm-3desede-00

    Known to be used by many vendors including Cisco and others.
    """
    serviceID = (1, 3, 6, 1, 4, 1, 9, 12, 6, 1, 101)  # cusmAESCfb192PrivProtocol (non-standard)
    keySize = 24
