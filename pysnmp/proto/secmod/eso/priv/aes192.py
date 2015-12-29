#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysnmp.sf.net/license.html
#
from pysnmp.proto.secmod.eso.priv import aesbase

class Aes192(aesbase.AbstractAes):
    """AES 192/256 bit encryption (Internet draft)

       http://tools.ietf.org/html/draft-blumenthal-aes-usm-04
    """
    serviceID = (1, 3, 6, 1, 4, 1, 9, 12, 6, 1, 1)  # cusmAESCfb192PrivProtocol
    keySize = 24
