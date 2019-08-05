#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.hlapi.v3arch import auth
from pysnmp.hlapi.v3arch.context import *
from pysnmp.proto.rfc1902 import *
from pysnmp.proto.rfc1905 import EndOfMibView
from pysnmp.proto.rfc1905 import NoSuchInstance
from pysnmp.proto.rfc1905 import NoSuchObject
from pysnmp.smi.rfc1902 import *
from pysnmp.entity.engine import *

# default is synchronous asyncore-based API
from pysnmp.hlapi.v3arch.asyncore.sync import *

USM_AUTH_NONE = auth.USM_AUTH_NONE
"""No Authentication Protocol"""

USM_AUTH_HMAC96_MD5 = auth.USM_AUTH_HMAC96_MD5
"""The HMAC-MD5-96 Digest Authentication Protocol (:RFC:`3414#section-6`)"""

USM_AUTH_HMAC96_SHA = auth.USM_AUTH_HMAC96_SHA
"""The HMAC-SHA-96 Digest Authentication Protocol AKA SHA-1 \
(:RFC:`3414#section-7`)"""

USM_AUTH_HMAC128_SHA224 = auth.USM_AUTH_HMAC128_SHA224
"""The HMAC-SHA-2 Digest Authentication Protocols (:RFC:`7860`)"""

USM_AUTH_HMAC192_SHA256 = auth.USM_AUTH_HMAC192_SHA256
"""The HMAC-SHA-2 Digest Authentication Protocols (:RFC:`7860`)"""

USM_AUTH_HMAC256_SHA384 = auth.USM_AUTH_HMAC256_SHA384
"""The HMAC-SHA-2 Digest Authentication Protocols (:RFC:`7860`)"""

USM_AUTH_HMAC384_SHA512 = auth.USM_AUTH_HMAC384_SHA512
"""The HMAC-SHA-2 Digest Authentication Protocols (:RFC:`7860`)"""

USM_PRIV_NONE = auth.USM_PRIV_NONE
"""No Privacy Protocol"""

USM_PRIV_CBC56_DES = auth.USM_PRIV_CBC56_DES
"""The CBC-DES Symmetric Encryption Protocol (:RFC:`3414#section-8`)"""

USM_PRIV_CBC168_3DES = auth.USM_PRIV_CBC168_3DES
"""The 3DES-EDE Symmetric Encryption Protocol (`draft-reeder-snmpv3-usm-3desede-00 \
<https:://tools.ietf.org/html/draft-reeder-snmpv3-usm-3desede-00#section-5>`_)"""

USM_PRIV_CFB128_AES = auth.USM_PRIV_CFB128_AES
"""The CFB128-AES-128 Symmetric Encryption Protocol (:RFC:`3826#section-3`)"""

USM_PRIV_CFB192_AES = auth.USM_PRIV_CFB192_AES
"""The CFB128-AES-192 Symmetric Encryption Protocol (`draft-blumenthal-aes-usm-04 \
<https:://tools.ietf.org/html/draft-blumenthal-aes-usm-04#section-3>`_) with \
Reeder key localization"""

USM_PRIV_CFB256_AES = auth.USM_PRIV_CFB256_AES
"""The CFB128-AES-256 Symmetric Encryption Protocol (`draft-blumenthal-aes-usm-04 \
<https:://tools.ietf.org/html/draft-blumenthal-aes-usm-04#section-3>`_) with \
Reeder key localization"""

USM_PRIV_CFB192_AES_BLUMENTHAL = auth.USM_PRIV_CFB192_AES_BLUMENTHAL
"""The CFB128-AES-192 Symmetric Encryption Protocol (`draft-blumenthal-aes-usm-04 \
<https:://tools.ietf.org/html/draft-blumenthal-aes-usm-04#section-3>`_)"""

USM_PRIV_CFB256_AES_BLUMENTHAL = auth.USM_PRIV_CFB256_AES_BLUMENTHAL
"""The CFB128-AES-256 Symmetric Encryption Protocol (`draft-blumenthal-aes-usm-04 \
<https:://tools.ietf.org/html/draft-blumenthal-aes-usm-04#section-3>`_)"""

USM_KEY_TYPE_PASSPHRASE = auth.USM_KEY_TYPE_PASSPHRASE
"""USM key material type - plain-text pass phrase (:RFC:`3414#section-2.6`)"""

USM_KEY_TYPE_MASTER = auth.USM_KEY_TYPE_MASTER
"""USM key material type - hashed pass-phrase AKA master key \
(:RFC:`3414#section-2.6`)"""

USM_KEY_TYPE_LOCALIZED = auth.USM_KEY_TYPE_LOCALIZED
"""USM key material type - hashed pass-phrase hashed with Context SNMP Engine \
ID (:RFC:`3414#section-2.6`)"""

# Backward-compatible protocol IDs

usmNoAuthProtocol = USM_AUTH_NONE
usmHMACMD5AuthProtocol = USM_AUTH_HMAC96_MD5
usmHMACSHAAuthProtocol = USM_AUTH_HMAC96_SHA
usmHMAC128SHA224AuthProtocol = USM_AUTH_HMAC128_SHA224
usmHMAC192SHA256AuthProtocol = USM_AUTH_HMAC192_SHA256
usmHMAC256SHA384AuthProtocol = USM_AUTH_HMAC256_SHA384
usmHMAC384SHA512AuthProtocol = USM_AUTH_HMAC384_SHA512
usmNoPrivProtocol = USM_PRIV_NONE
usmDESPrivProtocol = USM_PRIV_CBC56_DES
usm3DESEDEPrivProtocol = USM_PRIV_CBC168_3DES
usmAesCfb128Protocol = USM_PRIV_CFB128_AES
usmAesCfb192Protocol = USM_PRIV_CFB192_AES
usmAesCfb256Protocol = USM_PRIV_CFB256_AES
usmAesBlumenthalCfb192Protocol = USM_PRIV_CFB192_AES_BLUMENTHAL
usmAesBlumenthalCfb256Protocol = USM_PRIV_CFB256_AES_BLUMENTHAL

usmKeyTypePassphrase = USM_KEY_TYPE_PASSPHRASE
usmKeyTypeMaster = USM_KEY_TYPE_MASTER
usmKeyTypeLocalized = USM_KEY_TYPE_LOCALIZED
