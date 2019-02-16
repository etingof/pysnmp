#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# ASN.1 source http://mibs.snmplabs.com:80/asn1/PYSNMP-USM-MIB
# Produced by pysmi-0.4.0 at Thu Feb 14 23:15:36 2019
#

if 'mibBuilder' not in globals():
    import sys

    sys.stderr.write(__doc__)
    sys.exit(1)

(Integer,
 OctetString,
 ObjectIdentifier) = mibBuilder.importSymbols(
    "ASN1",
    "Integer",
    "OctetString",
    "ObjectIdentifier")

(NamedValues,) = mibBuilder.importSymbols(
    "ASN1-ENUMERATION",
    "NamedValues")

(ConstraintsIntersection,
 SingleValueConstraint,
 ValueRangeConstraint,
 ValueSizeConstraint,
 ConstraintsUnion) = mibBuilder.importSymbols(
    "ASN1-REFINEMENT",
    "ConstraintsIntersection",
    "SingleValueConstraint",
    "ValueRangeConstraint",
    "ValueSizeConstraint",
    "ConstraintsUnion")

(pysnmpModuleIDs,) = mibBuilder.importSymbols(
    "PYSNMP-MIB",
    "pysnmpModuleIDs")

(SnmpAdminString,) = mibBuilder.importSymbols(
    "SNMP-FRAMEWORK-MIB",
    "SnmpAdminString")

(usmUserEntry,) = mibBuilder.importSymbols(
    "SNMP-USER-BASED-SM-MIB",
    "usmUserEntry")

(ModuleCompliance,
 NotificationGroup) = mibBuilder.importSymbols(
    "SNMPv2-CONF",
    "ModuleCompliance",
    "NotificationGroup")

(Bits,
 NotificationType,
 Counter64,
 Gauge32,
 ObjectIdentity,
 Unsigned32,
 IpAddress,
 MibIdentifier,
 Counter32,
 MibScalar,
 MibTable,
 MibTableRow,
 MibTableColumn,
 ModuleIdentity,
 iso,
 TimeTicks,
 Integer32) = mibBuilder.importSymbols(
    "SNMPv2-SMI",
    "Bits",
    "NotificationType",
    "Counter64",
    "Gauge32",
    "ObjectIdentity",
    "Unsigned32",
    "IpAddress",
    "MibIdentifier",
    "Counter32",
    "MibScalar",
    "MibTable",
    "MibTableRow",
    "MibTableColumn",
    "ModuleIdentity",
    "iso",
    "TimeTicks",
    "Integer32")

(TextualConvention,
 RowStatus,
 DisplayString) = mibBuilder.importSymbols(
    "SNMPv2-TC",
    "TextualConvention",
    "RowStatus",
    "DisplayString")

pysnmpUsmMIB = ModuleIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1)
)
pysnmpUsmMIB.setRevisions(
        ("2017-04-14 00:00",
         "2005-05-14 00:00")
)
pysnmpUsmMIB.setLastUpdated("201704140000Z")
if mibBuilder.loadTexts:
    pysnmpUsmMIB.setOrganization("""\
The PySNMP Project
""")
pysnmpUsmMIB.setContactInfo("""\
E-mail: Ilya Etingof <etingof@gmail.com> GitHub:
https://github.com/etingof/pysnmp
""")
if mibBuilder.loadTexts:
    pysnmpUsmMIB.setDescription("""\
This MIB module defines objects specific to User Security Model (USM)
implementation at PySNMP.
""")

_PysnmpUsmMIBObjects_ObjectIdentity = ObjectIdentity
pysnmpUsmMIBObjects = _PysnmpUsmMIBObjects_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1)
)
_PysnmpUsmCfg_ObjectIdentity = ObjectIdentity
pysnmpUsmCfg = _PysnmpUsmCfg_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 1)
)


class _PysnmpUsmDiscoverable_Type(Integer32):
    defaultValue = 1

    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(0,
              1)
        )
    )
    namedValues = NamedValues(
        *(("discoverable", 1),
          ("notDiscoverable", 0))
    )


_PysnmpUsmDiscoverable_Type.__name__ = "Integer32"
_PysnmpUsmDiscoverable_Object = MibScalar
pysnmpUsmDiscoverable = _PysnmpUsmDiscoverable_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 1, 1),
    _PysnmpUsmDiscoverable_Type()
)
pysnmpUsmDiscoverable.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    pysnmpUsmDiscoverable.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmDiscoverable.setDescription("""\
Whether SNMP engine would support its discovery by responding to unknown
clients.
""")


class _PysnmpUsmDiscovery_Type(Integer32):
    defaultValue = 1

    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(0,
              1)
        )
    )
    namedValues = NamedValues(
        *(("doDiscover", 1),
          ("doNotDiscover", 0))
    )


_PysnmpUsmDiscovery_Type.__name__ = "Integer32"
_PysnmpUsmDiscovery_Object = MibScalar
pysnmpUsmDiscovery = _PysnmpUsmDiscovery_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 1, 2),
    _PysnmpUsmDiscovery_Type()
)
pysnmpUsmDiscovery.setMaxAccess("read-write")
if mibBuilder.loadTexts:
    pysnmpUsmDiscovery.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmDiscovery.setDescription("""\
Whether SNMP engine would try to figure out the EngineIDs of its peers by
sending discover requests.
""")
_PysnmpUsmSecretTable_Object = MibTable
pysnmpUsmSecretTable = _PysnmpUsmSecretTable_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 2)
)
if mibBuilder.loadTexts:
    pysnmpUsmSecretTable.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmSecretTable.setDescription("""\
The table of USM users passphrases configured in the SNMP engine's Local
Configuration Datastore (LCD).
""")
_PysnmpUsmSecretEntry_Object = MibTableRow
pysnmpUsmSecretEntry = _PysnmpUsmSecretEntry_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 2, 1)
)
pysnmpUsmSecretEntry.setIndexNames(
    (1, "PYSNMP-USM-MIB", "pysnmpUsmSecretUserName"),
)
if mibBuilder.loadTexts:
    pysnmpUsmSecretEntry.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmSecretEntry.setDescription("""\
Information about a particular USM user credentials.
""")


class _PysnmpUsmSecretUserName_Type(SnmpAdminString):
    subtypeSpec = SnmpAdminString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(1, 32),
    )


_PysnmpUsmSecretUserName_Type.__name__ = "SnmpAdminString"
_PysnmpUsmSecretUserName_Object = MibTableColumn
pysnmpUsmSecretUserName = _PysnmpUsmSecretUserName_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 2, 1, 1),
    _PysnmpUsmSecretUserName_Type()
)
pysnmpUsmSecretUserName.setMaxAccess("not-accessible")
if mibBuilder.loadTexts:
    pysnmpUsmSecretUserName.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmSecretUserName.setDescription("""\
The username string for which a row in this table represents a configuration.
""")


class _PysnmpUsmSecretAuthKey_Type(OctetString):
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(8, 65535),
    )
    defaultHexValue = '0000000000000000'


_PysnmpUsmSecretAuthKey_Type.__name__ = "OctetString"
_PysnmpUsmSecretAuthKey_Object = MibTableColumn
pysnmpUsmSecretAuthKey = _PysnmpUsmSecretAuthKey_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 2, 1, 2),
    _PysnmpUsmSecretAuthKey_Type()
)
pysnmpUsmSecretAuthKey.setMaxAccess("not-accessible")
if mibBuilder.loadTexts:
    pysnmpUsmSecretAuthKey.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmSecretAuthKey.setDescription("""\
User's authentication passphrase used for localized key generation.
""")


class _PysnmpUsmSecretPrivKey_Type(OctetString):
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(8, 65535),
    )
    defaultHexValue = '0000000000000000'


_PysnmpUsmSecretPrivKey_Type.__name__ = "OctetString"
_PysnmpUsmSecretPrivKey_Object = MibTableColumn
pysnmpUsmSecretPrivKey = _PysnmpUsmSecretPrivKey_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 2, 1, 3),
    _PysnmpUsmSecretPrivKey_Type()
)
pysnmpUsmSecretPrivKey.setMaxAccess("not-accessible")
if mibBuilder.loadTexts:
    pysnmpUsmSecretPrivKey.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmSecretPrivKey.setDescription("""\
User's encryption passphrase used for localized key generation.
""")
_PysnmpUsmSecretStatus_Type = RowStatus
_PysnmpUsmSecretStatus_Object = MibTableColumn
pysnmpUsmSecretStatus = _PysnmpUsmSecretStatus_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 2, 1, 4),
    _PysnmpUsmSecretStatus_Type()
)
pysnmpUsmSecretStatus.setMaxAccess("read-create")
if mibBuilder.loadTexts:
    pysnmpUsmSecretStatus.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmSecretStatus.setDescription("""\
Table status
""")
_PysnmpUsmUser_ObjectIdentity = ObjectIdentity
pysnmpUsmUser = _PysnmpUsmUser_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3)
)
_PysnmpUsmKeyTable_Object = MibTable
pysnmpUsmKeyTable = _PysnmpUsmKeyTable_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3)
)
if mibBuilder.loadTexts:
    pysnmpUsmKeyTable.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmKeyTable.setDescription("""\
The table of USM users localized keys configured in the SNMP engine's Local
Configuration Datastore (LCD).
""")
_PysnmpUsmKeyEntry_Object = MibTableRow
pysnmpUsmKeyEntry = _PysnmpUsmKeyEntry_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3, 1)
)
usmUserEntry.registerAugmentions(
    ("PYSNMP-USM-MIB",
     "pysnmpUsmKeyEntry")
)
pysnmpUsmKeyEntry.setIndexNames(*usmUserEntry.getIndexNames())
if mibBuilder.loadTexts:
    pysnmpUsmKeyEntry.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmKeyEntry.setDescription("""\
Information about a particular USM user credentials.
""")


class _PysnmpUsmKeyAuthLocalized_Type(OctetString):
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(8, 32),
    )
    defaultHexValue = '0000000000000000'


_PysnmpUsmKeyAuthLocalized_Type.__name__ = "OctetString"
_PysnmpUsmKeyAuthLocalized_Object = MibTableColumn
pysnmpUsmKeyAuthLocalized = _PysnmpUsmKeyAuthLocalized_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3, 1, 1),
    _PysnmpUsmKeyAuthLocalized_Type()
)
pysnmpUsmKeyAuthLocalized.setMaxAccess("not-accessible")
if mibBuilder.loadTexts:
    pysnmpUsmKeyAuthLocalized.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmKeyAuthLocalized.setDescription("""\
User's localized key used for authentication.
""")


class _PysnmpUsmKeyPrivLocalized_Type(OctetString):
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(8, 32),
    )
    defaultHexValue = '0000000000000000'


_PysnmpUsmKeyPrivLocalized_Type.__name__ = "OctetString"
_PysnmpUsmKeyPrivLocalized_Object = MibTableColumn
pysnmpUsmKeyPrivLocalized = _PysnmpUsmKeyPrivLocalized_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3, 1, 2),
    _PysnmpUsmKeyPrivLocalized_Type()
)
pysnmpUsmKeyPrivLocalized.setMaxAccess("not-accessible")
if mibBuilder.loadTexts:
    pysnmpUsmKeyPrivLocalized.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmKeyPrivLocalized.setDescription("""\
User's localized key used for encryption.
""")


class _PysnmpUsmKeyAuth_Type(OctetString):
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(8, 32),
    )
    defaultHexValue = '0000000000000000'


_PysnmpUsmKeyAuth_Type.__name__ = "OctetString"
_PysnmpUsmKeyAuth_Object = MibTableColumn
pysnmpUsmKeyAuth = _PysnmpUsmKeyAuth_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3, 1, 3),
    _PysnmpUsmKeyAuth_Type()
)
pysnmpUsmKeyAuth.setMaxAccess("not-accessible")
if mibBuilder.loadTexts:
    pysnmpUsmKeyAuth.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmKeyAuth.setDescription("""\
User's non-localized key used for authentication.
""")


class _PysnmpUsmKeyPriv_Type(OctetString):
    subtypeSpec = OctetString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(8, 32),
    )
    defaultHexValue = '0000000000000000'


_PysnmpUsmKeyPriv_Type.__name__ = "OctetString"
_PysnmpUsmKeyPriv_Object = MibTableColumn
pysnmpUsmKeyPriv = _PysnmpUsmKeyPriv_Object(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3, 1, 4),
    _PysnmpUsmKeyPriv_Type()
)
pysnmpUsmKeyPriv.setMaxAccess("not-accessible")
if mibBuilder.loadTexts:
    pysnmpUsmKeyPriv.setStatus("current")
if mibBuilder.loadTexts:
    pysnmpUsmKeyPriv.setDescription("""\
User's non-localized key used for encryption.
""")
_PysnmpUsmMIBConformance_ObjectIdentity = ObjectIdentity
pysnmpUsmMIBConformance = _PysnmpUsmMIBConformance_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 2)
)
_PysnmpUsmMIBCompliances_ObjectIdentity = ObjectIdentity
pysnmpUsmMIBCompliances = _PysnmpUsmMIBCompliances_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 2, 1)
)
_PysnmpUsmMIBGroups_ObjectIdentity = ObjectIdentity
pysnmpUsmMIBGroups = _PysnmpUsmMIBGroups_ObjectIdentity(
    (1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 2, 2)
)

mibBuilder.exportSymbols(
    "PYSNMP-USM-MIB",
    **{"pysnmpUsmMIB": pysnmpUsmMIB,
       "pysnmpUsmMIBObjects": pysnmpUsmMIBObjects,
       "pysnmpUsmCfg": pysnmpUsmCfg,
       "pysnmpUsmDiscoverable": pysnmpUsmDiscoverable,
       "pysnmpUsmDiscovery": pysnmpUsmDiscovery,
       "pysnmpUsmSecretTable": pysnmpUsmSecretTable,
       "pysnmpUsmSecretEntry": pysnmpUsmSecretEntry,
       "pysnmpUsmSecretUserName": pysnmpUsmSecretUserName,
       "pysnmpUsmSecretAuthKey": pysnmpUsmSecretAuthKey,
       "pysnmpUsmSecretPrivKey": pysnmpUsmSecretPrivKey,
       "pysnmpUsmSecretStatus": pysnmpUsmSecretStatus,
       "pysnmpUsmUser": pysnmpUsmUser,
       "pysnmpUsmKeyTable": pysnmpUsmKeyTable,
       "pysnmpUsmKeyEntry": pysnmpUsmKeyEntry,
       "pysnmpUsmKeyAuthLocalized": pysnmpUsmKeyAuthLocalized,
       "pysnmpUsmKeyPrivLocalized": pysnmpUsmKeyPrivLocalized,
       "pysnmpUsmKeyAuth": pysnmpUsmKeyAuth,
       "pysnmpUsmKeyPriv": pysnmpUsmKeyPriv,
       "pysnmpUsmMIBConformance": pysnmpUsmMIBConformance,
       "pysnmpUsmMIBCompliances": pysnmpUsmMIBCompliances,
       "pysnmpUsmMIBGroups": pysnmpUsmMIBGroups}
)
