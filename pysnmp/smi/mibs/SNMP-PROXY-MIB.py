#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# ASN.1 source http://mibs.snmplabs.com:80/asn1/SNMP-PROXY-MIB
# Produced by pysmi-0.4.0 at Sat Feb 16 12:22:13 2019
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

(SnmpAdminString,
 SnmpEngineID) = mibBuilder.importSymbols(
    "SNMP-FRAMEWORK-MIB",
    "SnmpAdminString",
    "SnmpEngineID")

(SnmpTagValue,) = mibBuilder.importSymbols(
    "SNMP-TARGET-MIB",
    "SnmpTagValue")

(ObjectGroup,
 NotificationGroup,
 ModuleCompliance) = mibBuilder.importSymbols(
    "SNMPv2-CONF",
    "ObjectGroup",
    "NotificationGroup",
    "ModuleCompliance")

(MibIdentifier,
 MibScalar,
 MibTable,
 MibTableRow,
 MibTableColumn,
 ModuleIdentity,
 snmpModules,
 Counter64,
 NotificationType,
 Bits,
 IpAddress,
 Gauge32,
 ObjectIdentity,
 Integer32,
 Counter32,
 TimeTicks,
 Unsigned32,
 iso) = mibBuilder.importSymbols(
    "SNMPv2-SMI",
    "MibIdentifier",
    "MibScalar",
    "MibTable",
    "MibTableRow",
    "MibTableColumn",
    "ModuleIdentity",
    "snmpModules",
    "Counter64",
    "NotificationType",
    "Bits",
    "IpAddress",
    "Gauge32",
    "ObjectIdentity",
    "Integer32",
    "Counter32",
    "TimeTicks",
    "Unsigned32",
    "iso")

(TextualConvention,
 DisplayString,
 StorageType,
 RowStatus) = mibBuilder.importSymbols(
    "SNMPv2-TC",
    "TextualConvention",
    "DisplayString",
    "StorageType",
    "RowStatus")

snmpProxyMIB = ModuleIdentity(
    (1, 3, 6, 1, 6, 3, 14)
)
snmpProxyMIB.setRevisions(
        ("2002-10-14 00:00",
         "1998-08-04 00:00",
         "1997-07-14 00:00")
)
snmpProxyMIB.setLastUpdated("200210140000Z")
if mibBuilder.loadTexts:
    snmpProxyMIB.setOrganization("""\
IETF SNMPv3 Working Group
""")
snmpProxyMIB.setContactInfo("""\
WG-email: snmpv3@lists.tislabs.com Subscribe: majordomo@lists.tislabs.com In
message body: subscribe snmpv3 Co-Chair: Russ Mundy Network Associates
Laboratories Postal: 15204 Omega Drive, Suite 300 Rockville, MD 20850-4601 USA
EMail: mundy@tislabs.com Phone: +1 301-947-7107 Co-Chair: David Harrington
Enterasys Networks Postal: 35 Industrial Way P. O. Box 5004 Rochester, New
Hampshire 03866-5005 USA EMail: dbh@enterasys.com Phone: +1 603-337-2614 Co-
editor: David B. Levi Nortel Networks Postal: 3505 Kesterwood Drive Knoxville,
Tennessee 37918 EMail: dlevi@nortelnetworks.com Phone: +1 865 686 0432 Co-
editor: Paul Meyer Secure Computing Corporation Postal: 2675 Long Lake Road
Roseville, Minnesota 55113 EMail: paul_meyer@securecomputing.com Phone: +1 651
628 1592 Co-editor: Bob Stewart Retired
""")
if mibBuilder.loadTexts:
    snmpProxyMIB.setDescription("""\
This MIB module defines MIB objects which provide mechanisms to remotely
configure the parameters used by a proxy forwarding application. Copyright (C)
The Internet Society (2002). This version of this MIB module is part of RFC
3413; see the RFC itself for full legal notices.
""")

_SnmpProxyObjects_ObjectIdentity = ObjectIdentity
snmpProxyObjects = _SnmpProxyObjects_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 14, 1)
)
_SnmpProxyTable_Object = MibTable
snmpProxyTable = _SnmpProxyTable_Object(
    (1, 3, 6, 1, 6, 3, 14, 1, 2)
)
if mibBuilder.loadTexts:
    snmpProxyTable.setStatus("current")
if mibBuilder.loadTexts:
    snmpProxyTable.setDescription("""\
The table of translation parameters used by proxy forwarder applications for
forwarding SNMP messages.
""")
_SnmpProxyEntry_Object = MibTableRow
snmpProxyEntry = _SnmpProxyEntry_Object(
    (1, 3, 6, 1, 6, 3, 14, 1, 2, 1)
)
snmpProxyEntry.setIndexNames(
    (1, "SNMP-PROXY-MIB", "snmpProxyName"),
)
if mibBuilder.loadTexts:
    snmpProxyEntry.setStatus("current")
if mibBuilder.loadTexts:
    snmpProxyEntry.setDescription("""\
A set of translation parameters used by a proxy forwarder application for
forwarding SNMP messages. Entries in the snmpProxyTable are created and deleted
using the snmpProxyRowStatus object.
""")


class _SnmpProxyName_Type(SnmpAdminString):
    """Custom type snmpProxyName based on SnmpAdminString"""
    subtypeSpec = SnmpAdminString.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        ValueSizeConstraint(1, 32),
    )


_SnmpProxyName_Type.__name__ = "SnmpAdminString"
_SnmpProxyName_Object = MibTableColumn
snmpProxyName = _SnmpProxyName_Object(
    (1, 3, 6, 1, 6, 3, 14, 1, 2, 1, 1),
    _SnmpProxyName_Type()
)
snmpProxyName.setMaxAccess("not-accessible")
if mibBuilder.loadTexts:
    snmpProxyName.setStatus("current")
if mibBuilder.loadTexts:
    snmpProxyName.setDescription("""\
The locally arbitrary, but unique identifier associated with this
snmpProxyEntry.
""")


class _SnmpProxyType_Type(Integer32):
    """Custom type snmpProxyType based on Integer32"""
    subtypeSpec = Integer32.subtypeSpec
    subtypeSpec += ConstraintsUnion(
        SingleValueConstraint(
            *(1,
              2,
              3,
              4)
        )
    )
    namedValues = NamedValues(
        *(("inform", 4),
          ("read", 1),
          ("trap", 3),
          ("write", 2))
    )


_SnmpProxyType_Type.__name__ = "Integer32"
_SnmpProxyType_Object = MibTableColumn
snmpProxyType = _SnmpProxyType_Object(
    (1, 3, 6, 1, 6, 3, 14, 1, 2, 1, 2),
    _SnmpProxyType_Type()
)
snmpProxyType.setMaxAccess("read-create")
if mibBuilder.loadTexts:
    snmpProxyType.setStatus("current")
if mibBuilder.loadTexts:
    snmpProxyType.setDescription("""\
The type of message that may be forwarded using the translation parameters
defined by this entry.
""")
_SnmpProxyContextEngineID_Type = SnmpEngineID
_SnmpProxyContextEngineID_Object = MibTableColumn
snmpProxyContextEngineID = _SnmpProxyContextEngineID_Object(
    (1, 3, 6, 1, 6, 3, 14, 1, 2, 1, 3),
    _SnmpProxyContextEngineID_Type()
)
snmpProxyContextEngineID.setMaxAccess("read-create")
if mibBuilder.loadTexts:
    snmpProxyContextEngineID.setStatus("current")
if mibBuilder.loadTexts:
    snmpProxyContextEngineID.setDescription("""\
The contextEngineID contained in messages that may be forwarded using the
translation parameters defined by this entry.
""")
_SnmpProxyContextName_Type = SnmpAdminString
_SnmpProxyContextName_Object = MibTableColumn
snmpProxyContextName = _SnmpProxyContextName_Object(
    (1, 3, 6, 1, 6, 3, 14, 1, 2, 1, 4),
    _SnmpProxyContextName_Type()
)
snmpProxyContextName.setMaxAccess("read-create")
if mibBuilder.loadTexts:
    snmpProxyContextName.setStatus("current")
if mibBuilder.loadTexts:
    snmpProxyContextName.setDescription("""\
The contextName contained in messages that may be forwarded using the
translation parameters defined by this entry. This object is optional, and if
not supported, the contextName contained in a message is ignored when selecting
an entry in the snmpProxyTable.
""")
_SnmpProxyTargetParamsIn_Type = SnmpAdminString
_SnmpProxyTargetParamsIn_Object = MibTableColumn
snmpProxyTargetParamsIn = _SnmpProxyTargetParamsIn_Object(
    (1, 3, 6, 1, 6, 3, 14, 1, 2, 1, 5),
    _SnmpProxyTargetParamsIn_Type()
)
snmpProxyTargetParamsIn.setMaxAccess("read-create")
if mibBuilder.loadTexts:
    snmpProxyTargetParamsIn.setStatus("current")
if mibBuilder.loadTexts:
    snmpProxyTargetParamsIn.setDescription("""\
This object selects an entry in the snmpTargetParamsTable. The selected entry
is used to determine which row of the snmpProxyTable to use for forwarding
received messages.
""")
_SnmpProxySingleTargetOut_Type = SnmpAdminString
_SnmpProxySingleTargetOut_Object = MibTableColumn
snmpProxySingleTargetOut = _SnmpProxySingleTargetOut_Object(
    (1, 3, 6, 1, 6, 3, 14, 1, 2, 1, 6),
    _SnmpProxySingleTargetOut_Type()
)
snmpProxySingleTargetOut.setMaxAccess("read-create")
if mibBuilder.loadTexts:
    snmpProxySingleTargetOut.setStatus("current")
if mibBuilder.loadTexts:
    snmpProxySingleTargetOut.setDescription("""\
This object selects a management target defined in the snmpTargetAddrTable (in
the SNMP-TARGET-MIB). The selected target is defined by an entry in the
snmpTargetAddrTable whose index value (snmpTargetAddrName) is equal to this
object. This object is only used when selection of a single target is required
(i.e. when forwarding an incoming read or write request).
""")
_SnmpProxyMultipleTargetOut_Type = SnmpTagValue
_SnmpProxyMultipleTargetOut_Object = MibTableColumn
snmpProxyMultipleTargetOut = _SnmpProxyMultipleTargetOut_Object(
    (1, 3, 6, 1, 6, 3, 14, 1, 2, 1, 7),
    _SnmpProxyMultipleTargetOut_Type()
)
snmpProxyMultipleTargetOut.setMaxAccess("read-create")
if mibBuilder.loadTexts:
    snmpProxyMultipleTargetOut.setStatus("current")
if mibBuilder.loadTexts:
    snmpProxyMultipleTargetOut.setDescription("""\
This object selects a set of management targets defined in the
snmpTargetAddrTable (in the SNMP-TARGET-MIB). This object is only used when
selection of multiple targets is required (i.e. when forwarding an incoming
notification).
""")


class _SnmpProxyStorageType_Type(StorageType):
    """Custom type snmpProxyStorageType based on StorageType"""


_SnmpProxyStorageType_Object = MibTableColumn
snmpProxyStorageType = _SnmpProxyStorageType_Object(
    (1, 3, 6, 1, 6, 3, 14, 1, 2, 1, 8),
    _SnmpProxyStorageType_Type()
)
snmpProxyStorageType.setMaxAccess("read-create")
if mibBuilder.loadTexts:
    snmpProxyStorageType.setStatus("current")
if mibBuilder.loadTexts:
    snmpProxyStorageType.setDescription("""\
The storage type of this conceptual row. Conceptual rows having the value
'permanent' need not allow write-access to any columnar objects in the row.
""")
_SnmpProxyRowStatus_Type = RowStatus
_SnmpProxyRowStatus_Object = MibTableColumn
snmpProxyRowStatus = _SnmpProxyRowStatus_Object(
    (1, 3, 6, 1, 6, 3, 14, 1, 2, 1, 9),
    _SnmpProxyRowStatus_Type()
)
snmpProxyRowStatus.setMaxAccess("read-create")
if mibBuilder.loadTexts:
    snmpProxyRowStatus.setStatus("current")
if mibBuilder.loadTexts:
    snmpProxyRowStatus.setDescription("""\
The status of this conceptual row. To create a row in this table, a manager
must set this object to either createAndGo(4) or createAndWait(5). The
following objects may not be modified while the value of this object is
active(1): - snmpProxyType - snmpProxyContextEngineID - snmpProxyContextName -
snmpProxyTargetParamsIn - snmpProxySingleTargetOut - snmpProxyMultipleTargetOut
""")
_SnmpProxyConformance_ObjectIdentity = ObjectIdentity
snmpProxyConformance = _SnmpProxyConformance_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 14, 3)
)
_SnmpProxyCompliances_ObjectIdentity = ObjectIdentity
snmpProxyCompliances = _SnmpProxyCompliances_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 14, 3, 1)
)
_SnmpProxyGroups_ObjectIdentity = ObjectIdentity
snmpProxyGroups = _SnmpProxyGroups_ObjectIdentity(
    (1, 3, 6, 1, 6, 3, 14, 3, 2)
)

snmpProxyGroup = ObjectGroup(
    (1, 3, 6, 1, 6, 3, 14, 3, 2, 3)
)
snmpProxyGroup.setObjects(
      *(("SNMP-PROXY-MIB", "snmpProxyType"),
        ("SNMP-PROXY-MIB", "snmpProxyContextEngineID"),
        ("SNMP-PROXY-MIB", "snmpProxyContextName"),
        ("SNMP-PROXY-MIB", "snmpProxyTargetParamsIn"),
        ("SNMP-PROXY-MIB", "snmpProxySingleTargetOut"),
        ("SNMP-PROXY-MIB", "snmpProxyMultipleTargetOut"),
        ("SNMP-PROXY-MIB", "snmpProxyStorageType"),
        ("SNMP-PROXY-MIB", "snmpProxyRowStatus"))
)
if mibBuilder.loadTexts:
    snmpProxyGroup.setStatus("current")
if mibBuilder.loadTexts:
    snmpProxyGroup.setDescription("""\
A collection of objects providing remote configuration of management target
translation parameters for use by proxy forwarder applications.
""")

snmpProxyCompliance = ModuleCompliance(
    (1, 3, 6, 1, 6, 3, 14, 3, 1, 1)
)
if mibBuilder.loadTexts:
    snmpProxyCompliance.setStatus(
        "current"
    )
if mibBuilder.loadTexts:
    snmpProxyCompliance.setDescription("""\
The compliance statement for SNMP entities which include a proxy forwarding
application.
""")

mibBuilder.exportSymbols(
    "SNMP-PROXY-MIB",
    **{"snmpProxyMIB": snmpProxyMIB,
       "snmpProxyObjects": snmpProxyObjects,
       "snmpProxyTable": snmpProxyTable,
       "snmpProxyEntry": snmpProxyEntry,
       "snmpProxyName": snmpProxyName,
       "snmpProxyType": snmpProxyType,
       "snmpProxyContextEngineID": snmpProxyContextEngineID,
       "snmpProxyContextName": snmpProxyContextName,
       "snmpProxyTargetParamsIn": snmpProxyTargetParamsIn,
       "snmpProxySingleTargetOut": snmpProxySingleTargetOut,
       "snmpProxyMultipleTargetOut": snmpProxyMultipleTargetOut,
       "snmpProxyStorageType": snmpProxyStorageType,
       "snmpProxyRowStatus": snmpProxyRowStatus,
       "snmpProxyConformance": snmpProxyConformance,
       "snmpProxyCompliances": snmpProxyCompliances,
       "snmpProxyCompliance": snmpProxyCompliance,
       "snmpProxyGroups": snmpProxyGroups,
       "snmpProxyGroup": snmpProxyGroup}
)
