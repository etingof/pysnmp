#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# This file instantiates some of the MIB managed objects for SNMP engine use
#

from sys import version
from time import time
from pysnmp import __version__

if 'mibBuilder' not in globals():
    import sys

    sys.stderr.write(__doc__)
    sys.exit(1)

(MibScalarInstance,
 TimeTicks) = mibBuilder.importSymbols(
    'SNMPv2-SMI',
    'MibScalarInstance',
    'TimeTicks'
)

(sysDescr,
 sysObjectID,
 sysUpTime,
 sysContact,
 sysName,
 sysLocation,
 sysServices,
 sysORLastChange,
 snmpInPkts,
 snmpOutPkts,
 snmpInBadVersions,
 snmpInBadCommunityNames,
 snmpInBadCommunityUses,
 snmpInASNParseErrs,
 snmpInTooBigs,
 snmpInNoSuchNames,
 snmpInBadValues,
 snmpInReadOnlys,
 snmpInGenErrs,
 snmpInTotalReqVars,
 snmpInTotalSetVars,
 snmpInGetRequests,
 snmpInGetNexts,
 snmpInSetRequests,
 snmpInGetResponses,
 snmpInTraps,
 snmpOutTooBigs,
 snmpOutNoSuchNames,
 snmpOutBadValues,
 snmpOutGenErrs,
 snmpOutSetRequests,
 snmpOutGetResponses,
 snmpOutTraps,
 snmpEnableAuthenTraps,
 snmpSilentDrops,
 snmpProxyDrops,
 snmpTrapOID,
 coldStart,
 snmpSetSerialNo) = mibBuilder.importSymbols(
    'SNMPv2-MIB',
    'sysDescr',
    'sysObjectID',
    'sysUpTime',
    'sysContact',
    'sysName',
    'sysLocation',
    'sysServices',
    'sysORLastChange',
    'snmpInPkts',
    'snmpOutPkts',
    'snmpInBadVersions',
    'snmpInBadCommunityNames',
    'snmpInBadCommunityUses',
    'snmpInASNParseErrs',
    'snmpInTooBigs',
    'snmpInNoSuchNames',
    'snmpInBadValues',
    'snmpInReadOnlys',
    'snmpInGenErrs',
    'snmpInTotalReqVars',
    'snmpInTotalSetVars',
    'snmpInGetRequests',
    'snmpInGetNexts',
    'snmpInSetRequests',
    'snmpInGetResponses',
    'snmpInTraps',
    'snmpOutTooBigs',
    'snmpOutNoSuchNames',
    'snmpOutBadValues',
    'snmpOutGenErrs',
    'snmpOutSetRequests',
    'snmpOutGetResponses',
    'snmpOutTraps',
    'snmpEnableAuthenTraps',
    'snmpSilentDrops',
    'snmpProxyDrops',
    'snmpTrapOID',
    'coldStart',
    'snmpSetSerialNo'
)

_sysDescr = MibScalarInstance(
    sysDescr.name, (0,),
    sysDescr.syntax.clone("PySNMP engine version %s, Python %s" % (
        __version__, version.replace('\n', ' ').replace('\r', ' ')))
)
_sysObjectID = MibScalarInstance(
    sysObjectID.name, (0,),
    sysObjectID.syntax.clone((1, 3, 6, 1, 4, 1, 20408))
)


class SysUpTime(TimeTicks):
    createdAt = time()

    def clone(self, **kwargs):
        if 'value' not in kwargs:
            kwargs['value'] = int((time() - self.createdAt) * 100)

        return TimeTicks.clone(self, **kwargs)


_sysUpTime = MibScalarInstance(
    sysUpTime.name, (0,),
    SysUpTime(0)
)
_sysContact = MibScalarInstance(
    sysContact.name, (0,),
    sysContact.syntax.clone('')
)
_sysName = MibScalarInstance(
    sysName.name, (0,),
    sysName.syntax.clone('')
)
_sysLocation = MibScalarInstance(
    sysLocation.name, (0,),
    sysLocation.syntax.clone('')
)
_sysServices = MibScalarInstance(
    sysServices.name, (0,),
    sysServices.syntax.clone(0)
)
_sysORLastChange = MibScalarInstance(
    sysORLastChange.name, (0,),
    sysORLastChange.syntax.clone(0)
)
_snmpInPkts = MibScalarInstance(
    snmpInPkts.name, (0,),
    snmpInPkts.syntax.clone(0)
)
_snmpOutPkts = MibScalarInstance(
    snmpOutPkts.name, (0,),
    snmpOutPkts.syntax.clone(0)
)
_snmpInBadVersions = MibScalarInstance(
    snmpInBadVersions.name, (0,),
    snmpInBadVersions.syntax.clone(0)
)
_snmpInBadCommunityNames = MibScalarInstance(
    snmpInBadCommunityNames.name, (0,),
    snmpInBadCommunityNames.syntax.clone(0)
)
_snmpInBadCommunityUses = MibScalarInstance(
    snmpInBadCommunityUses.name, (0,),
    snmpInBadCommunityUses.syntax.clone(0)
)
_snmpInASNParseErrs = MibScalarInstance(
    snmpInASNParseErrs.name, (0,),
    snmpInASNParseErrs.syntax.clone(0)
)
_snmpInTooBigs = MibScalarInstance(
    snmpInTooBigs.name, (0,),
    snmpInTooBigs.syntax.clone(0)
)
_snmpInNoSuchNames = MibScalarInstance(
    snmpInNoSuchNames.name, (0,),
    snmpInNoSuchNames.syntax.clone(0)
)
_snmpInBadValues = MibScalarInstance(
    snmpInBadValues.name, (0,),
    snmpInBadValues.syntax.clone(0)
)
_snmpInReadOnlys = MibScalarInstance(
    snmpInReadOnlys.name, (0,),
    snmpInReadOnlys.syntax.clone(0)
)
_snmpInGenErrs = MibScalarInstance(
    snmpInGenErrs.name, (0,),
    snmpInGenErrs.syntax.clone(0)
)
_snmpInTotalReqVars = MibScalarInstance(
    snmpInTotalReqVars.name, (0,),
    snmpInTotalReqVars.syntax.clone(0)
)
_snmpInTotalSetVars = MibScalarInstance(
    snmpInTotalSetVars.name, (0,),
    snmpInTotalSetVars.syntax.clone(0)
)
_snmpInGetRequests = MibScalarInstance(
    snmpInGetRequests.name, (0,),
    snmpInGetRequests.syntax.clone(0)
)
_snmpInGetNexts = MibScalarInstance(
    snmpInGetNexts.name, (0,),
    snmpInGetNexts.syntax.clone(0)
)
_snmpInSetRequests = MibScalarInstance(
    snmpInSetRequests.name, (0,),
    snmpInSetRequests.syntax.clone(0)
)
_snmpInGetResponses = MibScalarInstance(
    snmpInGetResponses.name, (0,),
    snmpInGetResponses.syntax.clone(0)
)
_snmpInTraps = MibScalarInstance(
    snmpInTraps.name, (0,),
    snmpInTraps.syntax.clone(0)
)
_snmpOutTooBigs = MibScalarInstance(
    snmpOutTooBigs.name, (0,),
    snmpOutTooBigs.syntax.clone(0)
)
_snmpOutNoSuchNames = MibScalarInstance(
    snmpOutNoSuchNames.name, (0,),
    snmpOutNoSuchNames.syntax.clone(0)
)
_snmpOutBadValues = MibScalarInstance(
    snmpOutBadValues.name, (0,),
    snmpOutBadValues.syntax.clone(0)
)
_snmpOutGenErrs = MibScalarInstance(
    snmpOutGenErrs.name, (0,),
    snmpOutGenErrs.syntax.clone(0)
)
_snmpOutSetRequests = MibScalarInstance(
    snmpOutSetRequests.name, (0,),
    snmpOutSetRequests.syntax.clone(0)
)
_snmpOutGetResponses = MibScalarInstance(
    snmpOutGetResponses.name, (0,),
    snmpOutGetResponses.syntax.clone(0)
)
_snmpOutTraps = MibScalarInstance(
    snmpOutTraps.name, (0,),
    snmpOutTraps.syntax.clone(0)
)
_snmpEnableAuthenTraps = MibScalarInstance(
    snmpEnableAuthenTraps.name, (0,),
    snmpEnableAuthenTraps.syntax.clone(1)
)
_snmpSilentDrops = MibScalarInstance(
    snmpSilentDrops.name, (0,),
    snmpSilentDrops.syntax.clone(0)
)
_snmpProxyDrops = MibScalarInstance(
    snmpProxyDrops.name, (0,),
    snmpProxyDrops.syntax.clone(0)
)
_snmpTrapOID = MibScalarInstance(
    snmpTrapOID.name, (0,), snmpTrapOID.syntax.clone(coldStart.name)
)
_snmpSetSerialNo = MibScalarInstance(
    snmpSetSerialNo.name, (0,),
    snmpSetSerialNo.syntax.clone(0)
)

mibBuilder.exportSymbols(
    "__SNMPv2-MIB",
    sysDescr=_sysDescr,
    sysObjectID=_sysObjectID,
    sysUpTime=_sysUpTime,
    sysContact=_sysContact,
    sysName=_sysName,
    sysLocation=_sysLocation,
    sysServices=_sysServices,
    sysORLastChange=_sysORLastChange,
    snmpInPkts=_snmpInPkts,
    snmpOutPkts=_snmpOutPkts,
    snmpInBadVersions=_snmpInBadVersions,
    snmpInBadCommunityNames=_snmpInBadCommunityNames,
    snmpInBadCommunityUses=_snmpInBadCommunityUses,
    snmpInASNParseErrs=_snmpInASNParseErrs,
    snmpInTooBigs=_snmpInTooBigs,
    snmpInNoSuchNames=_snmpInNoSuchNames,
    snmpInBadValues=_snmpInBadValues,
    snmpInReadOnlys=_snmpInReadOnlys,
    snmpInGenErrs=_snmpInGenErrs,
    snmpInTotalReqVars=_snmpInTotalReqVars,
    snmpInTotalSetVars=_snmpInTotalSetVars,
    snmpInGetRequests=_snmpInGetRequests,
    snmpInGetNexts=_snmpInGetNexts,
    snmpInSetRequests=_snmpInSetRequests,
    snmpInGetResponses=_snmpInGetResponses,
    snmpInTraps=_snmpInTraps,
    snmpOutTooBigs=_snmpOutTooBigs,
    snmpOutNoSuchNames=_snmpOutNoSuchNames,
    snmpOutBadValues=_snmpOutBadValues,
    snmpOutGenErrs=_snmpOutGenErrs,
    snmpOutSetRequests=_snmpOutSetRequests,
    snmpOutGetResponses=_snmpOutGetResponses,
    snmpOutTraps=_snmpOutTraps,
    snmpEnableAuthenTraps=_snmpEnableAuthenTraps,
    snmpSilentDrops=_snmpSilentDrops,
    snmpProxyDrops=_snmpProxyDrops,
    snmpTrapOID=_snmpTrapOID,
    snmpSetSerialNo=_snmpSetSerialNo
)
