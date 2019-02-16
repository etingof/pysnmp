#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# This file instantiates some of the MIB managed objects for SNMP engine use
#

if 'mibBuilder' not in globals():
    import sys

    sys.stderr.write(__doc__)
    sys.exit(1)

MibScalarInstance, = mibBuilder.importSymbols('SNMPv2-SMI', 'MibScalarInstance')

(usmStatsUnsupportedSecLevels,
 usmStatsNotInTimeWindows,
 usmStatsUnknownUserNames,
 usmStatsUnknownEngineIDs,
 usmStatsWrongDigests,
 usmStatsDecryptionErrors,
 usmUserSpinLock) = mibBuilder.importSymbols(
    'SNMP-USER-BASED-SM-MIB',
    'usmStatsUnsupportedSecLevels',
    'usmStatsNotInTimeWindows',
    'usmStatsUnknownUserNames',
    'usmStatsUnknownEngineIDs',
    'usmStatsWrongDigests',
    'usmStatsDecryptionErrors',
    'usmUserSpinLock'
)

_usmStatsUnsupportedSecLevels = MibScalarInstance(
    usmStatsUnsupportedSecLevels.name, (0,),
    usmStatsUnsupportedSecLevels.syntax.clone(0)
)
_usmStatsNotInTimeWindows = MibScalarInstance(
    usmStatsNotInTimeWindows.name, (0,),
    usmStatsNotInTimeWindows.syntax.clone(0)
)
_usmStatsUnknownUserNames = MibScalarInstance(
    usmStatsUnknownUserNames.name, (0,),
    usmStatsUnknownUserNames.syntax.clone(0)
)
_usmStatsUnknownEngineIDs = MibScalarInstance(
    usmStatsUnknownEngineIDs.name, (0,),
    usmStatsUnknownEngineIDs.syntax.clone(0)
)
_usmStatsWrongDigests = MibScalarInstance(
    usmStatsWrongDigests.name, (0,),
    usmStatsWrongDigests.syntax.clone(0)
)
_usmStatsDecryptionErrors = MibScalarInstance(
    usmStatsDecryptionErrors.name, (0,),
    usmStatsDecryptionErrors.syntax.clone(0)
)
_usmUserSpinLock = MibScalarInstance(
    usmUserSpinLock.name, (0,),
    usmUserSpinLock.syntax.clone(0)
)

mibBuilder.exportSymbols(
    '__SNMP-USER-BASED-SM-MIB',
    usmStatsUnsupportedSecLevels=_usmStatsUnsupportedSecLevels,
    usmStatsNotInTimeWindows=_usmStatsNotInTimeWindows,
    usmStatsUnknownUserNames=_usmStatsUnknownUserNames,
    usmStatsUnknownEngineIDs=_usmStatsUnknownEngineIDs,
    usmStatsWrongDigests=_usmStatsWrongDigests,
    usmStatsDecryptionErrors=_usmStatsDecryptionErrors,
    usmUserSpinLock=_usmUserSpinLock
)
