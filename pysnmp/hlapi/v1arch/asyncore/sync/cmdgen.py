#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pyasn1.type.univ import Null

from pysnmp.hlapi.v1arch.asyncore import cmdgen
from pysnmp.hlapi.varbinds import *
from pysnmp.proto.rfc1905 import endOfMibView

__all__ = ['getCmd', 'nextCmd', 'setCmd', 'bulkCmd']

VB_PROCESSOR = CommandGeneratorVarBinds()


def getCmd(snmpDispatcher, authData, transportTarget,
           *varBinds, **options):
    """Creates a generator to perform one or more SNMP GET queries.

    On each iteration, new SNMP GET request is send (:RFC:`1905#section-4.2.1`).
    The iterator blocks waiting for response to arrive or error to occur.

    Parameters
    ----------
    snmpDispatcher: :py:class:`~pysnmp.hlapi.v1arch.asyncore.SnmpDispatcher`
        Class instance representing asyncore-based asynchronous event loop and
        associated state information.

    authData: :py:class:`~pysnmp.hlapi.CommunityData` or :py:class:`~pysnmp.hlapi.UsmUserData`
        Class instance representing SNMP credentials.

    transportTarget: :py:class:`~pysnmp.hlapi.asyncore.UdpTransportTarget` or :py:class:`~pysnmp.hlapi.asyncore.Udp6TransportTarget`
        Class instance representing transport type along with SNMP peer address.

    \*varBinds: :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        One or more class instances representing MIB variables to place
        into SNMP request.

    Other Parameters
    ----------------
    \*\*options:
        Request options:

            * `lookupMib` - load MIB and resolve response MIB variables at
              the cost of slightly reduced performance. Default is `False`.

    Yields
    ------
    errorIndication: str
        True value indicates local SNMP error.
    errorStatus: str
        True value indicates SNMP PDU error reported by remote.
    errorIndex: int
        Non-zero value refers to `varBinds[errorIndex-1]`
    varBinds: tuple
        A sequence of :py:class:`~pysnmp.smi.rfc1902.ObjectType` class
        instances representing MIB variables returned in SNMP response.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Notes
    -----
    The `getCmd` generator will be exhausted immediately unless
    a new sequence of `varBinds` are send back into running generator
    (supported since Python 2.6).

    Examples
    --------
    >>> from pysnmp.hlapi.v1arch import *
    >>>
    >>> g = getCmd(snmpDispatcher(),
    >>>            CommunityData('public'),
    >>>            UdpTransportTarget(('demo.snmplabs.com', 161)),
    >>>            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
    >>>
    >>> next(g)
    (None, 0, 0, [ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.1.0')),
                  DisplayString('SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m'))])
    """

    def cbFun(*args, **kwargs):
        response[:] = args

    options['cbFun'] = cbFun

    errorIndication, errorStatus, errorIndex = None, 0, 0
    response = []

    while True:
        if varBinds:
            cmdgen.getCmd(snmpDispatcher, authData, transportTarget,
                          *varBinds, **options)

            snmpDispatcher.transportDispatcher.runDispatcher()

            errorIndication, errorStatus, errorIndex, varBinds = response

        varBinds = (yield errorIndication, errorStatus, errorIndex, varBinds)

        if not varBinds:
            break


def setCmd(snmpDispatcher, authData, transportTarget,
           *varBinds, **options):
    """Creates a generator to perform one or more SNMP SET queries.

    On each iteration, new SNMP SET request is send (:RFC:`1905#section-4.2.5`).
    The iterator blocks waiting for response to arrive or error to occur.

    Parameters
    ----------
    snmpDispatcher : :py:class:`~pysnmp.hlapi.snmpDispatcher`
        Class instance representing SNMP engine.

    authData : :py:class:`~pysnmp.hlapi.CommunityData` or :py:class:`~pysnmp.hlapi.UsmUserData`
        Class instance representing SNMP credentials.

    transportTarget : :py:class:`~pysnmp.hlapi.asyncore.UdpTransportTarget` or :py:class:`~pysnmp.hlapi.asyncore.Udp6TransportTarget`
        Class instance representing transport type along with SNMP peer address.

    \*varBinds : :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        One or more class instances representing MIB variables to place
        into SNMP request.

    Other Parameters
    ----------------
    \*\*options :
        Request options:

            * `lookupMib` - load MIB and resolve response MIB variables at
              the cost of slightly reduced performance. Default is `True`.
              Default is `True`.

    Yields
    ------
    errorIndication : str
        True value indicates SNMP engine error.
    errorStatus : str
        True value indicates SNMP PDU error.
    errorIndex : int
        Non-zero value refers to `varBinds[errorIndex-1]`
    varBinds : tuple
        A sequence of :py:class:`~pysnmp.smi.rfc1902.ObjectType` class
        instances representing MIB variables returned in SNMP response.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Notes
    -----
    The `setCmd` generator will be exhausted immediately unless
    a new sequence of `varBinds` are send back into running generator
    (supported since Python 2.6).

    Examples
    --------
    >>> from pysnmp.hlapi.v1arch import *
    >>>
    >>> g = setCmd(snmpDispatcher(),
    >>>            CommunityData('public'),
    >>>            UdpTransportTarget(('demo.snmplabs.com', 161)),
    >>>            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0), 'Linux i386'))
    >>>
    >>> next(g)
    (None, 0, 0, [ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.1.0')),
                  DisplayString('Linux i386'))])
    """

    def cbFun(*args, **kwargs):
        response[:] = args

    options['cbFun'] = cbFun

    errorIndication, errorStatus, errorIndex = None, 0, 0
    response = []

    while True:
        if varBinds:
            cmdgen.setCmd(snmpDispatcher, authData, transportTarget,
                          *varBinds, **options)

            snmpDispatcher.transportDispatcher.runDispatcher()

            errorIndication, errorStatus, errorIndex, varBinds = response

        varBinds = (yield errorIndication, errorStatus, errorIndex, varBinds)

        if not varBinds:
            break


def nextCmd(snmpDispatcher, authData, transportTarget,
            *varBinds, **options):
    """Create a generator to perform one or more SNMP GETNEXT queries.

    On each iteration, new SNMP GETNEXT request is send
    (:RFC:`1905#section-4.2.2`). The iterator blocks waiting for response
    to arrive or error to occur.

    Parameters
    ----------
    snmpDispatcher : :py:class:`~pysnmp.hlapi.snmpDispatcher`
        Class instance representing SNMP engine.

    authData : :py:class:`~pysnmp.hlapi.CommunityData` or :py:class:`~pysnmp.hlapi.UsmUserData`
        Class instance representing SNMP credentials.

    transportTarget : :py:class:`~pysnmp.hlapi.asyncore.UdpTransportTarget` or :py:class:`~pysnmp.hlapi.asyncore.Udp6TransportTarget`
        Class instance representing transport type along with SNMP peer address.

    \*varBinds : :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        One or more class instances representing MIB variables to place
        into SNMP request.

    Other Parameters
    ----------------
    \*\*options :
        Request options:

            * `lookupMib` - load MIB and resolve response MIB variables at
              the cost of slightly reduced performance. Default is `True`.
              Default is `True`.
            * `lexicographicMode` - walk SNMP agent's MIB till the end (if `True`),
              otherwise (if `False`) stop iteration when all response MIB
              variables leave the scope of initial MIB variables in
              `varBinds`. Default is `True`.
            * `ignoreNonIncreasingOid` - continue iteration even if response
              MIB variables (OIDs) are not greater then request MIB variables.
              Be aware that setting it to `True` may cause infinite loop between
              SNMP management and agent applications. Default is `False`.
            * `maxRows` - stop iteration once this generator instance processed
              `maxRows` of SNMP conceptual table. Default is `0` (no limit).
            * `maxCalls` - stop iteration once this generator instance processed
              `maxCalls` responses. Default is 0 (no limit).

    Yields
    ------
    errorIndication: str
        True value indicates SNMP engine error.
    errorStatus: str
        True value indicates SNMP PDU error.
    errorIndex: int
        Non-zero value refers to `varBinds[errorIndex-1]`
    varBindTable: tuple
        A 2-dimensional array of :py:class:`~pysnmp.smi.rfc1902.ObjectType` class
        instances representing a table of MIB variables returned in SNMP response.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Notes
    -----
    The `nextCmd` generator will be exhausted on any of the following
    conditions:

    * SNMP engine error occurs thus `errorIndication` is `True`
    * SNMP PDU `errorStatus` is reported as `True`
    * SNMP :py:class:`~pysnmp.proto.rfc1905.EndOfMibView` values
      (also known as *SNMP exception values*) are reported for all
      MIB variables in `varBinds`
    * *lexicographicMode* option is `True` and SNMP agent reports
      end-of-mib or *lexicographicMode* is `False` and all
      response MIB variables leave the scope of `varBinds`

    At any moment a new sequence of `varBinds` could be send back into
    running generator (supported since Python 2.6).

    Examples
    --------
    >>> from pysnmp.hlapi.v1arch import *
    >>>
    >>> g = nextCmd(snmpDispatcher(),
    >>>             CommunityData('public'),
    >>>             UdpTransportTarget(('demo.snmplabs.com', 161)),
    >>>             ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr')))
    >>> next(g)
    (None, 0, 0, [[ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.1.0')), DisplayString('SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m'))]])
    >>> g.send([ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets'))])
    (None, 0, 0, [(ObjectName('1.3.6.1.2.1.2.2.1.10.1'), Counter32(284817787))])
    """

    def cbFun(*args, **kwargs):
        response[:] = args + (kwargs.get('nextVarBinds', ()),)

    options['cbFun'] = cbFun

    lexicographicMode = options.pop('lexicographicMode', True)
    maxRows = options.pop('maxRows', 0)
    maxCalls = options.pop('maxCalls', 0)

    initialVarBinds = VB_PROCESSOR.makeVarBinds(snmpDispatcher.cache, varBinds)

    totalRows = totalCalls = 0

    errorIndication, errorStatus, errorIndex, varBindTable = None, 0, 0, ()
    response = []

    while True:
        if not varBinds:
            yield (errorIndication, errorStatus, errorIndex,
                   varBindTable and varBindTable[0] or [])
            return

        cmdgen.nextCmd(snmpDispatcher, authData, transportTarget,
                       *[(x[0], Null('')) for x in varBinds], **options)

        snmpDispatcher.transportDispatcher.runDispatcher()

        errorIndication, errorStatus, errorIndex, varBindTable, varBinds = response

        if errorIndication:
            yield (errorIndication, errorStatus, errorIndex,
                   varBindTable and varBindTable[0] or [])
            return

        elif errorStatus:
            if errorStatus == 2:
                # Hide SNMPv1 noSuchName error which leaks in here
                # from SNMPv1 Agent through internal pysnmp proxy.
                errorStatus = errorStatus.clone(0)
                errorIndex = errorIndex.clone(0)
            yield (errorIndication, errorStatus, errorIndex,
                   varBindTable and varBindTable[0] or [])
            return

        else:
            varBindRow = varBindTable and varBindTable[-1]

            if not lexicographicMode:
                for idx, varBind in enumerate(varBindRow):
                    name, val = varBind
                    if not isinstance(val, Null):
                        if initialVarBinds[idx][0].isPrefixOf(name):
                            break
                else:
                    return

            for varBindRow in varBindTable:
                nextVarBinds = (yield errorIndication, errorStatus, errorIndex, varBindRow)

                if nextVarBinds:
                    initialVarBinds = varBinds = VB_PROCESSOR.makeVarBinds(snmpDispatcher.cache, nextVarBinds)

                totalRows += 1
                totalCalls += 1

                if maxRows and totalRows >= maxRows:
                    return

                if maxCalls and totalCalls >= maxCalls:
                    return


def bulkCmd(snmpDispatcher, authData, transportTarget,
            nonRepeaters, maxRepetitions, *varBinds, **options):
    """Creates a generator to perform one or more SNMP GETBULK queries.

    On each iteration, new SNMP GETBULK request is send
    (:RFC:`1905#section-4.2.3`). The iterator blocks waiting for response
    to arrive or error to occur.

    Parameters
    ----------
    snmpDispatcher : :py:class:`~pysnmp.hlapi.snmpDispatcher`
        Class instance representing SNMP engine.

    authData : :py:class:`~pysnmp.hlapi.CommunityData` or :py:class:`~pysnmp.hlapi.UsmUserData`
        Class instance representing SNMP credentials.

    transportTarget : :py:class:`~pysnmp.hlapi.asyncore.UdpTransportTarget` or :py:class:`~pysnmp.hlapi.asyncore.Udp6TransportTarget`
        Class instance representing transport type along with SNMP peer address.

    nonRepeaters : int
        One MIB variable is requested in response for the first
        `nonRepeaters` MIB variables in request.

    maxRepetitions : int
        `maxRepetitions` MIB variables are requested in response for each
        of the remaining MIB variables in the request (e.g. excluding
        `nonRepeaters`). Remote SNMP engine may choose lesser value than
        requested.

    \*varBinds : :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        One or more class instances representing MIB variables to place
        into SNMP request.

    Other Parameters
    ----------------
    \*\*options :
        Request options:

            * `lookupMib` - load MIB and resolve response MIB variables at
              the cost of slightly reduced performance. Default is `True`.
              Default is `True`.
            * `lexicographicMode` - walk SNMP agent's MIB till the end (if `True`),
              otherwise (if `False`) stop iteration when all response MIB
              variables leave the scope of initial MIB variables in
              `varBinds`. Default is `True`.
            * `ignoreNonIncreasingOid` - continue iteration even if response
              MIB variables (OIDs) are not greater then request MIB variables.
              Be aware that setting it to `True` may cause infinite loop between
              SNMP management and agent applications. Default is `False`.
            * `maxRows` - stop iteration once this generator instance processed
              `maxRows` of SNMP conceptual table. Default is `0` (no limit).
            * `maxCalls` - stop iteration once this generator instance processed
              `maxCalls` responses. Default is 0 (no limit).

    Yields
    ------
    errorIndication : str
        True value indicates SNMP engine error.
    errorStatus : str
        True value indicates SNMP PDU error.
    errorIndex : int
        Non-zero value refers to \*varBinds[errorIndex-1]
    varBinds: tuple
        A sequence of :py:class:`~pysnmp.smi.rfc1902.ObjectType` class
        instances representing MIB variables returned in SNMP response.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Notes
    -----
    The `bulkCmd` generator will be exhausted on any of the following
    conditions:

    * SNMP engine error occurs thus `errorIndication` is `True`
    * SNMP PDU `errorStatus` is reported as `True`
    * SNMP :py:class:`~pysnmp.proto.rfc1905.EndOfMibView` values
      (also known as *SNMP exception values*) are reported for all
      MIB variables in `varBinds`
    * *lexicographicMode* option is `True` and SNMP agent reports
      end-of-mib or *lexicographicMode* is `False` and all
      response MIB variables leave the scope of `varBinds`

    At any moment a new sequence of `varBinds` could be send back into
    running generator (supported since Python 2.6).

    Setting `maxRepetitions` value to 15..50 might significantly improve
    system performance, as many MIB variables get packed into a single
    response message at once.

    Examples
    --------
    >>> from pysnmp.hlapi.v1arch import *
    >>>
    >>> g = bulkCmd(snmpDispatcher(),
    >>>             CommunityData('public'),
    >>>             UdpTransportTarget(('demo.snmplabs.com', 161)),
    >>>             0, 25,
    >>>             ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr')))
    >>> next(g)
    (None, 0, 0, [[ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.1.0')), DisplayString('SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m'))]])
    >>> g.send([ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets'))])
    (None, 0, 0, [[(ObjectName('1.3.6.1.2.1.2.2.1.10.1'), Counter32(284817787))]])
    """

    def cbFun(*args, **kwargs):
        response[:] = args + (kwargs.get('nextVarBinds', ()),)

    options['cbFun'] = cbFun

    lexicographicMode = options.pop('lexicographicMode', True)
    maxRows = options.pop('maxRows', 0)
    maxCalls = options.pop('maxCalls', 0)

    initialVarBinds = VB_PROCESSOR.makeVarBinds(snmpDispatcher.cache, varBinds)

    nullVarBinds = [False] * len(initialVarBinds)

    totalRows = totalCalls = 0

    errorIndication, errorStatus, errorIndex, varBindTable = None, 0, 0, ()
    response = []

    stopFlag = False

    while not stopFlag:
        if not varBinds:
            yield (errorIndication, errorStatus, errorIndex, varBinds)
            return

        if maxRows and totalRows < maxRows:
            maxRepetitions = min(maxRepetitions, maxRows - totalRows)

        cmdgen.bulkCmd(snmpDispatcher, authData, transportTarget,
                       nonRepeaters, maxRepetitions,
                       *[(x[0], Null('')) for x in varBinds], **options)

        snmpDispatcher.transportDispatcher.runDispatcher()

        errorIndication, errorStatus, errorIndex, varBindTable, varBinds = response

        if errorIndication:
            yield (errorIndication, errorStatus, errorIndex, ())
            return

        elif errorStatus:
            if errorStatus == 2:
                # Hide SNMPv1 noSuchName error which leaks in here
                # from SNMPv1 Agent through internal pysnmp proxy.
                errorStatus = errorStatus.clone(0)
                errorIndex = errorIndex.clone(0)
            yield (errorIndication, errorStatus, errorIndex, varBindTable and varBindTable[0] or [])
            return

        else:
            for rowIdx, varBindRow in enumerate(varBindTable):
                stopFlag = True
                if len(varBindRow) != len(initialVarBinds):
                    varBindTable = rowIdx and varBindTable[:rowIdx - 1] or []
                    break

                for colIdx, varBind in enumerate(varBindRow):
                    name, val = varBind
                    if nullVarBinds[colIdx]:
                        varBindRow[colIdx] = name, endOfMibView
                        continue

                    stopFlag = False

                    if isinstance(val, Null):
                        nullVarBinds[colIdx] = True

                    elif not lexicographicMode and not initialVarBinds[colIdx][0].isPrefixOf(name):
                        varBindRow[colIdx] = name, endOfMibView
                        nullVarBinds[colIdx] = True

                if stopFlag:
                    varBindTable = rowIdx and varBindTable[:rowIdx - 1] or []
                    break

            totalRows += len(varBindTable)
            totalCalls += 1

            if maxRows and totalRows >= maxRows:
                if totalRows > maxRows:
                    varBindTable = varBindTable[:-(totalRows - maxRows)]
                stopFlag = True

            if maxCalls and totalCalls >= maxCalls:
                stopFlag = True

            for varBindRow in varBindTable:
                nextVarBinds = (yield errorIndication, errorStatus, errorIndex, varBindRow)

                if nextVarBinds:
                    initialVarBinds = varBinds = VB_PROCESSOR.makeVarBinds(snmpDispatcher.cache, nextVarBinds)
