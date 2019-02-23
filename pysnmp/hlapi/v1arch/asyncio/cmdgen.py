#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
try:
    import asyncio

except ImportError:
    import trollius as asyncio

from pysnmp.hlapi.v1arch.auth import *
from pysnmp.hlapi.varbinds import *
from pysnmp.hlapi.v1arch.asyncio.transport import *
from pysnmp.smi.rfc1902 import *
from pysnmp.proto import api

__all__ = ['getCmd', 'nextCmd', 'setCmd', 'bulkCmd', 'isEndOfMib']

VB_PROCESSOR = CommandGeneratorVarBinds()

isEndOfMib = lambda varBinds: not api.v2c.apiPDU.getNextVarBinds(varBinds)[1]


@asyncio.coroutine
def getCmd(snmpDispatcher, authData, transportTarget,
           *varBinds, **options):
    """Creates a generator to perform SNMP GET query.

    When iterator gets advanced by :py:mod:`asyncio` main loop,
    SNMP GET request is sent (:RFC:`1905#section-4.2.1`).
    The iterator yields :py:class:`asyncio.Future` which gets done whenever
    response arrives or error occurs.

    Parameters
    ----------
    snmpDispatcher: :py:class:`~pysnmp.hlapi.v1arch.asyncore.SnmpDispatcher`
        Class instance representing asynio-based asynchronous event loop and
        associated state information.

    authData: :py:class:`~pysnmp.hlapi.v1arch.CommunityData`
        Class instance representing SNMPv1/v2c credentials.

    transportTarget: :py:class:`~pysnmp.hlapi.v1arch.asyncio.UdpTransportTarget` or
        :py:class:`~pysnmp.hlapi.v1arch.asyncio.Udp6TransportTarget` Class instance representing
        transport type along with SNMP peer address.

    \*varBinds: :class:`tuple` of OID-value pairs or :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        One or more class instances representing MIB variables to place
        into SNMP request.

    Note
    ----
    The `SnmpDispatcher` object may be expensive to create, therefore it is
    advised to maintain it for the lifecycle of the application/thread for
    as long as possible.

    Other Parameters
    ----------------
    \*\*options :
        Request options:

        * `lookupMib` - load MIB and resolve response MIB variables at
          the cost of slightly reduced performance. Default is `False`,
          unless :py:class:`~pysnmp.smi.rfc1902.ObjectType` is present
          among `varBinds` in which case `lookupMib` gets automatically
          enabled.

    Yields
    ------
    errorIndication: str
        True value indicates SNMP engine error.
    errorStatus: str
        True value indicates SNMP PDU error.
    errorIndex: int
        Non-zero value refers to `varBinds[errorIndex-1]`
    varBinds: tuple
        A sequence of OID-value pairs in form of base SNMP types (if
        `lookupMib` is `False`) or :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        class instances (if `lookupMib` is `True`) representing MIB variables
        returned in SNMP response.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Examples
    --------
    >>> import asyncio
    >>> from pysnmp.hlapi.v1arch.asyncio import *
    >>>
    >>> @asyncio.coroutine
    ... def run():
    ...     errorIndication, errorStatus, errorIndex, varBinds = yield from getCmd(
    ...         SnmpDispatcher(),
    ...         CommunityData('public'),
    ...         UdpTransportTarget(('demo.snmplabs.com', 161)),
    ...         ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
    ...     )
    ...     print(errorIndication, errorStatus, errorIndex, varBinds)
    >>>
    >>> asyncio.get_event_loop().run_until_complete(run())
    (None, 0, 0, [ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.1.0')), DisplayString('SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m'))])
    >>>
    """

    def _cbFun(snmpDispatcher, stateHandle, errorIndication, rspPdu, _cbCtx):
        if future.cancelled():
            return

        errorStatus = pMod.apiPDU.getErrorStatus(rspPdu)
        errorIndex = pMod.apiPDU.getErrorIndex(rspPdu)

        varBinds = pMod.apiPDU.getVarBinds(rspPdu)

        if lookupMib:
            try:
                varBinds = VB_PROCESSOR.unmakeVarBinds(
                    snmpDispatcher.cache, varBinds, lookupMib)

            except Exception as e:
                future.set_exception(e)
                return

        future.set_result(
            (errorIndication, errorStatus, errorIndex, varBinds)
        )

    lookupMib = options.get('lookupMib')

    if not lookupMib and any(isinstance(x, ObjectType) for x in varBinds):
        lookupMib = True

    if lookupMib:
        varBinds = VB_PROCESSOR.makeVarBinds(snmpDispatcher.cache, varBinds)

    pMod = api.PROTOCOL_MODULES[authData.mpModel]

    reqPdu = pMod.GetRequestPDU()
    pMod.apiPDU.setDefaults(reqPdu)
    pMod.apiPDU.setVarBinds(reqPdu, varBinds)

    future = asyncio.Future()

    snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)

    return future


@asyncio.coroutine
def setCmd(snmpDispatcher, authData, transportTarget,
           *varBinds, **options):
    """Creates a generator to perform SNMP SET query.

    When iterator gets advanced by :py:mod:`asyncio` main loop,
    SNMP SET request is sent (:RFC:`1905#section-4.2.5`).
    The iterator yields :py:class:`asyncio.Future` which gets done whenever
    response arrives or error occurs.

    Parameters
    ----------
    snmpDispatcher: :py:class:`~pysnmp.hlapi.v1arch.asyncore.SnmpDispatcher`
        Class instance representing asynio-based asynchronous event loop and
        associated state information.

    authData: :py:class:`~pysnmp.hlapi.v1arch.CommunityData`
        Class instance representing SNMPv1/v2c credentials.

    transportTarget: :py:class:`~pysnmp.hlapi.v1arch.asyncio.UdpTransportTarget` or
        :py:class:`~pysnmp.hlapi.v1arch.asyncio.Udp6TransportTarget` Class instance representing
        transport type along with SNMP peer address.

    \*varBinds: :class:`tuple` of OID-value pairs or :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        One or more class instances representing MIB variables to place
        into SNMP request.

    Note
    ----
    The `SnmpDispatcher` object may be expensive to create, therefore it is
    advised to maintain it for the lifecycle of the application/thread for
    as long as possible.

    Other Parameters
    ----------------
    \*\*options :
        Request options:

        * `lookupMib` - load MIB and resolve response MIB variables at
          the cost of slightly reduced performance. Default is `False`,
          unless :py:class:`~pysnmp.smi.rfc1902.ObjectType` is present
          among `varBinds` in which case `lookupMib` gets automatically
          enabled.

    Yields
    ------
    errorIndication: str
        True value indicates SNMP engine error.
    errorStatus: str
        True value indicates SNMP PDU error.
    errorIndex: int
        Non-zero value refers to `varBinds[errorIndex-1]`
    varBinds: tuple
        A sequence of OID-value pairs in form of base SNMP types (if
        `lookupMib` is `False`) or :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        class instances (if `lookupMib` is `True`) representing MIB variables
        returned in SNMP response.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Examples
    --------
    >>> import asyncio
    >>> from pysnmp.hlapi.v1arch.asyncio import *
    >>>
    >>> @asyncio.coroutine
    ... def run():
    ...     errorIndication, errorStatus, errorIndex, varBinds = yield from setCmd(
    ...         SnmpDispatcher(),
    ...         CommunityData('public'),
    ...         UdpTransportTarget(('demo.snmplabs.com', 161)),
    ...         ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0), 'Linux i386')
    ...     )
    ...     print(errorIndication, errorStatus, errorIndex, varBinds)
    >>>
    >>> asyncio.get_event_loop().run_until_complete(run())
    (None, 0, 0, [ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.1.0')), DisplayString('Linux i386'))])
    >>>
    """

    def _cbFun(snmpDispatcher, stateHandle, errorIndication, rspPdu, _cbCtx):
        if future.cancelled():
            return

        errorStatus = pMod.apiPDU.getErrorStatus(rspPdu)
        errorIndex = pMod.apiPDU.getErrorIndex(rspPdu)

        varBinds = pMod.apiPDU.getVarBinds(rspPdu)

        if lookupMib:
            try:
                varBinds = VB_PROCESSOR.unmakeVarBinds(
                    snmpDispatcher.cache, varBinds, lookupMib)

            except Exception as e:
                future.set_exception(e)
                return

        future.set_result(
            (errorIndication, errorStatus, errorIndex, varBinds)
        )

    lookupMib = options.get('lookupMib')

    if not lookupMib and any(isinstance(x, ObjectType) for x in varBinds):
        lookupMib = True

    if lookupMib:
        varBinds = VB_PROCESSOR.makeVarBinds(snmpDispatcher.cache, varBinds)

    pMod = api.PROTOCOL_MODULES[authData.mpModel]

    reqPdu = pMod.SetRequestPDU()
    pMod.apiPDU.setDefaults(reqPdu)
    pMod.apiPDU.setVarBinds(reqPdu, varBinds)

    future = asyncio.Future()

    snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)

    return future


@asyncio.coroutine
def nextCmd(snmpDispatcher, authData, transportTarget,
            *varBinds, **options):
    """Creates a generator to perform SNMP GETNEXT query.

    When iterator gets advanced by :py:mod:`asyncio` main loop,
    SNMP GETNEXT request is send (:RFC:`1905#section-4.2.2`).
    The iterator yields :py:class:`asyncio.Future` which gets done whenever
    response arrives or error occurs.

    Parameters
    ----------
    snmpDispatcher: :py:class:`~pysnmp.hlapi.v1arch.asyncore.SnmpDispatcher`
        Class instance representing asynio-based asynchronous event loop and
        associated state information.

    authData: :py:class:`~pysnmp.hlapi.v1arch.CommunityData`
        Class instance representing SNMPv1/v2c credentials.

    transportTarget: :py:class:`~pysnmp.hlapi.v1arch.asyncio.UdpTransportTarget` or
        :py:class:`~pysnmp.hlapi.v1arch.asyncio.Udp6TransportTarget` Class instance representing
        transport type along with SNMP peer address.

    \*varBinds: :class:`tuple` of OID-value pairs or :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        One or more class instances representing MIB variables to place
        into SNMP request.

    Note
    ----
    The `SnmpDispatcher` object may be expensive to create, therefore it is
    advised to maintain it for the lifecycle of the application/thread for
    as long as possible.

    Other Parameters
    ----------------
    \*\*options:
        Request options:

        * `lookupMib` - load MIB and resolve response MIB variables at
          the cost of slightly reduced performance. Default is `False`,
          unless :py:class:`~pysnmp.smi.rfc1902.ObjectType` is present
          among `varBinds` in which case `lookupMib` gets automatically
          enabled.

    Yields
    ------
    errorIndication: str
        True value indicates SNMP engine error.
    errorStatus: str
        True value indicates SNMP PDU error.
    errorIndex: int
        Non-zero value refers to `varBinds[errorIndex-1]`
    varBinds: tuple
        A sequence of sequences (e.g. 2-D array) of OID-value pairs in form
        of base SNMP types (if `lookupMib` is `False`) or
        :py:class:`~pysnmp.smi.rfc1902.ObjectType` class instances (if
        `lookupMib` is `True`) a table of MIB variables returned in SNMP
        response. Inner sequences represent table rows and ordered exactly
        the same as `varBinds` in request. Response to GETNEXT always contain
        a single row.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Examples
    --------
    >>> import asyncio
    >>> from pysnmp.hlapi.asyncio import *
    >>>
    >>> @asyncio.coroutine
    ... def run():
    ...     errorIndication, errorStatus, errorIndex, varBinds = yield from nextCmd(
    ...         SnmpDispatcher(),
    ...         CommunityData('public'),
    ...         UdpTransportTarget(('demo.snmplabs.com', 161)),
    ...         ContextData(),
    ...         ObjectType(ObjectIdentity('SNMPv2-MIB', 'system'))
    ...     )
    ...     print(errorIndication, errorStatus, errorIndex, varBinds)
    >>>
    >>> asyncio.get_event_loop().run_until_complete(run())
    (None, 0, 0, [[ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'), DisplayString('Linux i386'))]])
    >>>
    """
    def _cbFun(snmpDispatcher, stateHandle, errorIndication, rspPdu, _cbCtx):
        if future.cancelled():
            return

        errorStatus = pMod.apiPDU.getErrorStatus(rspPdu)
        errorIndex = pMod.apiPDU.getErrorIndex(rspPdu)

        varBindTable = pMod.apiPDU.getVarBindTable(reqPdu, rspPdu)

        if lookupMib:
            try:
                varBindTable = [
                    VB_PROCESSOR.unmakeVarBinds(snmpDispatcher.cache,
                                                varBindTableRow, lookupMib)
                    for varBindTableRow in varBindTable
                ]

            except Exception as e:
                future.set_exception(e)
                return

        future.set_result(
            (errorIndication, errorStatus, errorIndex, varBindTable)
        )

    lookupMib = options.get('lookupMib')

    if not lookupMib and any(isinstance(x, ObjectType) for x in varBinds):
        lookupMib = True

    if lookupMib:
        varBinds = VB_PROCESSOR.makeVarBinds(snmpDispatcher.cache, varBinds)

    pMod = api.PROTOCOL_MODULES[authData.mpModel]

    reqPdu = pMod.GetNextRequestPDU()
    pMod.apiPDU.setDefaults(reqPdu)
    pMod.apiPDU.setVarBinds(reqPdu, varBinds)

    future = asyncio.Future()

    snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)

    return future


@asyncio.coroutine
def bulkCmd(snmpDispatcher, authData, transportTarget,
            nonRepeaters, maxRepetitions, *varBinds, **options):
    """Creates a generator to perform SNMP GETBULK query.

    When iterator gets advanced by :py:mod:`asyncio` main loop,
    SNMP GETBULK request is send (:RFC:`1905#section-4.2.3`).
    The iterator yields :py:class:`asyncio.Future` which gets done whenever
    response arrives or error occurs.

    Parameters
    ----------
    snmpDispatcher: :py:class:`~pysnmp.hlapi.v1arch.asyncore.SnmpDispatcher`
        Class instance representing asynio-based asynchronous event loop and
        associated state information.

    authData: :py:class:`~pysnmp.hlapi.v1arch.CommunityData`
        Class instance representing SNMPv1/v2c credentials.

    transportTarget: :py:class:`~pysnmp.hlapi.v1arch.asyncio.UdpTransportTarget` or
        :py:class:`~pysnmp.hlapi.v1arch.asyncio.Udp6TransportTarget` Class instance representing
        transport type along with SNMP peer address.

    nonRepeaters : int
        One MIB variable is requested in response for the first
        `nonRepeaters` MIB variables in request.

    maxRepetitions : int
        `maxRepetitions` MIB variables are requested in response for each
        of the remaining MIB variables in the request (e.g. excluding
        `nonRepeaters`). Remote SNMP engine may choose lesser value than
        requested.

    \*varBinds: :class:`tuple` of OID-value pairs or :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        One or more class instances representing MIB variables to place
        into SNMP request.

    Other Parameters
    ----------------
    \*\*options :
        Request options:

        * `lookupMib` - load MIB and resolve response MIB variables at
          the cost of slightly reduced performance. Default is `False`,
          unless :py:class:`~pysnmp.smi.rfc1902.ObjectType` is present
          among `varBinds` in which case `lookupMib` gets automatically
          enabled.

    Yields
    ------
    errorIndication: str
        True value indicates SNMP engine error.
    errorStatus: str
        True value indicates SNMP PDU error.
    errorIndex: int
        Non-zero value refers to `varBinds[errorIndex-1]`
    varBindTable: tuple
        A sequence of sequences (e.g. 2-D array) of OID-value pairs in form
        of base SNMP types (if `lookupMib` is `False`) or
        :py:class:`~pysnmp.smi.rfc1902.ObjectType` class instances (if
        `lookupMib` is `True`) a table of MIB variables returned in SNMP
        response, with up to `maxRepetitions` rows, i.e.
        `len(varBindTable) <= maxRepetitions`.

        For `0 <= i < len(varBindTable)` and `0 <= j < len(varBinds)`,
        `varBindTable[i][j]` represents:

        - For non-repeaters (`j < nonRepeaters`), the first lexicographic
          successor of `varBinds[j]`, regardless the value of `i`, or an
          :py:class:`~pysnmp.smi.rfc1902.ObjectType` instance with the
          :py:obj:`~pysnmp.proto.rfc1905.endOfMibView` value if no such
          successor exists;
        - For repeaters (`j >= nonRepeaters`), the `i`-th lexicographic
          successor of `varBinds[j]`, or an
          :py:class:`~pysnmp.smi.rfc1902.ObjectType` instance with the
          :py:obj:`~pysnmp.proto.rfc1905.endOfMibView` value if no such
          successor exists.

        See :rfc:`3416#section-4.2.3` for details on the underlying
        `GetBulkRequest-PDU` and the associated `GetResponse-PDU`, such as
        specific conditions under which the server may truncate the response,
        causing `varBindTable` to have less than `maxRepetitions` rows.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Examples
    --------
    >>> import asyncio
    >>> from pysnmp.hlapi.v1arch.asyncio import *
    >>>
    >>> @asyncio.coroutine
    ... def run():
    ...     errorIndication, errorStatus, errorIndex, varBinds = yield from bulkCmd(
    ...         SnmpDispatcher(),
    ...         CommunityData('public'),
    ...         UdpTransportTarget(('demo.snmplabs.com', 161)),
    ...         0, 2,
    ...         ObjectType(ObjectIdentity('SNMPv2-MIB', 'system'))
    ...     )
    ...     print(errorIndication, errorStatus, errorIndex, varBinds)
    >>>
    >>> asyncio.get_event_loop().run_until_complete(run())
    (None, 0, 0, [[ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.1.0')), DisplayString('SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m'))], [ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.2.0')), ObjectIdentifier('1.3.6.1.4.1.424242.1.1'))]])
    >>>
    """
    def _cbFun(snmpDispatcher, stateHandle, errorIndication, rspPdu, _cbCtx):
        if future.cancelled():
            return

        errorStatus = pMod.apiPDU.getErrorStatus(rspPdu)
        errorIndex = pMod.apiPDU.getErrorIndex(rspPdu)

        varBindTable = pMod.apiBulkPDU.getVarBindTable(reqPdu, rspPdu)

        if lookupMib:
            try:
                varBindTable = [
                    VB_PROCESSOR.unmakeVarBinds(snmpDispatcher.cache,
                                                varBindTableRow, lookupMib)
                    for varBindTableRow in varBindTable
                ]

            except Exception as e:
                future.set_exception(e)
                return

        future.set_result(
            (errorIndication, errorStatus, errorIndex, varBindTable)
        )

    lookupMib = options.get('lookupMib')

    if not lookupMib and any(isinstance(x, ObjectType) for x in varBinds):
        lookupMib = True

    if lookupMib:
        varBinds = VB_PROCESSOR.makeVarBinds(snmpDispatcher.cache, varBinds)

    pMod = api.PROTOCOL_MODULES[authData.mpModel]

    reqPdu = pMod.GetBulkRequestPDU()
    pMod.apiPDU.setDefaults(reqPdu)
    pMod.apiBulkPDU.setNonRepeaters(reqPdu, nonRepeaters)
    pMod.apiBulkPDU.setMaxRepetitions(reqPdu, maxRepetitions)
    pMod.apiPDU.setVarBinds(reqPdu, varBinds)

    future = asyncio.Future()

    snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)

    return future
