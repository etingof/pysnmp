#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#

from pysnmp.hlapi.varbinds import *
from pysnmp.hlapi.v1arch.auth import *
from pysnmp.hlapi.v1arch.asyncore import *
from pysnmp.smi.rfc1902 import *
from pysnmp.proto import api
from pysnmp import error

__all__ = ['getCmd', 'nextCmd', 'setCmd', 'bulkCmd']

vbProcessor = CommandGeneratorVarBinds()


def getCmd(snmpDispatcher, authData, transportTarget, *varBinds, **options):
    """Initiate SNMP GET query over SNMPv1/v2c.

    Based on passed parameters, prepares SNMP GET packet
    (:RFC:`1905#section-4.2.1`) and schedules its transmission by
    I/O framework at a later point of time.

    Parameters
    ----------
    snmpDispatcher: :py:class:`~pysnmp.hlapi.v1arch.asyncore.SnmpDispatcher`
        Class instance representing asyncore-based asynchronous event loop and
        associated state information.

    authData: :py:class:`~pysnmp.hlapi.v1arch.CommunityData`
        Class instance representing SNMPv1/v2c credentials.

    transportTarget: :py:class:`~pysnmp.hlapi.v1arch.asyncore.UdpTransportTarget` or
        :py:class:`~pysnmp.hlapi.v1arch.asyncore.Udp6TransportTarget` Class instance representing
        transport type along with SNMP peer address.

    \*varBinds: :class:`tuple` of OID-value pairs or :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        One or more class instances representing MIB variables to place
        into SNMP request.

    Other Parameters
    ----------------
    \*\*options:
        Request options:

        * `lookupMib` - load MIB and resolve response MIB variables at
          the cost of slightly reduced performance. Default is `False`.
        * `cbFun` (callable) - user-supplied callable that is invoked
          to pass SNMP response data or error to user at a later point
          of time. Default is `None`.
        * `cbCtx` (object) - user-supplied object passing additional
          parameters to/from `cbFun`. Default is `None`.

    Note
    ----
    The `SnmpDispatcher` object may be expensive to create, therefore it is
    advised to maintain it for the lifecycle of the application/thread for
    as long as possible.

    Note
    ----
    User-supplied `cbFun` callable must have the following call
    signature:

    * snmpDispatcher: :py:class:`~pysnmp.hlapi.v1arch.asyncore.SnmpDispatcher`
      Class instance representing asyncore-based asynchronous event loop and
      associated state information.
    * stateHandle (int): Unique request identifier. Can be used
      for matching multiple ongoing requests with received responses.
    * errorIndication (str): evaluates to `True` to indicate SNMP dispatcher
      error.
    * errorStatus (int): evaluates to `True` to indicate SNMP PDU error.
    * errorIndex (int): Non-zero value refers to `varBinds[errorIndex-1]`
    * varBinds (tuple): A sequence of
      :py:class:`~pysnmp.smi.rfc1902.ObjectType` class instances
      representing MIB variables returned in SNMP response in exactly
      the same order as `varBinds` in request.
    * `cbCtx` (object): Original user-supplied object.

    Returns
    -------
    stateHandle: int
        Unique request identifier. Can be used for matching received
        responses with ongoing requests.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Examples
    --------
    >>> from pysnmp.hlapi.v1arch.asyncore import *
    >>>
    >>> def cbFun(snmpDispatcher, stateHandle, errorIndication,
    >>>           errorStatus, errorIndex, varBinds, cbCtx):
    >>>     print(errorIndication, errorStatus, errorIndex, varBinds)
    >>>
    >>> snmpDispatcher = SnmpDispatcher()
    >>>
    >>> stateHandle = getCmd(
    >>>     snmpDispatcher,
    >>>     CommunityData('public'),
    >>>     UdpTransportTarget(('demo.snmplabs.com', 161)),
    >>>     ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
    >>>     cbFun=cbFun
    >>> )
    >>>
    >>> snmpDispatcher.transportDispatcher.runDispatcher()
    """

    def _cbFun(snmpDispatcher, stateHandle, errorIndication, rspPdu, _cbCtx):
        if not cbFun:
            return

        if errorIndication:
            cbFun(errorIndication, pMod.Integer(0), pMod.Integer(0), None,
                  cbCtx=cbCtx, snmpDispatcher=snmpDispatcher, stateHandle=stateHandle)
            return

        errorStatus = pMod.apiPDU.getErrorStatus(rspPdu)
        errorIndex = pMod.apiPDU.getErrorIndex(rspPdu)

        varBinds = pMod.apiPDU.getVarBinds(rspPdu)

        if lookupMib:
            varBinds = vbProcessor.unmakeVarBinds(snmpDispatcher.cache, varBinds)

        nextStateHandle = pMod.getNextRequestID()

        nextVarBinds = cbFun(errorIndication, errorStatus, errorIndex, varBinds,
                             cbCtx=cbCtx,
                             snmpDispatcher=snmpDispatcher,
                             stateHandle=stateHandle,
                             nextStateHandle=nextStateHandle)

        if not nextVarBinds:
            return

        pMod.apiPDU.setRequestID(reqPdu, nextStateHandle)
        pMod.apiPDU.setVarBinds(reqPdu, nextVarBinds)

        return snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)

    lookupMib, cbFun, cbCtx = [options.get(x) for x in ('lookupMib', 'cbFun', 'cbCtx')]

    if lookupMib:
        varBinds = vbProcessor.makeVarBinds(snmpDispatcher.cache, varBinds)

    pMod = api.PROTOCOL_MODULES[authData.mpModel]

    reqPdu = pMod.GetRequestPDU()
    pMod.apiPDU.setDefaults(reqPdu)
    pMod.apiPDU.setVarBinds(reqPdu, varBinds)

    return snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)


def setCmd(snmpDispatcher, authData, transportTarget,
           *varBinds, **options):
    """Initiate SNMP SET query over SNMPv1/v2c.

    Based on passed parameters, prepares SNMP SET packet
    (:RFC:`1905#section-4.2.5`) and schedules its transmission by
    I/O framework at a later point of time.

    Parameters
    ----------
    snmpDispatcher: :py:class:`~pysnmp.hlapi.v1arch.asyncore.SnmpDispatcher`
        Class instance representing asyncore-based asynchronous event loop and
        associated state information.

    authData: :py:class:`~pysnmp.hlapi.v1arch.CommunityData`
        Class instance representing SNMP credentials.

    transportTarget: :py:class:`~pysnmp.hlapi.v1arch.asyncore.UdpTransportTarget` or :py:class:`~pysnmp.hlapi.v1arch.asyncore.Udp6TransportTarget`
        Class instance representing transport type along with SNMP peer
        address.

    \*varBinds: :class:`tuple` of OID-value pairs or :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        One or more class instances representing MIB variables to place
        into SNMP request.

    Other Parameters
    ----------------
    \*\*options :
        Request options:

            * `lookupMib` - load MIB and resolve response MIB variables at
              the cost of slightly reduced performance. Default is `False`.
            * `cbFun` (callable) - user-supplied callable that is invoked
               to pass SNMP response data or error to user at a later point
               of time. Default is `None`.
            * `cbCtx` (object) - user-supplied object passing additional
               parameters to/from `cbFun`. Default is `None`.

    Note
    ----
    The `SnmpDispatcher` object may be expensive to create, therefore it is
    advised to maintain it for the lifecycle of the application/thread for
    as long as possible.

    Note
    ----
    User-supplied `cbFun` callable must have the following call
    signature:

    * snmpDispatcher: :py:class:`~pysnmp.hlapi.v1arch.asyncore.SnmpDispatcher`
      Class instance representing asyncore-based asynchronous event loop and
      associated state information.
    * stateHandle (int): Unique request identifier. Can be used
      for matching multiple ongoing requests with received responses.
    * errorIndication (str): evaluates to `True` to indicate SNMP dispatcher
      error.
    * errorStatus (int): evaluates to `True` to indicate SNMP PDU error.
    * errorIndex (int): Non-zero value refers to `varBinds[errorIndex-1]`
    * varBinds (tuple): A sequence of
      :py:class:`~pysnmp.smi.rfc1902.ObjectType` class instances
      representing MIB variables returned in SNMP response in exactly
      the same order as `varBinds` in request.
    * `cbCtx` (object): Original user-supplied object.

    Returns
    -------
    stateHandle: int
        Unique request identifier. Can be used for matching received
        responses with ongoing requests.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Examples
    --------
    >>> from pysnmp.hlapi.v1arch.asyncore import *
    >>>
    >>> def cbFun(snmpDispatcher, stateHandle, errorIndication,
    >>>           errorStatus, errorIndex, varBinds, cbCtx):
    >>>     print(errorIndication, errorStatus, errorIndex, varBinds)
    >>>
    >>> snmpDispatcher = SnmpDispatcher()
    >>>
    >>> stateHandle = setCmd(
    >>>     snmpDispatcher,
    >>>     CommunityData('public'),
    >>>     UdpTransportTarget(('demo.snmplabs.com', 161)),
    >>>     ('1.3.6.1.2.1.1.4.0', OctetString('info@snmplabs.com')),
    >>>     cbFun=cbFun
    >>> )
    >>>
    >>> snmpDispatcher.transportDispatcher.runDispatcher()
    """

    def _cbFun(snmpDispatcher, stateHandle, errorIndication, rspPdu, _cbCtx):
        if not cbFun:
            return

        if errorIndication:
            cbFun(errorIndication, pMod.Integer(0), pMod.Integer(0), None,
                  cbCtx=cbCtx, snmpDispatcher=snmpDispatcher, stateHandle=stateHandle)
            return

        errorStatus = pMod.apiPDU.getErrorStatus(rspPdu)
        errorIndex = pMod.apiPDU.getErrorIndex(rspPdu)

        varBinds = pMod.apiPDU.getVarBinds(rspPdu)

        if lookupMib:
            varBinds = vbProcessor.unmakeVarBinds(snmpDispatcher.cache, varBinds)

        nextStateHandle = pMod.getNextRequestID()

        nextVarBinds = cbFun(errorIndication, errorStatus, errorIndex, varBinds,
                             cbCtx=cbCtx,
                             snmpDispatcher=snmpDispatcher,
                             stateHandle=stateHandle,
                             nextStateHandle=nextStateHandle)

        if not nextVarBinds:
            return

        pMod.apiPDU.setRequestID(reqPdu, nextStateHandle)
        pMod.apiPDU.setVarBinds(reqPdu, nextVarBinds)

        return snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)

    lookupMib, cbFun, cbCtx = [options.get(x) for x in ('lookupMib', 'cbFun', 'cbCtx')]

    if lookupMib:
        varBinds = vbProcessor.makeVarBinds(snmpDispatcher.cache, varBinds)

    pMod = api.PROTOCOL_MODULES[authData.mpModel]

    reqPdu = pMod.SetRequestPDU()
    pMod.apiPDU.setDefaults(reqPdu)
    pMod.apiPDU.setVarBinds(reqPdu, varBinds)

    return snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)


def nextCmd(snmpDispatcher, authData, transportTarget,
            *varBinds, **options):
    """Initiate SNMP GETNEXT query over SNMPv1/v2c.

    Based on passed parameters, prepares SNMP GETNEXT packet
    (:RFC:`1905#section-4.2.2`) and schedules its transmission by
    I/O framework at a later point of time.

    Parameters
    ----------
    snmpDispatcher: :py:class:`~pysnmp.hlapi.v1arch.asyncore.SnmpDispatcher`
        Class instance representing SNMP dispatcher.

    authData: :py:class:`~pysnmp.hlapi.v1arch.CommunityData` or :py:class:`~pysnmp.hlapi.v1arch.UsmUserData`
        Class instance representing SNMP credentials.

    transportTarget: :py:class:`~pysnmp.hlapi.v1arch.asyncore.UdpTransportTarget` or :py:class:`~pysnmp.hlapi.v1arch.asyncore.Udp6TransportTarget`
        Class instance representing transport type along with SNMP peer
        address.

    \*varBinds: :class:`tuple` of OID-value pairs or :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        One or more class instances representing MIB variables to place
        into SNMP request.

    Other Parameters
    ----------------
    \*\*options :
        Request options:

            * `lookupMib` - load MIB and resolve response MIB variables at
              the cost of slightly reduced performance. Default is `True`.
            * `cbFun` (callable) - user-supplied callable that is invoked
              to pass SNMP response data or error to user at a later point
              of time. Default is `None`.
            * `cbCtx` (object) - user-supplied object passing additional
              parameters to/from `cbFun`. Default is `None`.

    Notes
    -----
    User-supplied `cbFun` callable must have the following call
    signature:

    * snmpDispatcher (:py:class:`~pysnmp.hlapi.v1arch.snmpDispatcher`):
      Class instance representing SNMP dispatcher.
    * stateHandle (int): Unique request identifier. Can be used
      for matching multiple ongoing requests with received responses.
    * errorIndication (str): True value indicates SNMP dispatcher error.
    * errorStatus (str): True value indicates SNMP PDU error.
    * errorIndex (int): Non-zero value refers to `varBinds[errorIndex-1]`
    * varBindTable (tuple): A sequence of sequences (e.g. 2-D array) of
      variable-bindings represented as :class:`tuple` or
      :py:class:`~pysnmp.smi.rfc1902.ObjectType` class instances
      representing a table of MIB variables returned in SNMP response.
      Inner sequences represent table rows and ordered exactly the same
      as `varBinds` in request. Response to GETNEXT always contain a
      single row.
    * `cbCtx` (object): Original user-supplied object.

    Returns
    -------
    stateHandle: int
        Unique request identifier. Can be used for matching received
        responses with ongoing requests.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Examples
    --------
    >>> from pysnmp.hlapi.v1arch.asyncore import *
    >>>
    >>> def cbFun(snmpDispatcher, stateHandle, errorIndication,
    >>>           errorStatus, errorIndex, varBinds, cbCtx):
    >>>     print(errorIndication, errorStatus, errorIndex, varBinds)
    >>>
    >>> snmpDispatcher = snmpDispatcher()
    >>>
    >>> stateHandle = nextCmd(
    >>>     snmpDispatcher,
    >>>     CommunityData('public'),
    >>>     UdpTransportTarget(('demo.snmplabs.com', 161)),
    >>>     ('1.3.6.1.2.1.1', None),
    >>>     cbFun=cbFun
    >>> )
    >>>
    >>> snmpDispatcher.transportDispatcher.runDispatcher()
    """

    def _cbFun(snmpDispatcher, stateHandle, errorIndication, rspPdu, _cbCtx):
        if not cbFun:
            return

        if errorIndication:
            cbFun(errorIndication, pMod.Integer(0), pMod.Integer(0), None,
                  cbCtx=cbCtx, snmpDispatcher=snmpDispatcher, stateHandle=stateHandle)
            return

        errorStatus = pMod.apiPDU.getErrorStatus(rspPdu)
        errorIndex = pMod.apiPDU.getErrorIndex(rspPdu)

        varBindTable = pMod.apiPDU.getVarBindTable(reqPdu, rspPdu)

        errorIndication, nextVarBinds = pMod.apiPDU.getNextVarBinds(
            varBindTable[-1], errorIndex=errorIndex
        )

        if options.get('lookupMib'):
            varBindTable = [
                vbProcessor.unmakeVarBinds(snmpDispatcher.cache, vbs) for vbs in varBindTable
            ]

        nextStateHandle = pMod.getNextRequestID()

        nextVarBinds = cbFun(errorIndication, errorStatus, errorIndex, varBindTable,
                             cbCtx=cbCtx,
                             snmpDispatcher=snmpDispatcher,
                             stateHandle=stateHandle,
                             nextStateHandle=nextStateHandle,
                             nextVarBinds=nextVarBinds)

        if not nextVarBinds:
            return

        pMod.apiPDU.setRequestID(reqPdu, nextStateHandle)
        pMod.apiPDU.setVarBinds(reqPdu, nextVarBinds)

        return snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)

    lookupMib, cbFun, cbCtx = [options.get(x) for x in ('lookupMib', 'cbFun', 'cbCtx')]

    if lookupMib:
        varBinds = vbProcessor.makeVarBinds(snmpDispatcher.cache, varBinds)

    pMod = api.PROTOCOL_MODULES[authData.mpModel]

    reqPdu = pMod.GetNextRequestPDU()
    pMod.apiPDU.setDefaults(reqPdu)
    pMod.apiPDU.setVarBinds(reqPdu, varBinds)

    return snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)


def bulkCmd(snmpDispatcher, authData, transportTarget,
            nonRepeaters, maxRepetitions, *varBinds, **options):
    """Initiate SNMP GETBULK query over SNMPv2c.

    Based on passed parameters, prepares SNMP GETBULK packet
    (:RFC:`1905#section-4.2.3`) and schedules its transmission by
    I/O framework at a later point of time.

    Parameters
    ----------
    snmpDispatcher: :py:class:`~pysnmp.hlapi.v1arch.asyncore.SnmpDispatcher`
        Class instance representing SNMP dispatcher.

    authData: :py:class:`~pysnmp.hlapi.v1arch.CommunityData` or :py:class:`~pysnmp.hlapi.v1arch.UsmUserData`
        Class instance representing SNMP credentials.

    transportTarget: :py:class:`~pysnmp.hlapi.v1arch.asyncore.UdpTransportTarget` or :py:class:`~pysnmp.hlapi.v1arch.asyncore.Udp6TransportTarget`
        Class instance representing transport type along with SNMP peer
        address.

    nonRepeaters: int
        One MIB variable is requested in response for the first
        `nonRepeaters` MIB variables in request.

    maxRepetitions: int
        `maxRepetitions` MIB variables are requested in response for each
        of the remaining MIB variables in the request (e.g. excluding
        `nonRepeaters`). Remote SNMP dispatcher may choose lesser value than
        requested.

    \*varBinds: :py:class:`~pysnmp.smi.rfc1902.ObjectType`
        One or more class instances representing MIB variables to place
        into SNMP request.

    Other Parameters
    ----------------
    \*\*options :
        Request options:

            * `lookupMib` - load MIB and resolve response MIB variables at
              the cost of slightly reduced performance. Default is `True`.
            * `cbFun` (callable) - user-supplied callable that is invoked
               to pass SNMP response data or error to user at a later point
               of time. Default is `None`.
            * `cbCtx` (object) - user-supplied object passing additional
               parameters to/from `cbFun`. Default is `None`.

    Notes
    -----
    User-supplied `cbFun` callable must have the following call
    signature:

    * snmpDispatcher (:py:class:`~pysnmp.hlapi.v1arch.snmpDispatcher`):
      Class instance representing SNMP dispatcher.
    * stateHandle (int): Unique request identifier. Can be used
      for matching multiple ongoing requests with received responses.
    * errorIndication (str): True value indicates SNMP dispatcher error.
    * errorStatus (str): True value indicates SNMP PDU error.
    * errorIndex (int): Non-zero value refers to `varBinds[errorIndex-1]`
    * varBindTable (tuple): A sequence of sequences (e.g. 2-D array) of
      variable-bindings represented as :class:`tuple` or
      :py:class:`~pysnmp.smi.rfc1902.ObjectType` class instances
      representing a table of MIB variables returned in SNMP response, with
      up to ``maxRepetitions`` rows, i.e. ``len(varBindTable) <= maxRepetitions``.

      For ``0 <= i < len(varBindTable)`` and ``0 <= j < len(varBinds)``,
      ``varBindTable[i][j]`` represents:

      - For non-repeaters (``j < nonRepeaters``), the first lexicographic
        successor of ``varBinds[j]``, regardless the value of ``i``, or an
        :py:class:`~pysnmp.smi.rfc1902.ObjectType` instance with the
        :py:obj:`~pysnmp.proto.rfc1905.endOfMibView` value if no such successor
        exists;
      - For repeaters (``j >= nonRepeaters``), the ``i``-th lexicographic
        successor of ``varBinds[j]``, or an
        :py:class:`~pysnmp.smi.rfc1902.ObjectType` instance with the
        :py:obj:`~pysnmp.proto.rfc1905.endOfMibView` value if no such successor
        exists.

      See :rfc:`3416#section-4.2.3` for details on the underlying
      ``GetBulkRequest-PDU`` and the associated ``GetResponse-PDU``, such as
      specific conditions under which the server may truncate the response,
      causing ``varBindTable`` to have less than ``maxRepetitions`` rows.
    * `cbCtx` (object): Original user-supplied object.

    Returns
    -------
    stateHandle : int
        Unique request identifier. Can be used for matching received
        responses with ongoing requests.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Examples
    --------
    >>> from pysnmp.hlapi.v1arch.asyncore import *
    >>>
    >>> def cbFun(snmpDispatcher, stateHandle, errorIndication,
    >>>           errorStatus, errorIndex, varBinds, cbCtx):
    >>>     print(errorIndication, errorStatus, errorIndex, varBinds)
    >>>
    >>> snmpDispatcher = snmpDispatcher()
    >>>
    >>> stateHandle = bulkCmd(
    >>>     snmpDispatcher,
    >>>     CommunityData('public'),
    >>>     UdpTransportTarget(('demo.snmplabs.com', 161)),
    >>>     0, 2,
    >>>     ('1.3.6.1.2.1.1', None),
    >>>     cbFun=cbFun
    >>> )
    >>>
    >>> snmpDispatcher.transportDispatcher.runDispatcher()
    """

    def _cbFun(snmpDispatcher, stateHandle, errorIndication, rspPdu, _cbCtx):
        if not cbFun:
            return

        if errorIndication:
            cbFun(errorIndication, pMod.Integer(0), pMod.Integer(0), None,
                  cbCtx=cbCtx, snmpDispatcher=snmpDispatcher, stateHandle=stateHandle)
            return

        errorStatus = pMod.apiBulkPDU.getErrorStatus(rspPdu)
        errorIndex = pMod.apiBulkPDU.getErrorIndex(rspPdu)

        varBindTable = pMod.apiBulkPDU.getVarBindTable(reqPdu, rspPdu)

        errorIndication, nextVarBinds = pMod.apiBulkPDU.getNextVarBinds(
            varBindTable[-1], errorIndex=errorIndex
        )

        if options.get('lookupMib'):
            varBindTable = [
                vbProcessor.unmakeVarBinds(snmpDispatcher.cache, vbs) for vbs in varBindTable
            ]

        nextStateHandle = pMod.getNextRequestID()

        nextVarBinds = cbFun(errorIndication, errorStatus, errorIndex, varBindTable,
                             cbCtx=cbCtx,
                             snmpDispatcher=snmpDispatcher,
                             stateHandle=stateHandle,
                             nextStateHandle=nextStateHandle,
                             nextVarBinds=nextVarBinds)

        if not nextVarBinds:
            return

        pMod.apiBulkPDU.setRequestID(reqPdu, nextStateHandle)
        pMod.apiBulkPDU.setVarBinds(reqPdu, nextVarBinds)

        return snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)

    if authData.mpModel < 1:
        raise error.PySnmpError('GETBULK PDU is only supported in SNMPv2c and SNMPv3')

    lookupMib, cbFun, cbCtx = [options.get(x) for x in ('lookupMib', 'cbFun', 'cbCtx')]

    if lookupMib:
        varBinds = vbProcessor.makeVarBinds(snmpDispatcher.cache, varBinds)

    pMod = api.PROTOCOL_MODULES[authData.mpModel]

    reqPdu = pMod.GetBulkRequestPDU()
    pMod.apiBulkPDU.setDefaults(reqPdu)
    pMod.apiBulkPDU.setNonRepeaters(reqPdu, nonRepeaters)
    pMod.apiBulkPDU.setMaxRepetitions(reqPdu, maxRepetitions)
    pMod.apiBulkPDU.setVarBinds(reqPdu, varBinds)

    return snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)
