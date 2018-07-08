#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.hlapi.varbinds import *
from pysnmp.hlapi.v1arch.auth import *
from pysnmp.hlapi.v1arch.asyncore import *
from pysnmp.smi.rfc1902 import *
from pysnmp.proto import api
from pysnmp.proto.proxy import rfc2576
from pysnmp import error

__all__ = ['sendNotification']

vbProcessor = NotificationOriginatorVarBinds()


def sendNotification(snmpDispatcher, authData, transportTarget,
                     notifyType, *varBinds, **options):
    """Send SNMP notification.

    Based on passed parameters, prepares SNMP TRAP or INFORM
    notification (:RFC:`1905#section-4.2.6`) and schedules its
    transmission by I/O framework at a later point of time.

    Parameters
    ----------
    snmpDispatcher: :py:class:`~pysnmp.hlapi.v1arch.asyncore.SnmpDispatcher`
        Class instance representing asyncore-based asynchronous event loop and
        associated state information.

    authData: :py:class:`~pysnmp.hlapi.CommunityData` or :py:class:`~pysnmp.hlapi.UsmUserData`
        Class instance representing SNMP credentials.

    transportTarget: :py:class:`~pysnmp.hlapi.asyncore.UdpTransportTarget` or
        :py:class:`~pysnmp.hlapi.asyncore.Udp6TransportTarget`
        Class instance representing transport type along with SNMP peer address.

    notifyType: str
        Indicates type of notification to be sent. Recognized literal
        values are *trap* or *inform*.

    \*varBinds: :class:`tuple` of OID-value pairs or :py:class:`~pysnmp.smi.rfc1902.ObjectType` or :py:class:`~pysnmp.smi.rfc1902.NotificationType`
        One or more objects representing MIB variables to place
        into SNMP notification. It could be tuples of OID-values
        or :py:class:`~pysnmp.smi.rfc1902.ObjectType` class instances
        of :py:class:`~pysnmp.smi.rfc1902.NotificationType` objects.

        SNMP Notification PDU places rigid requirement on the ordering of
        the variable-bindings.

        Mandatory variable-bindings:

        0. SNMPv2-MIB::sysUpTime.0 = <agent uptime>
        1. SNMPv2-SMI::snmpTrapOID.0 = {SNMPv2-MIB::coldStart, ...}

        Optional variable-bindings (applicable to SNMP v1 TRAP):

        2. SNMP-COMMUNITY-MIB::snmpTrapAddress.0 = <agent-IP>
        3. SNMP-COMMUNITY-MIB::snmpTrapCommunity.0 = <snmp-community-name>
        4. SNMP-COMMUNITY-MIB::snmpTrapEnterprise.0 = <enterprise-OID>

        Informational variable-bindings:

        * SNMPv2-SMI::NOTIFICATION-TYPE
        * SNMPv2-SMI::OBJECT-TYPE

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
    sendRequestHandle: int
        Unique request identifier. Can be used for matching received
        responses with ongoing *INFORM* requests. Returns `None` for
        *TRAP* notifications.

    Raises
    ------
    PySnmpError
        Or its derivative indicating that an error occurred while
        performing SNMP operation.

    Examples
    --------
    from pysnmp.hlapi.v1arch.asyncore import *

    snmpDispatcher = SnmpDispatcher()

    sendNotification(
        snmpDispatcher,
        CommunityData('public'),
        UdpTransportTarget(('demo.snmplabs.com', 162)),
        'trap',
        NotificationType(ObjectIdentity('SNMPv2-MIB', 'coldStart')),
        lookupMib=True
    )
    snmpDispatcher.transportDispatcher.runDispatcher()
    """

    def _cbFun(snmpDispatcher, stateHandle, errorIndication, rspPdu, _cbCtx):
        if not cbFun:
            return

        if errorIndication:
            cbFun(errorIndication, pMod.Integer(0), pMod.Integer(0), None,
                  cbCtx=cbCtx, snmpDispatcher=snmpDispatcher, stateHandle=stateHandle)
            return

        errorStatus = pMod.apiTrapPDU.getErrorStatus(rspPdu)
        errorIndex = pMod.apiTrapPDU.getErrorIndex(rspPdu)

        varBinds = pMod.apiTrapPDU.getVarBinds(rspPdu)

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

        pMod.apiTrapPDU.setRequestID(reqPdu, nextStateHandle)
        pMod.apiTrapPDU.setVarBinds(reqPdu, nextVarBinds)

        return snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)

    lookupMib, cbFun, cbCtx = [options.get(x) for x in ('lookupMib', 'cbFun', 'cbCtx')]

    if lookupMib:
        varBinds = vbProcessor.makeVarBinds(snmpDispatcher.cache, varBinds)

    # # make sure required PDU payload is in place
    # completeVarBinds = []
    #
    # # ensure sysUpTime
    # if len(varBinds) < 1 or varBinds[0][0] != pMod.apiTrapPDU.sysUpTime:
    #     varBinds.insert(0, (ObjectIdentifier(pMod.apiTrapPDU.sysUpTime), pMod.Integer(0)))
    #
    # # ensure sysUpTime
    # if len(varBinds) < 1 or varBinds[0][0] != pMod.apiTrapPDU.sysUpTime:
    #     varBinds.insert(0, (ObjectIdentifier(pMod.apiTrapPDU.sysUpTime), pMod.Integer(0)))
    #
    # # ensure snmpTrapOID
    # if len(varBinds) < 2 or varBinds[1][0] != pMod.apiTrapPDU.snmpTrapOID:
    #     varBinds.insert(0, (ObjectIdentifier(pMod.apiTrapPDU.sysUpTime), pMod.Integer(0)))

    # input PDU is always v2c
    pMod = api.protoModules[api.protoVersion2c]

    if notifyType == 'trap':
        reqPdu = pMod.TrapPDU()
    else:
        reqPdu = pMod.InformRequestPDU()

    pMod.apiTrapPDU.setDefaults(reqPdu)
    pMod.apiTrapPDU.setVarBinds(reqPdu, varBinds)

    if authData.mpModel == 0:
        reqPdu = rfc2576.v2ToV1(reqPdu)

    return snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)

