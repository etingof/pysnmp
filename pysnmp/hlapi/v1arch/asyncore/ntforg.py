#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.hlapi.v1arch.auth import *
from pysnmp.hlapi.v1arch.asyncore import *
from pysnmp.hlapi.varbinds import *
from pysnmp.smi.rfc1902 import *
from pysnmp.proto.api import v2c
from pysnmp.proto.proxy import rfc2576
from pysnmp import error

__all__ = ['sendNotification']

VB_PROCESSOR = NotificationOriginatorVarBinds()


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

        Besides user variable-bindings, SNMP Notification PDU requires at
        least two variable-bindings to be present:

        0. SNMPv2-MIB::sysUpTime.0 = <agent uptime>
        1. SNMPv2-SMI::snmpTrapOID.0 = <notification ID>

        When sending SNMPv1 TRAP, more variable-bindings could be present:

        2. SNMP-COMMUNITY-MIB::snmpTrapAddress.0 = <agent-IP>
        3. SNMP-COMMUNITY-MIB::snmpTrapCommunity.0 = <snmp-community-name>
        4. SNMP-COMMUNITY-MIB::snmpTrapEnterprise.0 = <enterprise-OID>

        If user does not supply some or any of the above variable-bindings or
        if they are at the wrong positions, the system will add/reorder the
        missing ones automatically.

        On top of that, some notification types imply including some additional
        variable-bindings providing additional details on the event being
        reported. Therefore it is generally easier to use
        :py:class:`~pysnmp.smi.rfc1902.NotificationType` object which will
        help adding relevant variable-bindings.

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
    >>> from pysnmp.hlapi.v1arch.asyncore import *
    >>>
    >>> snmpDispatcher = SnmpDispatcher()
    >>>
    >>> sendNotification(
    >>>     snmpDispatcher,
    >>>     CommunityData('public'),
    >>>     UdpTransportTarget(('demo.snmplabs.com', 162)),
    >>>     'trap',
    >>>     NotificationType(ObjectIdentity('SNMPv2-MIB', 'coldStart')),
    >>>     lookupMib=True
    >>> )
    >>> snmpDispatcher.transportDispatcher.runDispatcher()
    """

    sysUpTime = v2c.apiTrapPDU.sysUpTime
    snmpTrapOID = v2c.apiTrapPDU.snmpTrapOID

    def _ensureVarBinds(varBinds):
        # Add sysUpTime if not present already
        if not varBinds or varBinds[0][0] != sysUpTime:
            varBinds.insert(0, (v2c.ObjectIdentifier(sysUpTime), v2c.TimeTicks(0)))

        # Search for and reposition sysUpTime if it's elsewhere
        for idx, varBind in enumerate(varBinds[1:]):
            if varBind[0] == sysUpTime:
                varBinds[0] = varBind
                del varBinds[idx + 1]
                break

        if len(varBinds) < 2:
            raise error.PySnmpError('SNMP notification PDU requires '
                                    'SNMPv2-MIB::snmpTrapOID.0 to be present')

        # Search for and reposition snmpTrapOID if it's elsewhere
        for idx, varBind in enumerate(varBinds[2:]):
            if varBind[0] == snmpTrapOID:
                del varBinds[idx + 2]
                if varBinds[1][0] == snmpTrapOID:
                    varBinds[1] = varBind
                else:
                    varBinds.insert(1, varBind)
                break

        # Fail on missing snmpTrapOID
        if varBinds[1][0] != snmpTrapOID:
            raise error.PySnmpError('SNMP notification PDU requires '
                                    'SNMPv2-MIB::snmpTrapOID.0 to be present')

        return varBinds

    def _cbFun(snmpDispatcher, stateHandle, errorIndication, rspPdu, _cbCtx):
        if not cbFun:
            return

        if errorIndication:
            cbFun(errorIndication, v2c.Integer(0), v2c.Integer(0), None,
                  cbCtx=cbCtx, snmpDispatcher=snmpDispatcher, stateHandle=stateHandle)
            return

        errorStatus = v2c.apiTrapPDU.getErrorStatus(rspPdu)
        errorIndex = v2c.apiTrapPDU.getErrorIndex(rspPdu)

        varBinds = v2c.apiTrapPDU.getVarBinds(rspPdu)

        if lookupMib:
            varBinds = VB_PROCESSOR.unmakeVarBinds(snmpDispatcher.cache, varBinds)

        nextStateHandle = v2c.getNextRequestID()

        nextVarBinds = cbFun(errorIndication, errorStatus, errorIndex, varBinds,
                             cbCtx=cbCtx,
                             snmpDispatcher=snmpDispatcher,
                             stateHandle=stateHandle,
                             nextStateHandle=nextStateHandle)

        if not nextVarBinds:
            return

        v2c.apiTrapPDU.setRequestID(reqPdu, nextStateHandle)
        v2c.apiTrapPDU.setVarBinds(reqPdu, _ensureVarBinds(nextVarBinds))

        return snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)

    lookupMib, cbFun, cbCtx = [options.get(x) for x in ('lookupMib', 'cbFun', 'cbCtx')]

    if lookupMib:
        varBinds = VB_PROCESSOR.makeVarBinds(snmpDispatcher.cache, varBinds)

    if notifyType == 'trap':
        reqPdu = v2c.TrapPDU()
    else:
        reqPdu = v2c.InformRequestPDU()

    v2c.apiTrapPDU.setDefaults(reqPdu)
    v2c.apiTrapPDU.setVarBinds(reqPdu, varBinds)

    varBinds = v2c.apiTrapPDU.getVarBinds(reqPdu)

    v2c.apiTrapPDU.setVarBinds(reqPdu, _ensureVarBinds(varBinds))

    if authData.mpModel == 0:
        reqPdu = rfc2576.v2ToV1(reqPdu)

    return snmpDispatcher.sendPdu(authData, transportTarget, reqPdu, cbFun=_cbFun)

