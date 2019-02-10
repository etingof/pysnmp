#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.smi.rfc1902 import *
from pysnmp.entity.rfc3413 import ntforg
from pysnmp.hlapi.v3arch.auth import *
from pysnmp.hlapi.v3arch.context import *
from pysnmp.hlapi.v3arch.lcd import *
from pysnmp.hlapi.varbinds import *
from pysnmp.hlapi.v3arch.asyncore.transport import *

__all__ = ['sendNotification']

VB_PROCESSOR = NotificationOriginatorVarBinds()
LCD = NotificationOriginatorLcdConfigurator()


def sendNotification(snmpEngine, authData, transportTarget, contextData,
                     notifyType, *varBinds, **options):
    """Send SNMP notification.

    Based on passed parameters, prepares SNMP TRAP or INFORM
    notification (:RFC:`1905#section-4.2.6`) and schedules its
    transmission by I/O framework at a later point of time.

    Parameters
    ----------
    snmpEngine : :py:class:`~pysnmp.hlapi.SnmpEngine`
        Class instance representing SNMP engine.

    authData : :py:class:`~pysnmp.hlapi.CommunityData` or :py:class:`~pysnmp.hlapi.UsmUserData`
        Class instance representing SNMP credentials.

    transportTarget : :py:class:`~pysnmp.hlapi.asyncore.UdpTransportTarget` or :py:class:`~pysnmp.hlapi.asyncore.Udp6TransportTarget`
        Class instance representing transport type along with SNMP peer
        address.

    contextData : :py:class:`~pysnmp.hlapi.ContextData`
        Class instance representing SNMP ContextEngineId and ContextName
        values.

    notifyType : str
        Indicates type of notification to be sent. Recognized literal
        values are *trap* or *inform*.

    \*varBinds: :class:`tuple` of OID-value pairs or :py:class:`~pysnmp.smi.rfc1902.ObjectType` or :py:class:`~pysnmp.smi.rfc1902.NotificationType`
        One or more objects representing MIB variables to place
        into SNMP notification. It could be tuples of OID-values
        or :py:class:`~pysnmp.smi.rfc1902.ObjectType` class instances
        of :py:class:`~pysnmp.smi.rfc1902.NotificationType` objects.

        SNMP Notification PDU includes some housekeeping items that
        are required for SNMP to function.

        Agent information:

        * SNMPv2-MIB::sysUpTime.0 = <agent uptime>
        * SNMPv2-SMI::snmpTrapOID.0 = {SNMPv2-MIB::coldStart, ...}

        Applicable to SNMP v1 TRAP:

        * SNMP-COMMUNITY-MIB::snmpTrapAddress.0 = <agent-IP>
        * SNMP-COMMUNITY-MIB::snmpTrapCommunity.0 = <snmp-community-name>
        * SNMP-COMMUNITY-MIB::snmpTrapEnterprise.0 = <enterprise-OID>

        .. note::

           Unless user passes some of these variable-bindings, `.sendNotification()`
           call will fill in the missing items.

        User variable-bindings:

        * SNMPv2-SMI::NOTIFICATION-TYPE
        * SNMPv2-SMI::OBJECT-TYPE

        .. note::

           The :py:class:`~pysnmp.smi.rfc1902.NotificationType` object ensures
           properly formed SNMP notification (to comply MIB definition). If you
           build notification PDU out of :py:class:`~pysnmp.smi.rfc1902.ObjectType`
           objects or simple tuples of OID-value objects, it is your responsibility
           to provide well-formed notificaton payload.

    Other Parameters
    ----------------
    \*\*options:

        * lookupMib: bool
            `lookupMib` - load MIB and resolve response MIB variables at
            the cost of slightly reduced performance. Default is `True`.
        * cbFun: callable
            user-supplied callable that is invoked to pass SNMP response
            to *INFORM* notification or error to user at a later point of
            time. The `cbFun` callable is never invoked for *TRAP* notifications.
        * cbCtx: object
            user-supplied object passing additional parameters to/from
            `cbFun`

    Notes
    -----
    User-supplied `cbFun` callable must have the following call
    signature:

    * snmpEngine (:py:class:`~pysnmp.hlapi.SnmpEngine`):
      Class instance representing SNMP engine.
    * sendRequestHandle (int): Unique request identifier. Can be used
      for matching multiple ongoing *INFORM* notifications with received
      responses.
    * errorIndication (str): True value indicates SNMP engine error.
    * errorStatus (str): True value indicates SNMP PDU error.
    * errorIndex (int): Non-zero value refers to `varBinds[errorIndex-1]`
    * varBinds (tuple): A sequence of
      :py:class:`~pysnmp.smi.rfc1902.ObjectType` class instances
      representing MIB variables returned in SNMP response in exactly
      the same order as `varBinds` in request.
    * `cbCtx` : Original user-supplied object.

    Returns
    -------
    sendRequestHandle : int
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
    >>> from pysnmp.hlapi.asyncore import *
    >>>
    >>> snmpEngine = SnmpEngine()
    >>> sendNotification(
    ...     snmpEngine,
    ...     CommunityData('public'),
    ...     UdpTransportTarget(('demo.snmplabs.com', 162)),
    ...     ContextData(),
    ...     'trap',
    ...     NotificationType(ObjectIdentity('SNMPv2-MIB', 'coldStart')),
    ... )
    >>> snmpEngine.transportDispatcher.runDispatcher()
    >>>

    """

    # noinspection PyShadowingNames
    def __cbFun(snmpEngine, sendRequestHandle, errorIndication,
                errorStatus, errorIndex, varBinds, cbCtx):
        lookupMib, cbFun, cbCtx = cbCtx
        return cbFun and cbFun(
            snmpEngine, sendRequestHandle, errorIndication,
            errorStatus, errorIndex,
            VB_PROCESSOR.unmakeVarBinds(
                snmpEngine.cache, varBinds, lookupMib
            ), cbCtx
        )

    notifyName = LCD.configure(snmpEngine, authData, transportTarget,
                               notifyType, contextData.contextName)

    return ntforg.NotificationOriginator().sendVarBinds(
        snmpEngine, notifyName,
        contextData.contextEngineId, contextData.contextName,
        VB_PROCESSOR.makeVarBinds(snmpEngine.cache, varBinds), __cbFun,
        (options.get('lookupMib', True),
         options.get('cbFun'), options.get('cbCtx'))
    )
