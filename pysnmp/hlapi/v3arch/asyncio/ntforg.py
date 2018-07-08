#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# Copyright (C) 2014, Zebra Technologies
# Authors: Matt Hooks <me@matthooks.com>
#          Zachary Lorusso <zlorusso@gmail.com>
#
from pysnmp.smi.rfc1902 import *
from pysnmp.hlapi.v3arch.auth import *
from pysnmp.hlapi.v3arch.context import *
from pysnmp.hlapi.v3arch.lcd import *
from pysnmp.hlapi.varbinds import *
from pysnmp.hlapi.v3arch.asyncio.transport import *
from pysnmp.entity.rfc3413 import ntforg

try:
    import asyncio
except ImportError:
    import trollius as asyncio

__all__ = ['sendNotification']

vbProcessor = NotificationOriginatorVarBinds()
lcd = NotificationOriginatorLcdConfigurator()


@asyncio.coroutine
def sendNotification(snmpEngine, authData, transportTarget, contextData,
                     notifyType, *varBinds, **options):
    """Creates a generator to send SNMP notification.

    When iterator gets advanced by :py:mod:`asyncio` main loop,
    SNMP TRAP or INFORM notification is send (:RFC:`1905#section-4.2.6`).
    The iterator yields :py:class:`asyncio.Future` which gets done whenever
    response arrives or error occurs.

    Parameters
    ----------
    snmpEngine : :py:class:`~pysnmp.hlapi.SnmpEngine`
        Class instance representing SNMP engine.

    authData : :py:class:`~pysnmp.hlapi.CommunityData` or :py:class:`~pysnmp.hlapi.UsmUserData`
        Class instance representing SNMP credentials.

    transportTarget : :py:class:`~pysnmp.hlapi.asyncio.UdpTransportTarget` or :py:class:`~pysnmp.hlapi.asyncio.Udp6TransportTarget`
        Class instance representing transport type along with SNMP peer address.

    contextData : :py:class:`~pysnmp.hlapi.ContextData`
        Class instance representing SNMP ContextEngineId and ContextName values.

    notifyType : str
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
              the cost of slightly reduced performance. Default is `True`.

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
    The `sendNotification` generator will be exhausted immidiately unless
    an instance of :py:class:`~pysnmp.smi.rfc1902.NotificationType` class
    or a sequence of :py:class:`~pysnmp.smi.rfc1902.ObjectType` `varBinds`
    are send back into running generator (supported since Python 2.6).

    Examples
    --------
    >>> import asyncio
    >>> from pysnmp.hlapi.asyncio import *
    >>>
    >>> @asyncio.coroutine
    ... def run():
    ...     errorIndication, errorStatus, errorIndex, varBinds = yield from sendNotification(
    ...         SnmpEngine(),
    ...         CommunityData('public'),
    ...         UdpTransportTarget(('demo.snmplabs.com', 162)),
    ...         ContextData(),
    ...         'trap',
    ...         NotificationType(ObjectIdentity('IF-MIB', 'linkDown')))
    ...     print(errorIndication, errorStatus, errorIndex, varBinds)
    ...
    >>> asyncio.get_event_loop().run_until_complete(run())
    (None, 0, 0, [])
    >>>

    """

    def __cbFun(snmpEngine, sendRequestHandle,
                errorIndication, errorStatus, errorIndex,
                varBinds, cbCtx):
        lookupMib, future = cbCtx
        if future.cancelled():
            return
        try:
            varBindsUnmade = vbProcessor.unmakeVarBinds(snmpEngine.cache, varBinds,
                                                        lookupMib)
        except Exception as e:
            future.set_exception(e)
        else:
            future.set_result(
                    (errorIndication, errorStatus, errorIndex, varBindsUnmade)
            )

    notifyName = lcd.configure(
        snmpEngine, authData, transportTarget, notifyType
    )

    future = asyncio.Future()

    ntforg.NotificationOriginator().sendVarBinds(
        snmpEngine,
        notifyName,
        contextData.contextEngineId,
        contextData.contextName,
        vbProcessor.makeVarBinds(snmpEngine.cache, varBinds),
        __cbFun,
        (options.get('lookupMib', True), future)
    )

    if notifyType == 'trap':
        def __trapFun(future):
            if future.cancelled():
                return
            future.set_result((None, 0, 0, []))

        loop = asyncio.get_event_loop()
        loop.call_soon(__trapFun, future)

    return future
