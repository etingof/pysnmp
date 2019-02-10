#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.hlapi.v1arch.asyncore import ntforg
from pysnmp.hlapi.varbinds import *
from pysnmp.proto import errind
from pyasn1.type.univ import Null

__all__ = ['sendNotification']


def sendNotification(snmpDispatcher, authData, transportTarget,
                     notifyType, *varBinds, **options):
    """Creates a generator to send one or more SNMP notifications.

    On each iteration, new SNMP TRAP or INFORM notification is send
    (:RFC:`1905#section-4,2,6`). The iterator blocks waiting for
    INFORM acknowledgement to arrive or error to occur.

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
    The `sendNotification` generator will be exhausted immediately unless
    an instance of :py:class:`~pysnmp.smi.rfc1902.NotificationType` class
    or a sequence of :py:class:`~pysnmp.smi.rfc1902.ObjectType` `varBinds`
    are send back into running generator (supported since Python 2.6).

    Examples
    --------
    >>> from pysnmp.hlapi.v1arch import *
    >>>
    >>> g = sendNotification(SnmpDispatcher(),
    >>>                      CommunityData('public'),
    >>>                      UdpTransportTarget(('demo.snmplabs.com', 162)),
    >>>                      'trap',
    >>>                      NotificationType(ObjectIdentity('IF-MIB', 'linkDown')))
    >>> next(g)
    (None, 0, 0, [])
    """

    def cbFun(*args, **kwargs):
        response[:] = args

    options['cbFun'] = cbFun

    errorIndication, errorStatus, errorIndex = None, 0, 0

    response = [None, 0, 0, []]

    while True:
        if varBinds:
            ntforg.sendNotification(snmpDispatcher, authData, transportTarget,
                                    notifyType, *varBinds, **options)

            snmpDispatcher.transportDispatcher.runDispatcher()

            errorIndication, errorStatus, errorIndex, varBinds = response

        varBinds = (yield errorIndication, errorStatus, errorIndex, varBinds)

        if not varBinds:
            break
