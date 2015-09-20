from pysnmp.entity import engine, config
from pysnmp.smi.rfc1902 import *
from pysnmp.entity.rfc3413 import ntforg, context
from pysnmp.hlapi.auth import *
from pysnmp.hlapi.context import *
from pysnmp.hlapi.lcd import *
from pysnmp.hlapi.varbinds import *
from pysnmp.hlapi.asyncore.transport import *
from pysnmp.hlapi.asyncore import cmdgen
from pysnmp import error

__all__ = ['AsyncNotificationOriginator']

class AsyncNotificationOriginator:
    """Creates asyncore-based SNMP Notification Originator object.

    This is a high-level wrapper around pure Notification Originator
    impementation that aims at simplyfing 
    :py:class:`pysnmp.entity.engine.SnmpEngine`'s Local Configuration
    Datastore (:RFC:`2271#section-3.4.2`) management. Typically,
    users instantiate `AsyncNotificationOriginator` and call its 
    commmand-specific methods passing them canned Security,
    Transport and SNMP Context parameters along with
    :py:class:`~pysnmp.smi.rfc1902.NotificationType` object carrying
    MIB variables to include with Notification. `AsyncNotificationOriginator`
    will manage LCD by applying user-supplied configuratoin parameters
    and running requested operation.

    See :RFC:`3413#section-3.2` for more information on SNMP
    Notification Originator purpose, design and supported operations.

    """
    vbProcessor = NotificationOriginatorVarBinds()
    lcd = NotificationOriginatorLcdConfigurator()

    def sendNotification(self, snmpEngine,
                         authData, transportTarget, contextData,
                         notifyType,
                         varBinds,
                         cbInfo=(None, None), 
                         lookupMib=False):
        """Send SNMP notification.

        Based on passed parameters, prepares SNMP TRAP or INFORM
        notification (:RFC:`1905#section-4.2.6`) and schedules its
        transmission by I/O framework at a later point of time.

        Parameters
        ----------
        snmpEngine : :py:class:`~pysnmp.entity.engine.SnmpEngine`
            Class instance representing SNMP engine.

        authData : :py:class:`~pysnmp.entity.rfc3413.oneliner.auth.CommunityData` or :py:class:`~pysnmp.entity.rfc3413.oneliner.auth.UsmUserData`
            Class instance representing SNMP credentials.

        transportTarget : :py:class:`~pysnmp.entity.rfc3413.oneliner.target.UdpTransportTarget` or :py:class:`~pysnmp.entity.rfc3413.oneliner.target.Udp6TransportTarget`
            Class instance representing transport type along with SNMP peer
            address.

        contextData : :py:class:`~pysnmp.entity.rfc3413.oneliner.ctx.ContextData`
            Class instance representing SNMP ContextEngineId and ContextName
            values.

        notifyType : str
            Indicates type of notification to be sent. Recognized literal
            values are *trap* or *inform*.

        varBinds: tuple
            Single :py:class:`~pysnmp.smi.rfc1902.NotificationType` class
            instance representing a minimum sequence of MIB variables
            required for particular notification type. Alternatively,
            a sequence of :py:class:`~pysnmp.smi.rfc1902.ObjectType`
            objects could be passed instead. In the latter case it is up to
            the user to ensure proper Notification PDU contents.
    
        cbInfo : tuple

            * `cbFun` - user-supplied callable that is invoked to pass
              SNMP response to *INFORM* notification or error to user at
              a later point of time. The `cbFun` callable is never invoked
              for *TRAP* notifications.
            * `cbCtx` - user-supplied object passing additional parameters
              to/from `cbFun`. Default is `None`.
         
        Other Parameters
        ----------------
        lookupMib : bool
            `lookupMib` - load MIB and resolve response MIB variables at
            the cost of slightly reduced performance. Default is `True`.

        Notes
        -----
        User-supplied `cbFun` callable must have the following call
        signature:

        * snmpEngine (:py:class:`~pysnmp.entity.engine.SnmpEngine`): 
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
        >>> from pysnmp.entity.rfc3413.oneliner.ntforg import *
        >>>
        >>> snmpEngine = SnmpEngine()
        >>> n = AsyncNotificationOriginator()
        >>> n.sendNotification(
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
        def __cbFun(snmpEngine, sendRequestHandle, errorIndication,
                    errorStatus, errorIndex, varBinds, cbCtx):
            lookupMib, cbFun, cbCtx = cbCtx
            return cbFun and cbFun(
                snmpEngine,
                sendRequestHandle,
                errorIndication,
                errorStatus, errorIndex,
                self.vbProcessor.unmakeVarBinds(
                    snmpEngine, varBinds, lookupMib
                ),
                cbCtx
            )

        cbFun, cbCtx = cbInfo

        # Create matching transport tags if not given by user
        if not transportTarget.tagList:
            transportTarget.tagList = str(
                hash((authData.securityName, transportTarget.transportAddr))
            )
        if isinstance(authData, CommunityData) and not authData.tag:
            authData.tag = transportTarget.tagList.split()[0]

        notifyName = self.lcd.configure(
            snmpEngine, authData, transportTarget, notifyType
        )

        return ntforg.NotificationOriginator().sendVarBinds(snmpEngine, notifyName, contextData.contextEngineId, contextData.contextName, self.vbProcessor.makeVarBinds(snmpEngine, varBinds), __cbFun, (lookupMib, cbFun, cbCtx))
