from sys import version_info
from pysnmp.entity import config
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.smi.rfc1902 import *
from pysnmp.hlapi.auth import *
from pysnmp.hlapi.context import *
from pysnmp.hlapi.lcd import *
from pysnmp.hlapi.varbinds import *
from pysnmp.hlapi.asyncore.transport import *
from pysnmp.proto import rfc1905, errind
from pyasn1.type import univ, base

__all__ = ['AsyncCommandGenerator']

class AsyncCommandGenerator:
    """Creates asyncore-based SNMP Command Generator object.

    This is a high-level wrapper around pure Command Generator
    impementation that aims at simplyfing 
    :py:class:`pysnmp.entity.engine.SnmpEngine`'s Local Configuration
    Datastore (:RFC:`2271#section-3.4.2`) management. Typically,
    users instantiate `AsyncCommandGenerator` and call its 
    commmand-specific methods passing them canned Security,
    Transport and SNMP Context parameters along with
    :py:class:`~pysnmp.smi.rfc1902.ObjectType` object carrying
    MIB variables to include with SNMP request. `AsyncCommandGenerator`
    will manage LCD by applying user-supplied configuratoin parameters
    and running requested operation.

    See :RFC:`3413#section-3.1` for more information on SNMP
    Command Generator purpose, design and supported operations.

    """
    vbProcessor = CommandGeneratorVarBinds()
    lcd = CommandGeneratorLcdConfigurator()

    def getCmd(self, snmpEngine, authData, transportTarget, contextData, 
               varBinds, cbInfo, lookupMib=True):
        """Performs SNMP GET query.

        Based on passed parameters, prepares SNMP GET packet 
        (:RFC:`1905#section-4.2.1`) and schedules its transmission by
        I/O framework at a later point of time.

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

        varBinds : tuple
            A sequence of :py:class:`~pysnmp.smi.rfc1902.ObjectType` class
            instances representing MIB variables to place into SNMP request.
   
        cbInfo : tuple

            * `cbFun` - user-supplied callable that is invoked to pass
              SNMP response data or error to user at a later point of time.
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
          for matching multiple ongoing requests with received responses.
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
            responses with ongoing requests.

        Raises
        ------
        PySnmpError
            Or its derivative indicating that an error occurred while
            performing SNMP operation.

        Examples
        --------
        >>> from pysnmp.entity.rfc3413.oneliner.cmdgen import *
        >>> def cbFun(snmpEngine, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
        ...     print(errorIndication, errorStatus, errorIndex, varBinds)
        >>>
        >>> snmpEngine = SnmpEngine()
        >>> g = AsyncCommandGenerator()
        >>> g.getCmd(snmpEngine,
        ...          CommunityData('public'),
        ...          UdpTransportTarget(('demo.snmplabs.com', 161)),
        ...          ContextData(),
        ...          ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
        ...          (cbFun, None))
        >>> snmpEngine.transportDispatcher.runDispatcher()
        (None, 0, 0, [ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.1.0')), DisplayString('SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m'))])
        >>>

        """
        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBinds, cbCtx):
            lookupMib, cbFun, cbCtx = cbCtx
            return cbFun(
                snmpEngine,
                sendRequestHandle,
                errorIndication,
                errorStatus,
                errorIndex,
                self.vbProcessor.unmakeVarBinds(
                    snmpEngine, varBinds, lookupMib
                ),
                cbCtx
            )
        
        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.lcd.configure(
            snmpEngine, authData, transportTarget
        )

        return cmdgen.GetCommandGenerator().sendVarBinds(
            snmpEngine,
            addrName,
            contextData.contextEngineId,
            contextData.contextName,
            self.vbProcessor.makeVarBinds(snmpEngine, varBinds),
            __cbFun,
            (lookupMib, cbFun, cbCtx)
        )
    
    def setCmd(self, snmpEngine, authData, transportTarget, contextData,
               varBinds, cbInfo, lookupMib=True):
        """Performs SNMP SET query.

        Based on passed parameters, prepares SNMP SET packet 
        (:RFC:`1905#section-4.2.5`) and schedules its transmission by
        I/O framework at a later point of time.

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

        varBinds : tuple
            A sequence of :py:class:`~pysnmp.smi.rfc1902.ObjectType` class
            instances representing MIB variables to place into SNMP request.
   
        cbInfo : tuple

            * `cbFun` - user-supplied callable that is invoked to pass
              SNMP response data or error to user at a later point of time.
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
          for matching multiple ongoing requests with received responses.
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
            responses with ongoing requests.

        Raises
        ------
        PySnmpError
            Or its derivative indicating that an error occurred while
            performing SNMP operation.

        Examples
        --------
        >>> from pysnmp.entity.rfc3413.oneliner.cmdgen import *
        >>> def cbFun(snmpEngine, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
        ...     print(errorIndication, errorStatus, errorIndex, varBinds)
        >>>
        >>> snmpEngine = SnmpEngine()
        >>> g = AsyncCommandGenerator()
        >>> g.setCmd(snmpEngine,
        ...          CommunityData('public'),
        ...          UdpTransportTarget(('demo.snmplabs.com', 161)),
        ...          ContextData(),
        ...          ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysContact', 0), 'info@snmplabs.com'),
        ...          (cbFun, None))
        >>> snmpEngine.transportDispatcher.runDispatcher()
        (None, 0, 0, [ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.4.0')), DisplayString('info@snmplabs.com'))])
        >>>

        """
        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBinds, cbCtx):
            lookupMib, cbFun, cbCtx = cbCtx
            return cbFun(
                snmpEngine,
                sendRequestHandle,
                errorIndication,
                errorStatus,
                errorIndex,
                self.vbProcessor.unmakeVarBinds(
                    snmpEngine, varBinds, lookupMib
                ),
                cbCtx
            )

        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.lcd.configure(
            snmpEngine, authData, transportTarget
        )

        return cmdgen.SetCommandGenerator().sendVarBinds(
            snmpEngine,
            addrName,
            contextData.contextEngineId,
            contextData.contextName,
            self.vbProcessor.makeVarBinds(snmpEngine, varBinds),
            __cbFun,
            (lookupMib, cbFun, cbCtx)
        )
    
    def nextCmd(self, snmpEngine, authData, transportTarget, contextData,
                varBinds, cbInfo, lookupMib=True):
        """Performs SNMP GETNEXT query.

        Based on passed parameters, prepares SNMP GETNEXT packet 
        (:RFC:`1905#section-4.2.2`) and schedules its transmission by
        I/O framework at a later point of time.

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

        varBinds : tuple
            A sequence of :py:class:`~pysnmp.smi.rfc1902.ObjectType` class
            instances representing MIB variables to place into SNMP request.
   
        cbInfo : tuple

            * `cbFun` - user-supplied callable that is invoked to pass
              SNMP response data or error to user at a later point of time.
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
          for matching multiple ongoing requests with received responses.
        * errorIndication (str): True value indicates SNMP engine error.
        * errorStatus (str): True value indicates SNMP PDU error.
        * errorIndex (int): Non-zero value refers to `varBinds[errorIndex-1]`
        * varBinds (tuple): A sequence of sequences (e.g. 2-D array) of
          :py:class:`~pysnmp.smi.rfc1902.ObjectType` class instances
          representing a table of MIB variables returned in SNMP response.
          Inner sequences represent table rows and ordered exactly the same
          as `varBinds` in request. Response to GETNEXT always contain a
          single row.
        * `cbCtx` : Original user-supplied object.

        Returns
        -------
        sendRequestHandle : int
            Unique request identifier. Can be used for matching received
            responses with ongoing requests.

        Raises
        ------
        PySnmpError
            Or its derivative indicating that an error occurred while
            performing SNMP operation.

        Examples
        --------
        >>> from pysnmp.entity.rfc3413.oneliner.cmdgen import *
        >>> def cbFun(snmpEngine, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
        ...     print(errorIndication, errorStatus, errorIndex, varBinds)
        >>>
        >>> snmpEngine = SnmpEngine()
        >>> g = AsyncCommandGenerator()
        >>> g.nextCmd(snmpEngine,
        ...           CommunityData('public'),
        ...           UdpTransportTarget(('demo.snmplabs.com', 161)),
        ...           ContextData(),
        ...           ObjectType(ObjectIdentity('SNMPv2-MIB', 'system')),
        ...           (cbFun, None))
        >>> snmpEngine.transportDispatcher.runDispatcher()
        (None, 0, 0, [ [ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.1.0')), DisplayString('SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m'))] ])
        >>>

        """
        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            lookupMib, cbFun, cbCtx = cbCtx
            return cbFun(
                snmpEngine,
                sendRequestHandle,
                errorIndication,
                errorStatus,
                errorIndex,
                [ self.vbProcessor.unmakeVarBinds(snmpEngine, varBindTableRow, lookupMib) for varBindTableRow in varBindTable ],
                cbCtx
            )

        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.lcd.configure(
            snmpEngine, authData, transportTarget
        )
        return cmdgen.NextCommandGenerator().sendVarBinds(
            snmpEngine,
            addrName,
            contextData.contextEngineId, contextData.contextName,
            self.vbProcessor.makeVarBinds(snmpEngine, varBinds),
            __cbFun,
            (lookupMib, cbFun, cbCtx)
        )

    def bulkCmd(self, snmpEngine, authData, transportTarget, contextData,
                nonRepeaters, maxRepetitions, varBinds, cbInfo,
                lookupMib=True):
        """Performs SNMP GETBULK query.

        Based on passed parameters, prepares SNMP GETBULK packet 
        (:RFC:`1905#section-4.2.3`) and schedules its transmission by
        I/O framework at a later point of time.

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

        nonRepeaters : int
            One MIB variable is requested in response for the first 
            `nonRepeaters` MIB variables in request.

        maxRepetitions : int
            `maxRepetitions` MIB variables are requested in response for each
            of the remaining MIB variables in the request (e.g. excluding
            `nonRepeaters`). Remote SNMP engine may choose lesser value than
            requested.

        varBinds : tuple
            A sequence of :py:class:`~pysnmp.smi.rfc1902.ObjectType` class
            instances representing MIB variables to place into SNMP request.
   
        cbInfo : tuple

            * `cbFun` - user-supplied callable that is invoked to pass
              SNMP response data or error to user at a later point of time.
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
          for matching multiple ongoing requests with received responses.
        * errorIndication (str): True value indicates SNMP engine error.
        * errorStatus (str): True value indicates SNMP PDU error.
        * errorIndex (int): Non-zero value refers to `varBinds[errorIndex-1]`
        * varBinds (tuple): A sequence of sequences (e.g. 2-D array) of
          :py:class:`~pysnmp.smi.rfc1902.ObjectType` class instances
          representing a table of MIB variables returned in SNMP response.
          Inner sequences represent table rows and ordered exactly the same
          as `varBinds` in request. Number of rows might be less or equal
          to `maxRepetitions` value in request.
        * `cbCtx` : Original user-supplied object.

        Returns
        -------
        sendRequestHandle : int
            Unique request identifier. Can be used for matching received
            responses with ongoing requests.

        Raises
        ------
        PySnmpError
            Or its derivative indicating that an error occurred while
            performing SNMP operation.

        Examples
        --------
        >>> from pysnmp.entity.rfc3413.oneliner.cmdgen import *
        >>> def cbFun(snmpEngine, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
        ...     print(errorIndication, errorStatus, errorIndex, varBinds)
        >>>
        >>> snmpEngine = SnmpEngine()
        >>> g = AsyncCommandGenerator()
        >>> g.bulkCmd(snmpEngine,
        ...           CommunityData('public'),
        ...           UdpTransportTarget(('demo.snmplabs.com', 161)),
        ...           ContextData(),
        ...           0, 2,
        ...           ObjectType(ObjectIdentity('SNMPv2-MIB', 'system')),
        ...           (cbFun, None))
        >>> snmpEngine.transportDispatcher.runDispatcher()
        (None, 0, 0, [ [ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.1.0')), DisplayString('SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m')), ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.1.2.0')), ObjectIdentifier('1.3.6.1.4.1.424242.1.1')] ])
        >>>

        """
        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            lookupMib, cbFun, cbCtx = cbCtx
            return cbFun(
                snmpEngine,
                sendRequestHandle,
                errorIndication,
                errorStatus,
                errorIndex,
                [ self.vbProcessor.unmakeVarBinds(snmpEngine, varBindTableRow, lookupMib) for varBindTableRow in varBindTable ],
                cbCtx
            )

        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.lcd.configure(
            snmpEngine, authData, transportTarget
        )
        return cmdgen.BulkCommandGenerator().sendVarBinds(
            snmpEngine,
            addrName,
            contextData.contextEngineId,
            contextData.contextName,
            nonRepeaters, maxRepetitions,
            self.vbProcessor.makeVarBinds(snmpEngine, varBinds),
            __cbFun,
            (lookupMib, cbFun, cbCtx)
        )
