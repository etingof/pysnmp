from sys import version_info
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.smi.rfc1902 import *
from pysnmp.entity.rfc3413.oneliner.auth import *
from pysnmp.entity.rfc3413.oneliner.target import *
from pysnmp.entity.rfc3413.oneliner.ctx import *
from pysnmp.proto import rfc1905, errind
from pysnmp.smi import view
from pysnmp import nextid, error
from pyasn1.type import univ, base
from pyasn1.compat.octets import null

# obsolete, compatibility symbols
from pysnmp.entity.rfc3413.oneliner.mibvar import MibVariable

# SNMP engine
SnmpEngine = engine.SnmpEngine

nextID = nextid.Integer(0xffffffff)

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
    _null = univ.Null('')

    def _getCache(self, snmpEngine):
        cache = snmpEngine.getUserContext('cmdgen_cache')
        if cache is None:
            cache = {
                'auth': {}, 'parm': {}, 'tran': {}, 'addr': {}
            }
            snmpEngine.setUserContext(cmdgen_cache=cache)
        return cache

    def getMibViewController(self, snmpEngine):
        mibViewController = snmpEngine.getUserContext('mibViewController')
        if not mibViewController:
            mibViewController = view.MibViewController(
                snmpEngine.getMibBuilder()
            )
            snmpEngine.setUserContext(mibViewController=mibViewController)
        return mibViewController
        
    def cfgCmdGen(self, snmpEngine, authData, transportTarget):
        cache = self._getCache(snmpEngine)
        if isinstance(authData, CommunityData):
            if authData.communityIndex not in cache['auth']:
                config.addV1System(
                    snmpEngine,
                    authData.communityIndex,
                    authData.communityName,
                    authData.contextEngineId,
                    authData.contextName,
                    authData.tag,
                    authData.securityName
                )
                cache['auth'][authData.communityIndex] = authData
        elif isinstance(authData, UsmUserData):
            authDataKey = authData.userName, authData.securityEngineId
            if authDataKey not in cache['auth']:
                config.addV3User(
                    snmpEngine,
                    authData.userName,
                    authData.authProtocol, authData.authKey,
                    authData.privProtocol, authData.privKey,
                    authData.securityEngineId,
                    securityName=authData.securityName
                )
                cache['auth'][authDataKey] = authData
        else:
            raise error.PySnmpError('Unsupported authentication object')

        paramsKey = authData.securityName, \
                    authData.securityLevel, \
                    authData.mpModel
        if paramsKey in cache['parm']:
            paramsName, useCount = cache['parm'][paramsKey]
            cache['parm'][paramsKey] = paramsName, useCount + 1
        else:
            paramsName = 'p%s' % nextID()
            config.addTargetParams(
                snmpEngine, paramsName,
                authData.securityName, authData.securityLevel, authData.mpModel
            )
            cache['parm'][paramsKey] = paramsName, 1

        if transportTarget.transportDomain in cache['tran']:
            transport, useCount = cache['tran'][transportTarget.transportDomain]
            transportTarget.verifyDispatcherCompatibility(snmpEngine)
            cache['tran'][transportTarget.transportDomain] = transport, useCount + 1
        elif config.getTransport(snmpEngine, transportTarget.transportDomain):
            transportTarget.verifyDispatcherCompatibility(snmpEngine)
        else:
            transport = transportTarget.openClientMode()
            config.addTransport(
                snmpEngine,
                transportTarget.transportDomain,
                transport
            )
            cache['tran'][transportTarget.transportDomain] = transport, 1

        transportKey = ( paramsName,
                         transportTarget.transportDomain,
                         transportTarget.transportAddr,
                         transportTarget.tagList )

        if transportKey in cache['addr']:
            addrName, useCount = cache['addr'][transportKey]
            cache['addr'][transportKey] = addrName, useCount + 1
        else:
            addrName = 'a%s' % nextID()
            config.addTargetAddr(
                snmpEngine, addrName,
                transportTarget.transportDomain,
                transportTarget.transportAddr,
                paramsName,
                transportTarget.timeout * 100,
                transportTarget.retries,
                transportTarget.tagList
            )
            cache['addr'][transportKey] = addrName, 1

        return addrName, paramsName

    def uncfgCmdGen(self, snmpEngine, authData=None):
        cache = self._getCache(snmpEngine)
        if authData:
            if isinstance(authData, CommunityData):
                authDataKey = authData.communityIndex
            elif isinstance(authData, UsmUserData):
                authDataKey = authData.userName, authData.securityEngineId
            else:
                raise error.PySnmpError('Unsupported authentication object')
            if authDataKey in cache['auth']:
                authDataKeys = ( authDataKey, )
            else:
                raise error.PySnmpError('Unknown authData %s' % (authData,))
        else:
            authDataKeys = list(cache['auth'].keys())

        addrNames, paramsNames = set(), set()

        for authDataKey in authDataKeys:
            authDataX = cache['auth'][authDataKey] 
            del cache['auth'][authDataKey]
            if isinstance(authDataX, CommunityData):
                config.delV1System(
                    snmpEngine,
                    authDataX.communityIndex
                )
            elif isinstance(authDataX, UsmUserData):
                config.delV3User(
                    snmpEngine,
                    authDataX.userName, 
                    authDataX.securityEngineId
                )
            else:
                raise error.PySnmpError('Unsupported authentication object')

            paramsKey = authDataX.securityName, \
                        authDataX.securityLevel, \
                        authDataX.mpModel
            if paramsKey in cache['parm']:
                paramsName, useCount = cache['parm'][paramsKey]
                useCount -= 1
                if useCount:
                    cache['parm'][paramsKey] = paramsName, useCount
                else:
                    del cache['parm'][paramsKey]
                    config.delTargetParams(
                        snmpEngine, paramsName
                    )
                    paramsNames.add(paramsName)
            else:
                raise error.PySnmpError('Unknown target %s' % (paramsKey,))

            addrKeys = [ x for x in cache['addr'] if x[0] == paramsName ]

            for addrKey in addrKeys:
                addrName, useCount = cache['addr'][addrKey]
                useCount -= 1
                if useCount:
                    cache['addr'][addrKey] = addrName, useCount
                else:
                    config.delTargetAddr(snmpEngine, addrName)

                    addrNames.add(addrKey)

                    if addrKey[1] in cache['tran']:
                        transport, useCount = cache['tran'][addrKey[1]]
                        if useCount > 1:
                            useCount -= 1
                            cache['tran'][addrKey[1]] = transport, useCount
                        else:
                            config.delTransport(snmpEngine, addrKey[1])
                            transport.closeTransport()
                            del cache['tran'][addrKey[1]]

        return addrNames, paramsNames

    def makeVarBinds(self, snmpEngine, varBinds):
        mibViewController = self.getMibViewController(snmpEngine)
        __varBinds = []
        for varBind in varBinds:
            if isinstance(varBind, ObjectType):
                pass
            elif isinstance(varBind[0], ObjectIdentity):
                varBind = ObjectType(*varBind)
            elif isinstance(varBind[0][0], tuple):  # legacy
                varBind = ObjectType(ObjectIdentity(varBind[0][0][0], varBind[0][0][1], *varBind[0][1:]), varBind[1])
            else:
                varBind = ObjectType(ObjectIdentity(varBind[0]), varBind[1])

            __varBinds.append(varBind.resolveWithMib(mibViewController))

        return __varBinds

    def unmakeVarBinds(self, snmpEngine, varBinds, lookupMib=True):
        if lookupMib:
            mibViewController = self.getMibViewController(snmpEngine)
            varBinds = [ ObjectType(ObjectIdentity(x[0]), x[1]).resolveWithMib(mibViewController) for x in varBinds ]

        return varBinds

    # Standard SNMP apps follow

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
                self.unmakeVarBinds(
                    snmpEngine, varBinds, lookupMib
                ),
                cbCtx
            )
        
        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            snmpEngine, authData, transportTarget
        )

        return cmdgen.GetCommandGenerator().sendVarBinds(
            snmpEngine,
            addrName,
            contextData.contextEngineId,
            contextData.contextName,
            self.makeVarBinds(snmpEngine, varBinds),
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
                self.unmakeVarBinds(
                    snmpEngine, varBinds, lookupMib
                ),
                cbCtx
            )

        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            snmpEngine, authData, transportTarget
        )

        return cmdgen.SetCommandGenerator().sendVarBinds(
            snmpEngine,
            addrName,
            contextData.contextEngineId,
            contextData.contextName,
            self.makeVarBinds(snmpEngine, varBinds),
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
                [ self.unmakeVarBinds(snmpEngine, varBindTableRow, lookupMib) for varBindTableRow in varBindTable ],
                cbCtx
            )

        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            snmpEngine, authData, transportTarget
        )
        return cmdgen.NextCommandGenerator().sendVarBinds(
            snmpEngine,
            addrName,
            contextData.contextEngineId, contextData.contextName,
            self.makeVarBinds(snmpEngine, varBinds),
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
                [ self.unmakeVarBinds(snmpEngine, varBindTableRow, lookupMib) for varBindTableRow in varBindTable ],
                cbCtx
            )

        (cbFun, cbCtx) = cbInfo
        addrName, paramsName = self.cfgCmdGen(
            snmpEngine, authData, transportTarget
        )
        return cmdgen.BulkCommandGenerator().sendVarBinds(
            snmpEngine,
            addrName,
            contextData.contextEngineId,
            contextData.contextName,
            nonRepeaters, maxRepetitions,
            self.makeVarBinds(snmpEngine, varBinds),
            __cbFun,
            (lookupMib, cbFun, cbCtx)
        )

#
# The rest of code in this file belongs to obsolete, compatibility wrappers.
# Never use interfaces below for new applications!
#

class AsynCommandGenerator:
    def __init__(self, snmpEngine=None):
        if snmpEngine is None:
            self.snmpEngine = snmpEngine = engine.SnmpEngine()
        else:
            self.snmpEngine = snmpEngine

        self.__asyncCmdGen = AsyncCommandGenerator()
        self.mibViewController = self.__asyncCmdGen.getMibViewController(self.snmpEngine)

    def __del__(self):
        self.__asyncCmdGen.uncfgCmdGen(self.snmpEngine)

    def cfgCmdGen(self, authData, transportTarget):
        return self.__asyncCmdGen.cfgCmdGen(
            self.snmpEngine, authData, transportTarget
        )

    def uncfgCmdGen(self, authData=None):
        return self.__asyncCmdGen.uncfgCmdGen(
            self.snmpEngine, authData
        )

    # compatibility stub
    def makeReadVarBinds(self, varNames):
        return self.makeVarBinds(
            [ (x, univ.Null('')) for x in varNames ]
        )

    def makeVarBinds(self, varBinds):
        return self.__asyncCmdGen.makeVarBinds(
            self.snmpEngine, varBinds
        )

    def unmakeVarBinds(self, varBinds, lookupNames, lookupValues):
        return self.__asyncCmdGen.unmakeVarBinds(
            self.snmpEngine, varBinds, lookupNames or lookupValues
        )

    def getCmd(self, authData, transportTarget, varNames, cbInfo,
               lookupNames=False, lookupValues=False,
               contextEngineId=None, contextName=null):

        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            cbFun, cbCtx = cbCtx
            cbFun(sendRequestHandle,
                  errorIndication, errorStatus, errorIndex,
                  varBindTable, cbCtx)

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName

        cbInfo = __cbFun, cbInfo

        return self.__asyncCmdGen.getCmd(
            self.snmpEngine, 
            authData, transportTarget,
            ContextData(contextEngineId, contextName),
            [(x, self._null) for x in varNames],
            cbInfo,
            lookupNames or lookupValues
        )

    asyncGetCmd = getCmd

    def setCmd(self, authData, transportTarget, varBinds, cbInfo,
               lookupNames=False, lookupValues=False,
               contextEngineId=None, contextName=null):

        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            cbFun, cbCtx = cbCtx
            cbFun(sendRequestHandle,
                  errorIndication, errorStatus, errorIndex,
                  varBindTable, cbCtx)

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName

        cbInfo = __cbFun, cbInfo
        
        return self.__asyncCmdGen.setCmd(
            self.snmpEngine,
            authData, transportTarget,
            ContextData(contextEngineId, contextName), varBinds, cbInfo,
            lookupNames or lookupValues
        )

    asyncSetCmd = setCmd

    def nextCmd(self, authData, transportTarget, varNames, cbInfo,
                lookupNames=False, lookupValues=False,
                contextEngineId=None, contextName=null):

        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            cbFun, cbCtx = cbCtx
            return cbFun(sendRequestHandle,
                         errorIndication, errorStatus, errorIndex,
                         varBindTable, cbCtx)

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName

        cbInfo = __cbFun, cbInfo

        return self.__asyncCmdGen.nextCmd(
            self.snmpEngine,
            authData, transportTarget,
            ContextData(contextEngineId, contextName),
            [(x, self._null) for x in varNames],
            cbInfo,
            lookupNames or lookupValues
        )

    asyncNextCmd = nextCmd

    def bulkCmd(self, authData, transportTarget,
                nonRepeaters, maxRepetitions, varNames, cbInfo,
                lookupNames=False, lookupValues=False,
                contextEngineId=None, contextName=null):

        def __cbFun(snmpEngine, sendRequestHandle,
                    errorIndication, errorStatus, errorIndex,
                    varBindTable, cbCtx):
            cbFun, cbCtx = cbCtx
            return cbFun(sendRequestHandle,
                         errorIndication, errorStatus, errorIndex,
                         varBindTable, cbCtx)

        # for backward compatibility
        if contextName is null and authData.contextName:
            contextName = authData.contextName

        cbInfo = __cbFun, cbInfo

        return self.__asyncCmdGen.bulkCmd(
            self.snmpEngine, 
            authData, transportTarget,
            ContextData(contextEngineId, contextName),
            nonRepeaters, maxRepetitions,
            [(x, self._null) for x in varNames],
            cbInfo,
            lookupNames or lookupValues
        )

    asyncBulkCmd = bulkCmd

class CommandGenerator:
    def __init__(self, snmpEngine=None, asynCmdGen=None):
        # compatibility attributes
        self.snmpEngine = snmpEngine or SnmpEngine()
        self.mibViewController = AsyncCommandGenerator().getMibViewController(self.snmpEngine)

    def getCmd(self, authData, transportTarget, *varNames, **kwargs):
        for x in getCmd(self.snmpEngine, authData, transportTarget,
                        ContextData(kwargs.get('contextEngineId'),
                                    kwargs.get('contextName', null)),
                        *[ (x, univ.Null()) for x in varNames ],
                        **kwargs):
            return x

    def setCmd(self, authData, transportTarget, *varBinds, **kwargs):
        for x in setCmd(self.snmpEngine, authData, transportTarget,
                        ContextData(kwargs.get('contextEngineId'),
                                    kwargs.get('contextName', null)),
                        *varBinds,
                        **kwargs):
            return x

    def nextCmd(self, authData, transportTarget, *varNames, **kwargs):
        varBindTable = []
        for errorIndication, \
            errorStatus, errorIndex, \
            varBinds in nextCmd(self.snmpEngine, authData, transportTarget,
                                ContextData(kwargs.get('contextEngineId'),
                                            kwargs.get('contextName', null)),
                                *[ (x, univ.Null()) for x in varNames ],
                                **kwargs):
            if errorIndication or errorStatus:
                return errorIndication, errorStatus, errorIndex, varBinds

            varBindTable.append(varBinds)

        return errorIndication, errorStatus, errorIndex, varBindTable

    def bulkCmd(self, authData, transportTarget,
                nonRepeaters, maxRepetitions, *varNames, **kwargs):
        varBindTable = []
        for errorIndication, \
            errorStatus, errorIndex, \
            varBinds in bulkCmd(self.snmpEngine, authData, transportTarget,
                                ContextData(kwargs.get('contextEngineId'),
                                            kwargs.get('contextName', null)),
                                nonRepeaters, maxRepetitions,
                                *[ (x, univ.Null()) for x in varNames ],
                                **kwargs):
            if errorIndication or errorStatus:
                return errorIndication, errorStatus, errorIndex, varBinds

            varBindTable.append(varBinds)

        return errorIndication, errorStatus, errorIndex, varBindTable

# circular module import dependency
if version_info[:2] < (2, 6):
    from pysnmp.entity.rfc3413.oneliner.sync.compat.cmdgen import *
else:
    from pysnmp.entity.rfc3413.oneliner.sync.cmdgen import *
