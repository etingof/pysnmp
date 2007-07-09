# SNMP v3 USM model services
from pysnmp.proto.secmod.base import AbstractSecurityModel
from pysnmp.proto.secmod.rfc3414.auth import hmacmd5, hmacsha, noauth
from pysnmp.proto.secmod.rfc3414.priv import des, nopriv
from pysnmp.proto.secmod.rfc3826.priv import aes
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.smi.error import NoSuchInstanceError
from pysnmp.proto import rfc1155, error
from pyasn1.type import univ, namedtype, constraint
from pyasn1.codec.ber import encoder, decoder
from pyasn1.error import PyAsn1Error
from pysnmp import debug
import time
    
# USM security params

class UsmSecurityParameters(rfc1155.TypeCoercionHackMixIn, univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('msgAuthoritativeEngineID', univ.OctetString()),
        namedtype.NamedType('msgAuthoritativeEngineBoots', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 2147483647L))),
        namedtype.NamedType('msgAuthoritativeEngineTime', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 2147483647L))),
        namedtype.NamedType('msgUserName', univ.OctetString().subtype(subtypeSpec=constraint.ValueSizeConstraint(0, 32))),
        namedtype.NamedType('msgAuthenticationParameters', univ.OctetString()),
        namedtype.NamedType('msgPrivacyParameters', univ.OctetString())
        )

class SnmpUSMSecurityModel(AbstractSecurityModel):
    securityModelID = 3
    authServices = {
        hmacmd5.HmacMd5.serviceID: hmacmd5.HmacMd5(),
        hmacsha.HmacSha.serviceID: hmacsha.HmacSha(),
        noauth.NoAuth.serviceID: noauth.NoAuth()
        
        }
    privServices = {
        des.Des.serviceID: des.Des(),
        aes.Aes.serviceID: aes.Aes(),
        nopriv.NoPriv.serviceID: nopriv.NoPriv()
        }
    _securityParametersSpec = UsmSecurityParameters()
    def __init__(self):
        AbstractSecurityModel.__init__(self)
        self.__timeline = {}
        self.__timelineExpQueue = {}
        self.__expirationTimer = 0L

    def __getUserInfo(
        self, mibInstrumController, securityEngineID, securityName
        ):
        usmUserEntry, = mibInstrumController.mibBuilder.importSymbols(
            'SNMP-USER-BASED-SM-MIB', 'usmUserEntry'
            )
        tblIdx = usmUserEntry.getInstIdFromIndices(
            securityEngineID, securityName
            )
        # Get protocols
        usmUserSecurityName = usmUserEntry.getNode(
            usmUserEntry.name + (3,) + tblIdx
            ).syntax
        usmUserAuthProtocol = usmUserEntry.getNode(
            usmUserEntry.name + (5,) + tblIdx
            ).syntax
        usmUserPrivProtocol = usmUserEntry.getNode(
            usmUserEntry.name + (8,) + tblIdx
            ).syntax
        # Get keys
        pysnmpUsmKeyEntry, = mibInstrumController.mibBuilder.importSymbols(
            'PYSNMP-USM-MIB', 'pysnmpUsmKeyEntry'
            )
        pysnmpUsmKeyAuthLocalized = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (1,) + tblIdx
            ).syntax
        pysnmpUsmKeyPrivLocalized = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (2,) + tblIdx
            ).syntax
        return (
            usmUserSecurityName,  # XXX function needed?
            usmUserAuthProtocol,
            pysnmpUsmKeyAuthLocalized,
            usmUserPrivProtocol,
            pysnmpUsmKeyPrivLocalized
            )

    def __cloneUserInfo(
        self, mibInstrumController, securityEngineID, securityName
        ):
        snmpEngineID, = mibInstrumController.mibBuilder.importSymbols(
            '__SNMP-FRAMEWORK-MIB', 'snmpEngineID'
            )
        # Proto entry
        usmUserEntry, = mibInstrumController.mibBuilder.importSymbols(
            'SNMP-USER-BASED-SM-MIB', 'usmUserEntry'
            )
        tblIdx = usmUserEntry.getInstIdFromIndices(
            snmpEngineID.syntax, securityName
            )
        # Get proto protocols
        usmUserSecurityName = usmUserEntry.getNode(
            usmUserEntry.name + (3,) + tblIdx
            )
        usmUserAuthProtocol = usmUserEntry.getNode(
            usmUserEntry.name + (5,) + tblIdx
            )
        usmUserPrivProtocol = usmUserEntry.getNode(
            usmUserEntry.name + (8,) + tblIdx
            )
        # Get proto keys
        pysnmpUsmKeyEntry, = mibInstrumController.mibBuilder.importSymbols(
            'PYSNMP-USM-MIB', 'pysnmpUsmKeyEntry'
            )
        pysnmpUsmKeyAuth = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (3,) + tblIdx
            )
        pysnmpUsmKeyPriv = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (4,) + tblIdx
            )        
        
        # Create new row from proto values
        
        tblIdx = usmUserEntry.getInstIdFromIndices(
            securityEngineID, securityName
            )
        # New row
        mibInstrumController.writeVars(
            ((usmUserEntry.name + (13,) + tblIdx, 4),)
            )
        # Set protocols
        usmUserEntry.getNode(
            usmUserEntry.name + (3,) + tblIdx
            ).syntax = usmUserSecurityName.syntax
        usmUserEntry.getNode(
            usmUserEntry.name + (5,) + tblIdx
            ).syntax = usmUserAuthProtocol.syntax
        usmUserEntry.getNode(
            usmUserEntry.name + (8,) + tblIdx
            ).syntax = usmUserPrivProtocol.syntax
        
        # Localize and set keys
        pysnmpUsmKeyEntry, = mibInstrumController.mibBuilder.importSymbols(
            'PYSNMP-USM-MIB', 'pysnmpUsmKeyEntry'
            )
        pysnmpUsmKeyAuthLocalized = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (1,) + tblIdx
            )
        if usmUserAuthProtocol.syntax == hmacsha.HmacSha.serviceID:
            localAuthKey = localkey.localizeKeySHA(
                pysnmpUsmKeyAuth.syntax, securityEngineID
                )
        elif usmUserAuthProtocol.syntax == hmacmd5.HmacMd5.serviceID:
            localAuthKey = localkey.localizeKeyMD5(
                pysnmpUsmKeyAuth.syntax, securityEngineID
                )
        elif usmUserAuthProtocol.syntax == noauth.NoAuth.serviceID:
            localAuthKey = None
        else:
            raise error.StatusInformation(
                errorIndication = 'unsupportedAuthProtocol'
                )
        if localAuthKey is not None:
            pysnmpUsmKeyAuthLocalized.syntax = pysnmpUsmKeyAuthLocalized.syntax.clone(localAuthKey)
        pysnmpUsmKeyPrivLocalized = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (2,) + tblIdx
            )
        if usmUserPrivProtocol.syntax == des.Des.serviceID or \
           usmUserPrivProtocol.syntax == aes.Aes.serviceID:
            if usmUserAuthProtocol.syntax == hmacsha.HmacSha.serviceID:
                localPrivKey = localkey.localizeKeySHA(
                    pysnmpUsmKeyPriv.syntax, securityEngineID
                    )
            else:
                localPrivKey = localkey.localizeKeyMD5(
                    pysnmpUsmKeyPriv.syntax, securityEngineID
                    )
        elif usmUserPrivProtocol.syntax == nopriv.NoPriv.serviceID:
            localPrivKey = None
        else:
            raise error.StatusInformation(
                errorIndication = 'unsupportedPrivProtocol'
                )
        if localPrivKey is not None:
            pysnmpUsmKeyPrivLocalized.syntax = pysnmpUsmKeyPrivLocalized.syntax.clone(localPrivKey)
        return (
            usmUserSecurityName.syntax,  # XXX function needed?
            usmUserAuthProtocol.syntax,
            pysnmpUsmKeyAuthLocalized.syntax,
            usmUserPrivProtocol.syntax,
            pysnmpUsmKeyPrivLocalized.syntax
            )
              
    def __generateRequestOrResponseMsg(
        self,
        snmpEngine,
        messageProcessingModel,
        globalData,
        maxMessageSize,
        securityModel,
        securityEngineID,
        securityName,
        securityLevel,
        scopedPDU,
        securityStateReference
        ):
        snmpEngineID = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')[0].syntax
        # 3.1.1
        if securityStateReference is not None:
            # 3.1.1a
            cachedSecurityData = self._cachePop(securityStateReference)
            usmUserName = cachedSecurityData['msgUserName']
            usmUserAuthProtocol = cachedSecurityData.get('usmUserAuthProtocol')
            usmUserAuthKeyLocalized = cachedSecurityData.get(
                'usmUserAuthKeyLocalized'
                )
            usmUserPrivProtocol = cachedSecurityData.get('usmUserPrivProtocol')
            usmUserPrivKeyLocalized = cachedSecurityData.get(
                'usmUserPrivKeyLocalized'
                )
            securityEngineID = snmpEngineID
            debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: user info read from cache')
        elif securityName:
            # 3.1.1b
            try:
                ( usmUserName,
                  usmUserAuthProtocol,
                  usmUserAuthKeyLocalized,
                  usmUserPrivProtocol,
                  usmUserPrivKeyLocalized ) = self.__getUserInfo(
                    snmpEngine.msgAndPduDsp.mibInstrumController,
                    securityEngineID, securityName
                    )
                debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: read user info')
            except NoSuchInstanceError:
                pysnmpUsmDiscovery, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__PYSNMP-USM-MIB', 'pysnmpUsmDiscovery')
                __reportUnknownName = not pysnmpUsmDiscovery.syntax
                if not __reportUnknownName:
                    try:
                        ( usmUserName,
                          usmUserAuthProtocol,
                          usmUserAuthKeyLocalized,
                          usmUserPrivProtocol,
                          usmUserPrivKeyLocalized ) = self.__cloneUserInfo(
                            snmpEngine.msgAndPduDsp.mibInstrumController,
                            securityEngineID,
                            securityName
                            )
                    except NoSuchInstanceError:
                        __reportUnknownName = 1

                if __reportUnknownName:
                    raise error.StatusInformation(
                        errorIndication = 'unknownSecurityName'
                        )
                debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: clone user info')
        else:
            # empty username used for engineID discovery
            usmUserName = usmUserSecurityName = ''
            usmUserAuthProtocol = usmUserAuthKeyLocalized = None
            usmUserPrivProtocol = usmUserPrivKeyLocalized = None
            debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: use empty USM data')
            
        debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: local user usmUserName %s usmUserAuthProtocol %s usmUserPrivProtocol %s by securityEngineID %s securityName %s' % (usmUserName, usmUserAuthProtocol, usmUserPrivProtocol, securityEngineID, securityName))

        msg = globalData
        
        # 3.1.2
        if securityLevel == 3:
            if not usmUserAuthProtocol or not usmUserPrivProtocol:
                raise error.StatusInformation(
                    errorIndication = 'unsupportedSecurityLevel'
                    )

        # 3.1.3
        if securityLevel == 3 or securityLevel == 2:
            if not usmUserAuthProtocol:
                raise error.StatusInformation(
                    errorIndication = 'unsupportedSecurityLevel'
                    )

        securityParameters = UsmSecurityParameters()

        scopedPDUData = msg.setComponentByPosition(3).getComponentByPosition(3)
        scopedPDUData.setComponentByPosition(0, scopedPDU)
        
        # 3.1.6a
        if securityStateReference is None and (  # request type check added
            securityLevel == 3 or securityLevel == 2
            ):
            if self.__timeline.has_key(securityEngineID):
                ( snmpEngineBoots,
                  snmpEngineTime,
                  latestReceivedEngineTime,
                  latestUpdateTimestamp) = self.__timeline[
                    securityEngineID
                    ]
                debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: read snmpEngineBoots, snmpEngineTime from timeline')
            else:
                # 2.3 XXX is this correct?
                snmpEngineBoots = snmpEngineTime = 0
                debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: no timeline for securityEngineID %s' % securityEngineID)
        # 3.1.6.b
        elif securityStateReference is not None:  # XXX Report?
            ( snmpEngineBoots,
              snmpEngineTime ) = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineBoots', 'snmpEngineTime')
            snmpEngineBoots = snmpEngineBoots.syntax
            snmpEngineTime = snmpEngineTime.syntax.clone()
            debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: read snmpEngineBoots, snmpEngineTime from LCD')
        # 3.1.6.c
        else:
            snmpEngineBoots = snmpEngineTime = 0
            debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: assuming zero snmpEngineBoots, snmpEngineTime')

        debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: use snmpEngineBoots %s snmpEngineTime %s for securityEngineID %s' % (snmpEngineBoots, snmpEngineTime, securityEngineID))

        # 3.1.4a
        if securityLevel == 3:
            privHandler = self.privServices.get(usmUserPrivProtocol)
            if privHandler is None:
                raise error.StatusInformation(
                    errorIndication = 'encryptionError'
                    )
            dataToEncrypt = encoder.encode(scopedPDU)
            
            debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: scopedPDU encoded')

            try:
                ( encryptedData,
                  privParameters ) = privHandler.encryptData(
                    usmUserPrivKeyLocalized,
                    ( snmpEngineBoots, snmpEngineTime, None ),
                    dataToEncrypt
                    )
            except error.StatusInformation, statusInformation:
                raise

            securityParameters.setComponentByPosition(5, privParameters)
            scopedPDUData.setComponentByPosition(1, encryptedData)

            debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: scopedPDU ciphered')

        # 3.1.4b
        elif securityLevel == 1 or securityLevel == 2:
            securityParameters.setComponentByPosition(5, '')

        debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: %s' % scopedPDUData.prettyPrint())
        
        # 3.1.5
        securityParameters.setComponentByPosition(0, securityEngineID)
        securityParameters.setComponentByPosition(1, snmpEngineBoots)
        securityParameters.setComponentByPosition(2, snmpEngineTime)
    
        # 3.1.7
        securityParameters.setComponentByPosition(3, usmUserName)

        # 3.1.8a
        if securityLevel == 3 or securityLevel == 2:
            authHandler = self.authServices.get(usmUserAuthProtocol)
            if authHandler is None:
                raise error.StatusInformation(
                    errorIndication = 'authenticationFailure'
                    )

            # extra-wild hack to facilitate BER substrate in-place re-write
            securityParameters.setComponentByPosition(
                4, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                )

            debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: %s' % (securityParameters.prettyPrint(),))
            
            msg.setComponentByPosition(2, encoder.encode(securityParameters))

            wholeMsg = encoder.encode(msg)

            try:
                authenticatedWholeMsg = authHandler.authenticateOutgoingMsg(
                    usmUserAuthKeyLocalized, wholeMsg
                    )
            except error.StatusInformation, statusInformation:
                raise
            
            debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: auth outgoing msg')
        # 3.1.8b
        else:
            securityParameters.setComponentByPosition(4, '')
            debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: %s' % (securityParameters.prettyPrint(),))
            msg.setComponentByPosition(2, encoder.encode(securityParameters))
            authenticatedWholeMsg = encoder.encode(msg)
            debug.logger & debug.flagSM and debug.logger('__generateRequestOrResponseMsg: plain outgoing msg')

        # 3.1.9
        return (
            msg.getComponentByPosition(2),
            authenticatedWholeMsg
            )

    def generateRequestMsg(
        self,
        snmpEngine,
        messageProcessingModel,
        globalData,
        maxMessageSize,
        securityModel,
        securityEngineID,
        securityName,
        securityLevel,
        scopedPDU,
        ):
        return self.__generateRequestOrResponseMsg(
            snmpEngine,
            messageProcessingModel,
            globalData,
            maxMessageSize,
            securityModel,
            securityEngineID,
            securityName,
            securityLevel,
            scopedPDU,
            None
            )
    
    def generateResponseMsg(
        self,
        snmpEngine,
        messageProcessingModel,
        globalData,
        maxMessageSize,
        securityModel,
        securityEngineID,
        securityName,
        securityLevel,
        scopedPDU,
        securityStateReference
        ):
        return self.__generateRequestOrResponseMsg(
            snmpEngine,
            messageProcessingModel,
            globalData,
            maxMessageSize,
            securityModel,
            securityEngineID,
            securityName,
            securityLevel,
            scopedPDU,
            securityStateReference
            )
            
    # 3.2
    def processIncomingMsg(
        self,
        snmpEngine,
        messageProcessingModel,
        maxMessageSize,
        securityParameters,
        securityModel,
        securityLevel,
        wholeMsg,
        msg  # XXX 
        ):
        # 3.2.1 
        try:
            securityParameters, rest = decoder.decode(
                securityParameters,
                asn1Spec=self._securityParametersSpec
                )
        except PyAsn1Error:
           snmpInASNParseErrs, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMPv2-MIB', 'snmpInASNParseErrs')
           snmpInASNParseErrs.syntax = snmpInASNParseErrs.syntax + 1
           raise error.StatusInformation(
               errorIndication='parseError'
               )

        debug.logger & debug.flagSM and debug.logger('processIncomingMsg: %s' % (securityParameters.prettyPrint(),))

        # 3.2.9 -- moved up here to be able to report
        # maxSizeResponseScopedPDU on error
        maxSizeResponseScopedPDU = maxMessageSize - 512   # XXX
        if maxSizeResponseScopedPDU < 0:
            maxSizeResponseScopedPDU = 0
        
        # 3.2.2
        securityEngineID = securityParameters.getComponentByPosition(0)
        securityStateReference = self._cachePush(
            msgUserName=securityParameters.getComponentByPosition(3)
            )

        debug.logger & debug.flagSM and debug.logger('processIncomingMsg: cache read securityStateReference %s by msgUserName %s' % (securityStateReference, securityParameters.getComponentByPosition(3)))
        
        # Used for error reporting
        contextEngineId = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')[0].syntax
        contextName = ''

        # 3.2.3
        if not self.__timeline.has_key(securityEngineID):
            debug.logger & debug.flagSM and debug.logger('processIncomingMsg: unknown securityEngineID %s' % securityEngineID)
            if securityEngineID:
                # 3.2.3a XXX any other way to get auth engine in cache?
                self.__timeline[securityEngineID] = (
                    securityParameters.getComponentByPosition(1),
                    securityParameters.getComponentByPosition(2),
                    securityParameters.getComponentByPosition(2),
                    int(time.time())
                    )
                
                expireAt = self.__expirationTimer + 300
                if not self.__timelineExpQueue.has_key(expireAt):
                    self.__timelineExpQueue[expireAt] = []
                self.__timelineExpQueue[expireAt].append(securityEngineID)
                    
                debug.logger & debug.flagSM and debug.logger('processIncomingMsg: store timeline for securityEngineID %s' % (securityEngineID,))
            else:
                # 3.2.3b
                usmStatsUnknownEngineIDs, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-USER-BASED-SM-MIB', 'usmStatsUnknownEngineIDs')
                usmStatsUnknownEngineIDs.syntax = usmStatsUnknownEngineIDs.syntax+1
                debug.logger & debug.flagSM and debug.logger('processIncomingMsg: null securityEngineID')
                pysnmpUsmDiscoverable, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__PYSNMP-USM-MIB', 'pysnmpUsmDiscoverable')
                if pysnmpUsmDiscoverable.syntax:
                    debug.logger & debug.flagSM and debug.logger('processIncomingMsg: request EngineID discovery')
                    raise error.StatusInformation(
                        errorIndication = 'unknownEngineID',
                        oid=usmStatsUnknownEngineIDs.name,
                        val=usmStatsUnknownEngineIDs.syntax,
                        securityStateReference=securityStateReference,
                        contextEngineId=contextEngineId,
                        contextName=contextName,
                        maxSizeResponseScopedPDU=maxSizeResponseScopedPDU
                        )
                else:
                    debug.logger & debug.flagSM and debug.logger('processIncomingMsg: will not discover EngineID')                    
                    # free securityStateReference XXX
                    raise error.StatusInformation(
                        errorIndication = 'unknownEngineID'
                        )

        snmpEngineID = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')[0].syntax
 
        msgAuthoritativeEngineID = securityParameters.getComponentByPosition(0)
        msgUserName = securityParameters.getComponentByPosition(3)

        debug.logger & debug.flagSM and debug.logger('processIncomingMsg: read from securityParams msgAuthoritativeEngineID %s msgUserName %s' % (msgAuthoritativeEngineID, msgUserName))
        
        if msgUserName:
            # 3.2.4
            try:
                ( usmUserSecurityName,
                  usmUserAuthProtocol,
                  usmUserAuthKeyLocalized,
                  usmUserPrivProtocol,
                  usmUserPrivKeyLocalized ) = self.__getUserInfo(
                    snmpEngine.msgAndPduDsp.mibInstrumController, msgAuthoritativeEngineID, msgUserName
                    )
                debug.logger & debug.flagSM and debug.logger('processIncomingMsg: read user info from LCD')
            except NoSuchInstanceError:
                pysnmpUsmDiscoverable, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__PYSNMP-USM-MIB', 'pysnmpUsmDiscoverable')
                __reportUnknownName = not pysnmpUsmDiscoverable.syntax
                if not __reportUnknownName:
                    try:
                        ( usmUserSecurityName,
                          usmUserAuthProtocol,
                          usmUserAuthKeyLocalized,
                          usmUserPrivProtocol,
                          usmUserPrivKeyLocalized ) = self.__cloneUserInfo(
                            snmpEngine.msgAndPduDsp.mibInstrumController,
                            securityEngineID,
                            msgUserName
                            )
                        debug.logger & debug.flagSM and debug.logger('processIncomingMsg: cloned user info')
                    except NoSuchInstanceError:
                        __reportUnknownName = 1
                debug.logger & debug.flagSM and debug.logger('processIncomingMsg: unknown securityEngineID %s msgUserName %s' % (securityEngineID, msgUserName))
                if __reportUnknownName:
                        usmStatsUnknownUserNames, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-USER-BASED-SM-MIB', 'usmStatsUnknownUserNames')
                        usmStatsUnknownUserNames.syntax = usmStatsUnknownUserNames.syntax+1
                        raise error.StatusInformation(
                            errorIndication = 'unknownSecurityName',
                            oid = usmStatsUnknownUserNames.name,
                            val = usmStatsUnknownUserNames.syntax,
                            securityStateReference=securityStateReference,
                            contextEngineId=contextEngineId,
                            contextName=contextName,
                            maxSizeResponseScopedPDU=maxSizeResponseScopedPDU
                            )
        else:
            # empty username used for engineID discovery
            usmUserName = usmUserSecurityName = ''
            usmUserAuthProtocol = usmUserAuthKeyLocalized = None
            usmUserPrivProtocol = usmUserPrivKeyLocalized = None

        debug.logger & debug.flagSM and debug.logger('processIncomingMsg: now have usmUserSecurityName %s usmUserAuthProtocol %s usmUserPrivProtocol %s for msgUserName %s' % (usmUserSecurityName, usmUserAuthProtocol, usmUserPrivProtocol, msgUserName))

        # 3.2.5
        __reportError = 0
        if securityLevel == 3:
            if not usmUserAuthProtocol or not usmUserPrivProtocol:
                __reportError = 1
            elif securityLevel == 2:
                if not usmUserAuthProtocol:
                    __reportError = 1
        if __reportError:
            usmStatsUnsupportedSecLevels, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-USER-BASED-SM-MIB', 'usmStatsUnsupportedSecLevels')
            usmStatsUnsupportedSecLevels.syntax = usmStatsUnsupportedSecLevels.syntax + 1
            raise error.StatusInformation(
                errorIndication='unsupportedSecurityLevel',
                oid=usmStatsUnknownEngineIDs.name,
                val=usmStatsUnknownEngineIDs.syntax,
                securityStateReference=securityStateReference,
                contextEngineId=contextEngineId,
                contextName=contextName,
                maxSizeResponseScopedPDU=maxSizeResponseScopedPDU
                )

        # 3.2.6
        if securityLevel == 3 or securityLevel == 2:
            authHandler = self.authServices.get(usmUserAuthProtocol)
            if authHandler is None:
                raise error.StatusInformation(
                    errorIndication = 'authenticationFailure'
                    )
            try:
                authenticatedWholeMsg = authHandler.authenticateIncomingMsg(
                    usmUserAuthKeyLocalized,
                    securityParameters.getComponentByPosition(4),
                    wholeMsg
                    )
            except error.StatusInformation:
                usmStatsWrongDigests, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-USER-BASED-SM-MIB', 'usmStatsWrongDigests')
                usmStatsWrongDigests.syntax = usmStatsWrongDigests.syntax+1
                raise error.StatusInformation(
                    errorIndication = 'authenticationFailure',
                    oid=usmStatsWrongDigests.name,
                    val=usmStatsWrongDigests.syntax,
                    securityStateReference=securityStateReference,
                    contextEngineId=contextEngineId,
                    contextName=contextName,
                    maxSizeResponseScopedPDU=maxSizeResponseScopedPDU
                    )
            
            debug.logger & debug.flagSM and debug.logger('processIncomingMsg: incoming msg authed')
        # 3.2.7
        if securityLevel == 3 or securityLevel == 2:
            if msgAuthoritativeEngineID == snmpEngineID:
                # Authoritative SNMP engine: use local notion (SF bug #1649032)
                ( snmpEngineBoots,
                  snmpEngineTime ) = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineBoots', 'snmpEngineTime')
                snmpEngineBoots = snmpEngineBoots.syntax
                snmpEngineTime = snmpEngineTime.syntax.clone()
                idleTime = 0
                debug.logger & debug.flagSM and debug.logger('processIncomingMsg: read snmpEngineBoots (%s), snmpEngineTime (%s) from LCD' % (snmpEngineBoots, snmpEngineTime))
            else:
                # Non-authoritative SNMP engine: use cached estimates
                if self.__timeline.has_key(securityEngineID):
                    ( snmpEngineBoots,
                      snmpEngineTime,
                      latestReceivedEngineTime,
                      latestUpdateTimestamp ) = self.__timeline[
                        msgAuthoritativeEngineID
                        ]
                    # time passed since last talk with this SNMP engine
                    idleTime = int(time.time())-latestUpdateTimestamp
                    debug.logger & debug.flagSM and debug.logger('processIncomingMsg: read timeline snmpEngineBoots %s snmpEngineTime %s for msgAuthoritativeEngineID %s, idle time %s secs' % (snmpEngineBoots, snmpEngineTime, msgAuthoritativeEngineID, idleTime))
                else:
                    raise error.ProtocolError('Peer SNMP engine info missing')

            msgAuthoritativeEngineBoots = securityParameters.getComponentByPosition(1)
            msgAuthoritativeEngineTime = securityParameters.getComponentByPosition(2)

            # 3.2.7a
            if msgAuthoritativeEngineID == snmpEngineID:
                if snmpEngineBoots == 2147483647L or \
                   snmpEngineBoots != msgAuthoritativeEngineBoots or \
                   abs(idleTime + int(snmpEngineTime) - \
                       int(msgAuthoritativeEngineTime)) > 150:
                    usmStatsNotInTimeWindows, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-USER-BASED-SM-MIB', 'usmStatsNotInTimeWindows')
                    usmStatsNotInTimeWindows.syntax = usmStatsNotInTimeWindows.syntax+1
                    raise error.StatusInformation(
                        errorIndication = 'notInTimeWindow',
                        oid=usmStatsNotInTimeWindows.name,
                        val=usmStatsNotInTimeWindows.syntax,
                        securityStateReference=securityStateReference,
                        securityLevel=2,
                        contextEngineId=contextEngineId,
                        contextName=contextName,
                        maxSizeResponseScopedPDU=maxSizeResponseScopedPDU
                        )
            # 3.2.7b
            else:
                # 3.2.7b.1
                if msgAuthoritativeEngineBoots > snmpEngineBoots or \
                   msgAuthoritativeEngineBoots == snmpEngineBoots and \
                   msgAuthoritativeEngineTime > latestReceivedEngineTime:
                    self.__timeline[msgAuthoritativeEngineID] = (
                        msgAuthoritativeEngineBoots,
                        msgAuthoritativeEngineTime,
                        msgAuthoritativeEngineTime,
                        int(time.time())
                        )
                    debug.logger & debug.flagSM and debug.logger('processIncomingMsg: stored timeline msgAuthoritativeEngineBoots %s msgAuthoritativeEngineTime %s for msgAuthoritativeEngineID %s' % (msgAuthoritativeEngineBoots, msgAuthoritativeEngineTime, msgAuthoritativeEngineID))
                    
                # 3.2.7b.2
                if snmpEngineBoots == 2147483647L or \
                   msgAuthoritativeEngineBoots < snmpEngineBoots or \
                   msgAuthoritativeEngineBoots == snmpEngineBoots and \
                   abs(idleTime + int(snmpEngineTime) - \
                       int(msgAuthoritativeEngineTime)) > 150:
                    raise error.StatusInformation(
                        errorIndication = 'notInTimeWindow'
                        )

        scopedPduData = msg.getComponentByPosition(3)

        # 3.2.8a
        if securityLevel == 3:
            privHandler = self.privServices.get(usmUserPrivProtocol)
            if privHandler is None:
                raise error.StatusInformation(
                    errorIndication = 'decryptionError'
                    )
            encryptedPDU = scopedPduData.getComponentByPosition(1)
            if encryptedPDU is None: # no ciphertext
                raise error.StatusInformation(
                    errorIndication = 'decryptionError'
                    )

            try:
               decryptedData = privHandler.decryptData(
                    usmUserPrivKeyLocalized,
                    ( securityParameters.getComponentByPosition(1),
                      securityParameters.getComponentByPosition(2),
                      securityParameters.getComponentByPosition(5) ),
                    encryptedPDU
                    )
               debug.logger & debug.flagSM and debug.logger('processIncomingMsg: PDU deciphered')
            except error.StatusInformation:
                usmStatsDecryptionErrors, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-USER-BASED-SM-MIB', 'usmStatsDecryptionErrors')
                usmStatsDecryptionErrors.syntax = usmStatsDecryptionErrors.syntax+1
                raise error.StatusInformation(
                    errorIndication = 'decryptionError',
                    oid=usmStatsDecryptionErrors.name,
                    val=usmStatsDecryptionErrors.syntax,
                    securityStateReference=securityStateReference,
                    contextEngineId=contextEngineId,
                    contextName=contextName,
                    maxSizeResponseScopedPDU=maxSizeResponseScopedPDU
                    )
            scopedPduSpec = scopedPduData.setComponentByPosition(0).getComponentByPosition(0)
            try:
                scopedPDU, rest = decoder.decode(
                    decryptedData, asn1Spec=scopedPduSpec
                    )
            except PyAsn1Error, why:
               debug.logger & debug.flagSM and debug.logger('processIncomingMsg: PDU decoder failed %s' % why)                
               raise error.StatusInformation(
                   errorIndication = 'decryptionError'
                   )
        else:
            # 3.2.8b
            scopedPDU = scopedPduData.getComponentByPosition(0)
            if scopedPDU is None:  # no plaintext
                raise error.StatusInformation(
                    errorIndication = 'decryptionError'
                    )

        # 3.2.10
        securityName = usmUserSecurityName
        
        # 3.2.11
        self._cachePop(securityStateReference)
        securityStateReference = self._cachePush(
            msgUserName=securityParameters.getComponentByPosition(3),
            usmUserAuthProtocol=usmUserAuthProtocol,
            usmUserAuthKeyLocalized=usmUserAuthKeyLocalized,
            usmUserPrivProtocol=usmUserPrivProtocol,
            usmUserPrivKeyLocalized=usmUserPrivKeyLocalized
            )

        debug.logger & debug.flagSM and debug.logger('processIncomingMsg: cached msgUserName %s info by securityStateReference %s' % (msgUserName, securityStateReference))
        
        # Delayed to include details
        if not msgUserName and not securityEngineID:
            usmStatsUnknownUserNames, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-USER-BASED-SM-MIB', 'usmStatsUnknownUserNames')
            usmStatsUnknownUserNames.syntax = usmStatsUnknownUserNames.syntax+1
            raise error.StatusInformation(
                errorIndication='unknownSecurityName',
                oid=usmStatsUnknownUserNames.name,
                val=usmStatsUnknownUserNames.syntax,
                securityStateReference=securityStateReference,
                securityEngineID=securityEngineID,
                contextEngineId=contextEngineId,
                contextName=contextName,
                maxSizeResponseScopedPDU=maxSizeResponseScopedPDU,
                PDU=scopedPDU
                )

        # 3.2.12
        return ( securityEngineID,
                 securityName,
                 scopedPDU,
                 maxSizeResponseScopedPDU,
                 securityStateReference )

    def __expireTimelineInfo(self):
        if self.__timelineExpQueue.has_key(self.__expirationTimer):
            for engineIdKey in self.__timelineExpQueue[self.__expirationTimer]:
                del self.__timeline[engineIdKey]
                debug.logger & debug.flagMP and debug.logger('__expireEnginesInfo: expiring %s' % (engineIdKey,))
            del self.__timelineExpQueue[self.__expirationTimer]
        self.__expirationTimer = self.__expirationTimer + 1
        
    def receiveTimerTick(self, snmpEngine, timeNow):
        self.__expireTimelineInfo()
