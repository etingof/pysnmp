import sys
from pysnmp.proto import rfc1902, rfc1905
from pysnmp.proto.api import v2c
from pysnmp.smi.builder import ZipMibSource
from pysnmp.smi.compiler import addMibCompiler, defaultDest
from pysnmp.smi.error import SmiError
from pyasn1.type.base import AbstractSimpleAsn1Item
from pyasn1.error import PyAsn1Error
from pysnmp import debug

#
# An OID-like object that embeds MIB resolution.
#
# Valid initializers include:
# ObjectIdentity('1.3.6.1.2.1.1.1.0')
# ObjectIdentity('iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0')
# ObjectIdentity('SNMPv2-MIB', 'system')
# ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)
# ObjectIdentity('IP-MIB', 'ipAdEntAddr', '127.0.0.1', 123)
# 
class ObjectIdentity:
    stDirty, stClean = 1, 2
        
    def __init__(self, *args, **kwargs):
        self.__args = args
        self.__kwargs = kwargs
        self.__mibSourcesToAdd = self.__modNamesToLoad = None
        self.__asn1SourcesToAdd = None
        self.__state  = self.stDirty

    #
    # public API
    #
    def getMibSymbol(self):
        if self.__state & self.stClean:
            return self.__modName, self.__symName, self.__indices
        else:
            raise SmiError('%s object not fully initialized' % self.__class__.__name__)

    def getOid(self):
        if self.__state & self.stClean:
            return self.__oid
        else:
            raise SmiError('%s object not fully initialized' % self.__class__.__name__)

    def getLabel(self):
        if self.__state & self.stClean:
            return self.__label
        else:
            raise SmiError('%s object not fully initialized' % self.__class__.__name__)

    def getMibNode(self):
        if self.__state & self.stClean:
            return self.__mibNode
        else:
            raise SmiError('%s object not fully initialized' % self.__class__.__name__)
   
    #
    # A gateway to MIBs manipulation routines
    #

    def addMibCompiler(self, *asn1Sources, **kwargs):
        if self.__asn1SourcesToAdd is None:
            self.__asn1SourcesToAdd = asn1Sources
        else:
            self.__asn1SourcesToAdd += asn1Sources
        self.__mibDir = kwargs.get('destDir', defaultDest)
        return self

    def addMibSource(self, *mibSources):
        if self.__mibSourcesToAdd is None:
            self.__mibSourcesToAdd = mibSources
        else:
            self.__mibSourcesToAdd += mibSources
        return self

    # provides deferred MIBs load
    def loadMibs(self, *modNames):
        if self.__modNamesToLoad is None:
            self.__modNamesToLoad = modNames
        else:
            self.__modNamesToLoad += modNames
        return self

    # this would eventually be called by an entity which posses a
    # reference to MibViewController
    def resolveWithMib(self, mibViewController):
        if self.__mibSourcesToAdd is not None:
            debug.logger & debug.flagMIB and debug.logger('adding MIB sources %s' % ', '.join(self.__mibSourcesToAdd))
            mibViewController.mibBuilder.addMibSources(
                *[ ZipMibSource(x) for x in self.__mibSourcesToAdd ]
            )
            self.__mibSourcesToAdd = None

        if self.__asn1SourcesToAdd is not None:
            debug.logger & debug.flagMIB and debug.logger('adding MIB compiler with source paths %s' % ', '.join(self.__asn1SourcesToAdd))
            addMibCompiler(
                mibViewController.mibBuilder,
                sources=self.__asn1SourcesToAdd,
                destination=self.__mibDir
            )
            self.__asn1SourcesToAdd = self.__mibDir = None

        if self.__modNamesToLoad is not None:
            debug.logger & debug.flagMIB and debug.logger('loading MIB modules %s' % ', '.join(self.__modNamesToLoad))
            mibViewController.mibBuilder.loadModules(*self.__modNamesToLoad)
            self.__modNamesToLoad = None

        if self.__state & self.stClean:
            return self

        MibScalar, MibTableColumn = mibViewController.mibBuilder.importSymbols('SNMPv2-SMI', 'MibScalar', 'MibTableColumn')

        self.__indices = ()

        if len(self.__args) == 1:  # OID or label
            debug.logger & debug.flagMIB and debug.logger('resolving %s as OID or label' % self.__args)
            try:
                self.__oid = rfc1902.ObjectName(self.__args[0])
            except PyAsn1Error:
                try:
                    label = tuple(self.__args[0].split('.'))
                except ValueError:
                    raise SmiError('Bad OID format %r' % (self.__args[0],))
                prefix, label, suffix = mibViewController.getNodeNameByOid(
                    label
                )
             
                if suffix:
                    try:
                        suffix = tuple([ int(x) for x in suffix ])
                    except ValueError:
                        raise SmiError('Unknown object name component %r' % (suffix,))
                self.__oid = rfc1902.ObjectName(prefix + suffix)
            else:
                prefix, label, suffix = mibViewController.getNodeNameByOid(
                    self.__oid
                )

            debug.logger & debug.flagMIB and debug.logger('resolved %r into prefix %r and suffix %r' % (self.__args, prefix, suffix))

            modName, symName, _ = mibViewController.getNodeLocation(prefix)

            self.__modName = modName
            self.__symName = symName

            self.__label = label

            mibNode, = mibViewController.mibBuilder.importSymbols(
                modName, symName
            )

            self.__mibNode = mibNode

            debug.logger & debug.flagMIB and debug.logger('resolved prefix %r into MIB node %r' % (prefix, mibNode))

            if isinstance(mibNode, MibTableColumn): # table column
                if suffix:
                    rowModName, rowSymName, _ = mibViewController.getNodeLocation(
                        mibNode.name[:-1]
                    )
                    rowNode, = mibViewController.mibBuilder.importSymbols(
                        rowModName, rowSymName
                    )
                    self.__indices = rowNode.getIndicesFromInstId(suffix)
            elif isinstance(mibNode, MibScalar): # scalar
                if suffix:
                    self.__indices = ( rfc1902.ObjectName(suffix), )
            else:
                if suffix:
                    self.__indices = ( rfc1902.ObjectName(suffix), )
            self.__state |= self.stClean

            debug.logger & debug.flagMIB and debug.logger('resolved indices are %r' % (self.__indices,))

            return self
        elif len(self.__args) > 1:  # MIB, symbol[, index, index ...]
            self.__modName = self.__args[0]
            if self.__args[1]:
                self.__symName = self.__args[1]
            else:
                mibViewController.mibBuilder.loadModules(self.__modName)
                if self.__kwargs.get('last'):
                    oid,_,_ = mibViewController.getLastNodeName(self.__modName)
                else:
                    oid,_,_ = mibViewController.getFirstNodeName(self.__modName)
                _, self.__symName, _ = mibViewController.getNodeLocation(oid)

            mibNode, = mibViewController.mibBuilder.importSymbols(
                self.__modName, self.__symName
            )

            self.__mibNode = mibNode

            self.__oid = rfc1902.ObjectName(mibNode.getName())

            prefix, label, suffix = mibViewController.getNodeNameByOid(
                self.__oid
            )
            self.__label = label

            debug.logger & debug.flagMIB and debug.logger('resolved %r into prefix %r and suffix %r' % (self.__args, prefix, suffix))

            if isinstance(mibNode, MibTableColumn): # table
                rowModName, rowSymName, _ = mibViewController.getNodeLocation(
                    mibNode.name[:-1]
                )
                rowNode, = mibViewController.mibBuilder.importSymbols(
                    rowModName, rowSymName
                )
                if self.__args[2:]:
                    try:
                        instIds = rowNode.getInstIdFromIndices(*self.__args[2:])
                        self.__oid += instIds
                        self.__indices = rowNode.getIndicesFromInstId(instIds)
                    except PyAsn1Error:
                        raise SmiError('Instance index %r to OID convertion failure at object %r: %s' % (self.__args[2:], mibNode.getLabel(), sys.exc_info()[1]))
            elif self.__args[2:]: # any other kind of MIB node with indices
                if self.__args[2:]:
                    instId = rfc1902.ObjectName(
                        '.'.join([ str(x) for x in self.__args[2:] ])
                    )
                    self.__oid += instId
                    self.__indices = ( instId, )
            self.__state |= self.stClean

            debug.logger & debug.flagMIB and debug.logger('resolved indices are %r' % (self.__indices,))

            return self
        else:
            raise SmiError('Non-OID, label or MIB symbol')

    def prettyPrint(self):
        if self.__state & self.stClean:
            return '%s::%s%s%s' % (
                self.__modName, self.__symName,
                self.__indices and  '.' or '', 
                '.'.join(['"%s"' % x.prettyPrint() for x in self.__indices ])
            )
        else:
            raise SmiError('%s object not fully initialized' % self.__class__.__name__)
 
    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, ', '.join([ repr(x) for x in self.__args]))

    # Redirect some attrs access to the OID object to behave alike

    def __str__(self):
        if self.__state & self.stClean:
            return str(self.__oid)
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __eq__(self, other):
        if self.__state & self.stClean:
            return self.__oid == other
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __ne__(self, other):
        if self.__state & self.stClean:
            return self.__oid != other
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __lt__(self, other):
        if self.__state & self.stClean:
            return self.__oid < other
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __le__(self, other):
        if self.__state & self.stClean:
            return self.__oid <= other
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __gt__(self, other):
        if self.__state & self.stClean:
            return self.__oid > other
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __ge__(self, other):
        if self.__state & self.stClean:
            return self.__oid > other
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __nonzero__(self):
        if self.__state & self.stClean:
            return self.__oid != 0
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __bool__(self):
        if self.__state & self.stClean:
            return bool(self.__oid)
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __getitem__(self, i):
        if self.__state & self.stClean:
            return self.__oid[i]
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __len__(self):
        if self.__state & self.stClean:
            return len(self.__oid)
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __add__(self, other):
        if self.__state & self.stClean:
            return self.__oid + other
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __radd__(self, other):
        if self.__state & self.stClean:
            return other + self.__oid
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __hash__(self):
        if self.__state & self.stClean:
            return hash(self.__oid)
        else:
            raise SmiError('%s object not properly initialized' % self.__class__.__name__)

    def __getattr__(self, attr):
        if self.__state & self.stClean:
            if attr in ( 'asTuple', 'clone', 'subtype', 'isPrefixOf',
                         'isSameTypeWith', 'isSuperTypeOf'):
                return getattr(self.__oid, attr)
            raise AttributeError
        else:
            raise SmiError('%s object not properly initialized for accessing %s' % (self.__class__.__name__, attr))

# A two-element sequence of ObjectIdentity and SNMP data type object
class ObjectType:
    stDirty, stClean = 1, 2
    def __init__(self, objectIdentity, objectSyntax=rfc1905.unSpecified):
        if not isinstance(objectIdentity, ObjectIdentity):
            raise SmiError('initializer should be ObjectIdentity instance, not %r' % (objectIdentity,))
        self.__args = [ objectIdentity, objectSyntax ]
        self.__state = self.stDirty

    def __getitem__(self, i):
        if self.__state & self.stClean:
            return self.__args[i]
        else:
            raise SmiError('%s object not fully initialized' % self.__class__.__name__)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, ', '.join([ repr(x) for x in self.__args]))

    def resolveWithMib(self, mibViewController):
        if self.__state & self.stClean:
            return self

        self.__args[0].resolveWithMib(mibViewController)

        MibScalar, MibTableColumn = mibViewController.mibBuilder.importSymbols('SNMPv2-SMI', 'MibScalar', 'MibTableColumn')

        if not isinstance(self.__args[0].getMibNode(),
                          (MibScalar, MibTableColumn)):
            if not isinstance(self.__args[1], AbstractSimpleAsn1Item):
                raise SmiError('MIB object %r is not OBJECT-TYPE (MIB not loaded?)' % (self.__args[0],))
            self.__state |= self.stClean
            return self

        if isinstance(self.__args[1], (rfc1905.UnSpecified,
                                       rfc1905.NoSuchObject,
                                       rfc1905.NoSuchInstance,
                                       rfc1905.EndOfMibView)):
            self.__state |= self.stClean
            return self

        try:
            self.__args[1] = self.__args[0].getMibNode().getSyntax().clone(self.__args[1])
        except PyAsn1Error:
            raise SmiError('Value %r to type %r convertion failure: %s' % (self.__args[1], self.__args[0].getMibNode().getSyntax().__class__.__name__, sys.exc_info()[1]))

        self.__state |= self.stClean

        debug.logger & debug.flagMIB and debug.logger('resolved %r syntax is %r' % (self.__args[0], self.__args[1]))

        return self

    def prettyPrint(self):
        if self.__state & self.stClean:
            return '%s = %s' % (self.__args[0].prettyPrint(),
                                self.__args[1].prettyPrint())
        else:
            raise SmiError('%s object not fully initialized' % self.__class__.__name__)

# A sequence of ObjectType's
class NotificationType:
    stDirty, stClean = 1, 2
    def __init__(self, objectIdentity, instanceIndex=(), objects={}):
        if not isinstance(objectIdentity, ObjectIdentity):
            raise SmiError('initializer should be ObjectIdentity instance, not %r' % (objectIdentity,))
        self.__objectIdentity = objectIdentity
        self.__instanceIndex = instanceIndex
        self.__objects = objects
        self.__varBinds = []
        self.__additionalVarBinds = []
        self.__state  = self.stDirty

    def __getitem__(self, i):
        if self.__state & self.stClean:
            return self.__varBinds[i]
        else:
            raise SmiError('%s object not fully initialized' % self.__class__.__name__)

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.__objectIdentity, self.__instanceIndex, self.__objects)

    def addVarBinds(self, *varBinds):
        debug.logger & debug.flagMIB and debug.logger('additional var-binds: %r' % (varBinds,))
        if self.__state & self.stClean:
            self.__varBinds.extend(varBinds)
        else:
            self.__additionalVarBinds.extend(varBinds)
        return self

    def resolveWithMib(self, mibViewController):
        if self.__state & self.stClean:
            return self

        self.__objectIdentity.resolveWithMib(mibViewController)

        self.__varBinds.append(
            ObjectType(ObjectIdentity(v2c.apiTrapPDU.snmpTrapOID),
                       self.__objectIdentity).resolveWithMib(mibViewController)
        )

        NotificationType, = mibViewController.mibBuilder.importSymbols('SNMPv2-SMI', 'NotificationType')

        mibNode = self.__objectIdentity.getMibNode()

        if isinstance(mibNode, NotificationType):
            for notificationObject in mibNode.getObjects():
                objectIdentity = ObjectIdentity(*notificationObject+self.__instanceIndex).resolveWithMib(mibViewController)
                self.__varBinds.append(
                    ObjectType(objectIdentity, self.__objects.get(notificationObject, rfc1905.unSpecified)).resolveWithMib(mibViewController)
                )
        else:
            debug.logger & debug.flagMIB and debug.logger('WARNING: MIB object %r is not NOTIFICATION-TYPE (MIB not loaded?)' % (self.__objectIdentity,))

        if self.__additionalVarBinds:
            self.__varBinds.extend(self.__additionalVarBinds)
            self.__additionalVarBinds = []
        
        self.__state |= self.stClean

        debug.logger & debug.flagMIB and debug.logger('resolved %r into %r' % (self.__objectIdentity, self.__varBinds))

        return self

    def prettyPrint(self):
        if self.__state & self.stClean:
            return ' '.join([ '%s = %s' % (x[0].prettyPrint(), x[1].prettyPrint()) for x in self.__varBinds])
        else:
            raise SmiError('%s object not fully initialized' % self.__class__.__name__)
