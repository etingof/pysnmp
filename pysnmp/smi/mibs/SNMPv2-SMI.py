import string
from pysnmp.smi.indices import OidOrderedDict
from pysnmp.smi import exval, error
from pysnmp.proto import rfc1902
from pyasn1.type import constraint
from pyasn1.error import ValueConstraintError
from pysnmp import debug

( Integer, ObjectIdentifier, Null ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "Null")

# syntax of objects

OctetString = rfc1902.OctetString
Bits = rfc1902.Bits
Integer32 = rfc1902.Integer32
IpAddress = rfc1902.IpAddress
Counter32 = rfc1902.Counter32
Gauge32 = rfc1902.Gauge32
Unsigned32 = rfc1902.Unsigned32
TimeTicks = rfc1902.TimeTicks
Opaque = rfc1902.Opaque
Counter64 = rfc1902.Counter64

class ExtUTCTime(OctetString):
    subtypeSpec = OctetString.subtypeSpec+constraint.ConstraintsUnion(constraint.ValueSizeConstraint(11,11), constraint.ValueSizeConstraint(13,13))

# MIB tree foundation classes

class MibNode:
    label = ''
    def __init__(self, name):
        self.name = name
        
    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, self.name)

    def getName(self): return self.name
    
    def getLabel(self): return self.label
    def setLabel(self, label):
        self.label = label
        return self

    def clone(self, name=None):
        myClone = self.__class__(self.name)
        if name is not None:
            myClone.name = name
        if self.label is not None:
            myClone.label = self.label
        return myClone
    
# definitions for information modules

class ModuleIdentity(MibNode):
    def getLastUpdated(self):
        return getattr(self, 'lastUpdated', '')
    def setLastUpdated(self, v):
        self.lastUpdated = v
        return self
    def getOrganization(self):
        return getattr(self, 'organization', '')
    def setOrganization(self, v):
        self.organization = v
        return self
    def getContactInfo(self):
        return getattr(self, 'contactInfo', '')
    def setContactInfo(self, v):
        self.contactInfo = v
        return self
    def getDescription(self):
        return getattr(self, 'description', '')
    def setDescription(self, v):
        self.description = v
        return self
    def getRevisions(self):
        return getattr(self, 'revisions', ())
    def setRevisions(self, args):
        self.revisions = args
        return self

    def asn1Print(self):
        return '\
MODULE-IDENTITY\n\
  LAST-UPDATED %s\n\
  ORGANIZATION \"%s\"\n\
  CONTACT-INFO \"%s\"\n\
  DESCRIPTION \"%s\"\n\
  %s\
' % (self.getLastUpdated(),
     self.getOrganization(),
     self.getContactInfo(),
     self.getDescription(),
     string.join(map(lambda x: "REVISION \"%s\"\n" % x, self.getRevisions())))

class ObjectIdentity(MibNode):
    def getStatus(self):
        return getattr(self, 'status', 'current')
    def setStatus(self, v):
        self.status = v
        return self
    def getDescription(self):
        return getattr(self, 'description', '')
    def setDescription(self, v):
        self.description = v
        return self
    def getReference(self):
        return getattr(self, 'reference', '')
    def setReference(self, v):
        self.reference = v
        return self

    def asn1Print(self):
        return '\
OBJECT-IDENTITY\n\
  STATUS %s\n\
  DESCRIPTION \"%s\"\n\
  REFERENCE \"%s\"\
' % (self.getStatus(),
     self.getDescription(),
     self.getReference())

# definition for objects

class NotificationType(MibNode):
    def getObjects(self):
        return getattr(self, 'objects', ())
    def setObjects(self, *args):
        self.objects = args
        return self
    def getStatus(self):
        return getattr(self, 'status', 'current')
    def setStatus(self, v):
        self.status = v
        return self
    def getDescription(self):
        return getattr(self, 'description', '')
    def setDescription(self, v):
        self.description = v
        return self
    def getRevisions(self):
        return getattr(self, 'revisions', ())
    def setRevisions(self, args):
        self.revisions = args
        return self

    def asn1Print(self):
        return '\
NOTIFICATION-TYPE\n\
  OBJECTS { %s }\n\
  STATUS %s\n\
  DESCRIPTION \"%s\"\n\
  %s\
' % (reduce(lambda x,y: '%s, %s' % (x[1],y[1]), self.getObjects(), ("","")),
     self.getStatus(),
     self.getDescription(),
     string.join(map(lambda x: "REVISION \"%s\"\n" % x, self.getRevisions())))

class MibIdentifier(MibNode):
    def asn1Print(self):
        return 'OBJECT IDENTIFIER'

class ObjectType(MibNode):
    maxAccess = None
    def __init__(self, name, syntax=None):
        MibNode.__init__(self, name)
        self.syntax = syntax

    # XXX
    def __cmp__(self, other): return cmp(self.syntax, other)
    
    def __repr__(self):
        return '%s(%s, %s)' % (
            self.__class__.__name__, self.name, self.syntax
            )    
    def getSyntax(self):
        return self.syntax
    def getUnits(self):
        return getattr(self, 'units', '')
    def setUnits(self, v):
        self.units = v
        return self    
    def getMaxAccess(self):
        return getattr(self, 'maxAccess', 'not-accessible')
    def setMaxAccess(self, v):
        self.maxAccess = v
        return self
    def getStatus(self):
        return getattr(self, 'status', 'current')
    def setStatus(self, v):
        self.status = v
        return self
    def getDescription(self):
        return getattr(self, 'description', '')
    def setDescription(self, v):
        self.description = v
        return self    
    def getReference(self):
        return getattr(self, 'reference', '')
    def setReference(self, v):
        self.reference = v
        return self

    def asn1Print(self):
        return '\
OBJECT-TYPE\n\
  SYNTAX %s\n\
  UNITS \"%s\"\n\
  MAX-ACCESS %s\n\
  STATUS %s\n\
  DESCRIPTION \"%s\"\n\
  REFERENCE \"%s\"\
' % (self.getSyntax().__class__.__name__,
     self.getUnits(),
     self.getMaxAccess(),
     self.getStatus(),
     self.getDescription(),
     self.getReference())
        
class MibTree(ObjectType):
    branchVersionId = 0L    # increments on tree structure change XXX
    maxAccess = 'not-accessible'
    def __init__(self, name, syntax=None):
        ObjectType.__init__(self, name, syntax)
        self._vars = OidOrderedDict()            

    # Subtrees registration
    
    def registerSubtrees(self, *subTrees):
        """Register subtrees at this tree. Subtrees are always attached
           at the level of this tree, not subtrees."""
        for subTree in subTrees:
            if self._vars.has_key(subTree.name):
                raise error.SmiError(
                    'MIB subtree %s already registered at %s' %  (subTree.name, self)
                    )
            self._vars[subTree.name] = subTree
            MibTree.branchVersionId = MibTree.branchVersionId + 1

    def unregisterSubtrees(self, *names):
        """Detach subtrees from this tree"""
        for name in names:
            # This may fail if you fill a table by exporting MibScalarInstances
            # but later drop them through SNMP.
            if not self._vars.has_key(name):
                raise  error.SmiError(
                    'MIB subtree %s not registered at %s' %  (name, self)
                    )
            del self._vars[name]
            MibTree.branchVersionId = MibTree.branchVersionId + 1

    # Tree traversal

    def getBranch(self, name, idx):
        """Return a branch of this tree where the 'name' OID may reside"""
        name = tuple(name) # XXX
        if len(self.name) < len(name):
            for keyLen in self._vars.getKeysLens():
                subName = name[:keyLen]
                if self._vars.has_key(subName):
                    return self._vars[subName]
        raise error.NoSuchObjectError(name=name, idx=idx)

    def getNode(self, name, idx=None):
        """Return tree node found by name"""
        if name == self.name:
            return self
        else:
            return self.getBranch(name, idx).getNode(name, idx)

    def getNextNode(self, name, idx=None):
        """Return tree node next to name"""
        try:
            nextNode = self.getBranch(name, idx)
        except error.NoSuchObjectError:
            # Start from the beginning
            if self._vars and name <= self._vars.keys()[0]:
                return self._vars[self._vars.keys()[0]]
            else:
                # Try following the white rabbit at our level
                try:
                    return self._vars[self._vars.nextKey(name)]
                except KeyError:
                    raise error.NoSuchObjectError(idx=idx, name=name)
        else:
            try:
                return nextNode.getNextNode(name, idx)
            except error.NoSuchObjectError:
                try:
                    return self._vars[self._vars.nextKey(nextNode.name)]
                except KeyError:
                    raise error.NoSuchObjectError(idx=idx, name=name)
                
    # MIB instrumentation

    # Read operation
    
    def readTest(self, name, val, idx, (acFun, acCtx)):
        if name == self.name:
            if acFun and \
                   self.maxAccess != 'readonly' and \
                   self.maxAccess != 'readwrite' and \
                   self.maxAccess != 'readcreate' or \
                   acFun and acFun(name, idx, 'read', acCtx):
                raise error.NoAccessError(idx=idx, name=name)
        else:
            try:
                node = self.getBranch(name, idx)
            except error.NoSuchObjectError:
                return # missing object is not an error here

            node.readTest(name, val, idx, (acFun, acCtx))
        
    def readGet(self, name, val, idx, (acFun, acCtx)):
        try:
            node = self.getBranch(name, idx)
        except error.NoSuchObjectError:
            return name, exval.noSuchInstance
        else:
            return node.readGet(name, val, idx, (acFun, acCtx))

    # Read next operation is subtree-specific
    
    def readTestNext(self, name, val, idx, (acFun, acCtx)):
        nextName = name
        while 1:  # XXX linear search here
            try:
                nextName = self.getNextNode(nextName, idx).name
            except error.NoSuchObjectError:
                return # missing object is not an error here
            try:
                return self.readTest(nextName, val, idx, (acFun, acCtx))
            except error.NoAccessError:
                continue
    
    def readGetNext(self, name, val, idx, (acFun, acCtx)):
        nextName = name
        while 1:
            try:
                nextName = self.getNextNode(nextName, idx).name
            except error.NoSuchObjectError:
                return name, exval.endOfMib
            try:
                self.readTest(nextName, val, idx, (acFun, acCtx)) # XXX
            except error.NoAccessError:
                continue
            else:
                return self.readGet(nextName, val, idx, (acFun, acCtx))

    # Write operation
    
    def writeTest(self, name, val, idx, (acFun, acCtx)):
        if name == self.name:
            # Make sure variable is writable
            if acFun and \
                   self.maxAccess != 'readwrite' and \
                   self.maxAccess != 'readcreate' or \
                   acFun and acFun(name, idx, 'write', acCtx):
                raise error.NotWritableError(idx=idx, name=name)
        else:
            node = self.getBranch(name, idx)
            node.writeTest(name, val, idx, (acFun, acCtx))
    
    def writeCommit(self, name, val, idx, (acFun, acCtx)):
        self.getBranch(name, idx).writeCommit(name, val, idx, (acFun, acCtx))
    
    def writeCleanup(self, name, val, idx, (acFun, acCtx)):
        self.getBranch(name, idx).writeCleanup(name, val, idx, (acFun, acCtx))
    
    def writeUndo(self, name, val, idx, (acFun, acCtx)):
        self.getBranch(name, idx).writeUndo(name, val, idx, (acFun, acCtx))

class MibScalar(MibTree):
    """Scalar MIB variable. Implements access control checking."""
    maxAccess = 'readonly'
        
    # MIB instrumentation methods
    
    # Read operation
    
    def readTest(self, name, val, idx, (acFun, acCtx)):
        if name == self.name:
            raise error.NoAccessError(idx=idx, name=name)
        else:
            MibTree.readTest(self, name, val, idx, (acFun, acCtx))
        # If instance exists, check permissions
        if acFun and \
               self.maxAccess != 'readonly' and \
               self.maxAccess != 'readwrite' and \
               self.maxAccess != 'readcreate' or \
               acFun and acFun(name, idx, 'read', acCtx):
            raise error.NoAccessError(idx=idx, name=name)
    
    # Two-phase commit implementation

    def writeTest(self, name, val, idx, (acFun, acCtx)):
        if name == self.name:
            raise error.NoAccessError(idx=idx, name=name)
        else:
            MibTree.writeTest(self, name, val, idx, (acFun, acCtx))
        # If instance exists, check permissions
        if acFun and \
               self.maxAccess != 'readwrite' and \
               self.maxAccess != 'readcreate' or \
               acFun and acFun(name, idx, 'write', acCtx):
            raise error.NotWritableError(idx=idx, name=name)

class MibScalarInstance(MibTree):
    """Scalar MIB variable instance. Implements read/write operations."""
    def __init__(self, typeName, instId, syntax):
        MibTree.__init__(self, typeName+instId, syntax)
        self.typeName = typeName
        self.instId = instId
        self.__oldSyntax = None
        
    def getNode(self, name, idx=None):
        # Recursion terminator
        if name == self.name:
            return self
        raise error.NoSuchInstanceError(idx=idx, name=name)

    def getNextNode(self, name, idx=None):
        raise error.NoSuchInstanceError(idx=idx, name=name)

    # MIB instrumentation methods
    
    # Read operation
    
    def readTest(self, name, val, idx, (acFun, acCtx)):
        if name != self.name:
            raise error.NoSuchObjectError(idx=idx, name=name)

    def readGet(self, name, val, idx, (acFun, acCtx)):
        # Return current variable (name, value). This is the only API method
        # capable of returning anything!
        if name == self.name:
            debug.logger & debug.flagIns and debug.logger('readGet: %s=%s' % (self.name, self.syntax))
            return self.name, self.syntax.clone()
        else:
            raise error.NoSuchObjectError(idx=idx, name=name)
    
    # Write operation: two-phase commit

    def writeTest(self, name, val, idx, (acFun, acCtx)):
        # Make sure write's allowed
        if name == self.name:
            if hasattr(self.syntax, 'smiWrite'):
                self.__newSyntax = self.syntax.smiWrite(name, val, idx)
            else:
                self.__newSyntax = self.syntax.clone(val)
            if hasattr(self.__newSyntax, 'smiRaisePendingError'):
                self.__newSyntax.smiRaisePendingError()
        else:
            raise error.NoSuchObjectError(idx=idx, name=name)

    def writeCommit(self, name, val, idx, (acFun, acCtx)):
        # Backup original value
        if self.__oldSyntax is None:
            self.__oldSyntax = self.syntax
        # Commit new value            
        self.syntax = self.__newSyntax
        
    def writeCleanup(self, name, val, idx, (acFun, acCtx)):
        debug.logger & debug.flagIns and debug.logger('writeCleanup: %s=%s' % (name, val))
        # Drop previous value
        self.__newSyntax = self.__oldSyntax = None
    
    def writeUndo(self, name, val, idx, (acFun, acCtx)):
        # Revive previous value
        self.syntax = self.__oldSyntax
        self.__newSyntax = self.__oldSyntax = None

    # Table column instance specifics

    # Create operation

    def createTest(self, name, val, idx, (acFun, acCtx)):
        if name == self.name:
            if hasattr(self.syntax, 'smiCreate'):
                self.__newSyntax = self.syntax.smiCreate(name, val, idx)
            else:
                self.__newSyntax = self.syntax.clone(val)
        else:
            raise error.NoSuchObjectError(idx=idx, name=name)
    def createCommit(self, name, val, idx, (acFun, acCtx)):
        if val is not None:
            self.writeCommit(name, val, idx, (acFun, acCtx))
    def createCleanup(self, name, val, idx, (acFun, acCtx)):
        debug.logger & debug.flagIns and debug.logger('createCleanup: %s=%s' % (name, val))
        if val is not None:
            self.writeCleanup(name, val, idx, (acFun, acCtx))
    def createUndo(self, name, val, idx, (acFun, acCtx)):
        if val is not None:
            self.writeCleanup(name, val, idx, (acFun, acCtx))

    # Destroy operation

    def destroyTest(self, name, val, idx, (acFun, acCtx)):
        if name == self.name:
            if hasattr(self.syntax, 'smiDestroy'):
                self.__newSyntax = self.syntax.smiDestoy(name, val)
            else:
                self.__newSyntax = self.syntax.clone(val)
        else:
            raise error.NoSuchObjectError(idx=idx, name=name)
    def destroyCommit(self, name, val, idx, (acFun, acCtx)): pass
    def destroyCleanup(self, name, val, idx, (acFun, acCtx)): pass
    def destroyUndo(self, name, val, idx, (acFun, acCtx)): pass

# Conceptual table classes

class MibTableColumn(MibScalar):
    """MIB table column. Manages a set of column instance variables"""
    protoInstance = MibScalarInstance
    def __init__(self, name, syntax):
        MibScalar.__init__(self, name, syntax)
        self.__createdInstances = {}; self.__destroyedInstances = {}
        self.__rowOpWanted = {}

    def getNode(self, name, idx=None):
        try:
            return MibScalar.getNode(self, name, idx=None)
        except error.NoSuchObjectError:
            raise error.NoSuchInstanceError(idx=idx, name=name)

    def getNextNode(self, name, idx=None):
        try:
            return MibScalar.getNextNode(self, name, idx=None)
        except error.NoSuchObjectError:
            raise error.NoSuchInstanceError(idx=idx, name=name)

    def setProtoInstance(self, protoInstance):
        self.protoInstance = protoInstance

    # Column creation (this should probably be converted into some state
    # machine for clarity). Also, it might be a good idea to inidicate
    # defaulted cols creation in a clearer way than just a val == None.
    
    def createTest(self, name, val, idx, (acFun, acCtx)):
        # Make sure creation allowed, create a new column instance but
        # do not replace the old one
        if name == self.name:
            raise error.NoAccessError(idx=idx, name=name)
        if acFun and \
               val is not None and \
               self.maxAccess != 'readcreate' or \
               acFun and acFun(name, idx, 'write', acCtx):
            raise error.NoCreationError(idx=idx, name=name)
        # Create instances if either it does not yet exist (row creation)
        # or a value is passed (multiple OIDs in SET PDU)
        if val is None and self.__createdInstances.has_key(name):
            return
        self.__createdInstances[name] = self.protoInstance(
            self.name, name[len(self.name):], self.syntax.clone()
            )
        self.__createdInstances[name].createTest(
            name, val, idx, (acFun, acCtx)
            )
            
    def createCommit(self, name, val, idx, (acFun, acCtx)):
        # Commit new instance value
        if self._vars.has_key(name): # XXX
            if self.__createdInstances.has_key(name):
                self._vars[name].createCommit(name, val, idx, (acFun, acCtx))
            return
        self.__createdInstances[name].createCommit(
            name, val, idx, (acFun, acCtx)
            )
        # ...commit new column instance
        self._vars[name], self.__createdInstances[name] = \
                          self.__createdInstances[name], self._vars.get(name)

    def createCleanup(self, name, val, idx, (acFun, acCtx)):
        # Drop previous column instance
        if self.__createdInstances.has_key(name):
            if self.__createdInstances[name] is not None:
                self.__createdInstances[name].createCleanup(
                    name, val, idx, (acFun, acCtx)
                    )
            del self.__createdInstances[name]
        elif self._vars.has_key(name):
            self._vars[name].createCleanup(name, val, idx, (acFun, acCtx))

    def createUndo(self, name, val, idx, (acFun, acCtx)):
        # Set back previous column instance, drop the new one
        if self.__createdInstances.has_key(name):
            self._vars[name] = self.__createdInstances[name]
            del self.__createdInstances[name]            
            # Remove new instance on rollback
            if self._vars[name] is None:
                del self._vars[name]
            else:
                self._vars[name].createUndo(name, val, idx, (acFun, acCtx))
                
    # Column destruction
        
    def destroyTest(self, name, val, idx, (acFun, acCtx)):
        # Make sure destruction is allowed
        if name == self.name:
            raise error.NoAccessError(idx=idx, name=name)        
        if not self._vars.has_key(name):
            return
        if acFun and \
               val is not None and \
               self.maxAccess != 'readcreate' or \
               acFun and acFun(name, idx, 'write', acCtx):
            raise error.NoAccessError(idx=idx, name=name)
        self._vars[name].destroyTest(
            name, val, idx, (acFun, acCtx)
            )

    def destroyCommit(self, name, val, idx, (acFun, acCtx)):
        # Make a copy of column instance and take it off the tree
        if self._vars.has_key(name):
            self._vars[name].destroyCommit(
                name, val, idx, (acFun, acCtx)
                )            
            self.__destroyedInstances[name] = self._vars[name]
            del self._vars[name]
        
    def destroyCleanup(self, name, val, idx, (acFun, acCtx)):
        # Drop instance copy
        if self.__destroyedInstances.has_key(name):
            self.__destroyedInstances[name].destroyCleanup(
                name, val, idx, (acFun, acCtx)
                )
            debug.logger & debug.flagIns and debug.logger('destroyCleanup: %s=%s' % (name, val))
            del self.__destroyedInstances[name]
            
    def destroyUndo(self, name, val, idx, (acFun, acCtx)):
        # Set back column instance
        if self.__destroyedInstances.has_key(name):
            self._vars[name] = self.__destroyedInstances[name]
            self._vars[name].destroyUndo(
                name, val, idx, (acFun, acCtx)
                )            
            del self.__destroyedInstances[name]
            
    # Set/modify column

    def writeTest(self, name, val, idx, (acFun, acCtx)):
        # Besides common checks, request row creation on no-instance
        try:
            # First try the instance
            MibScalar.writeTest(
                self, name, val, idx, (acFun, acCtx)
                )
        # ...otherwise proceed with creating new column
        except (error.NoSuchObjectError, error.RowCreationWanted):
            self.__rowOpWanted[name] = error.RowCreationWanted()
            self.createTest(name, val, idx, (acFun, acCtx))
        except error.RowDestructionWanted:
            self.__rowOpWanted[name] = error.RowDestructionWanted()
            self.destroyTest(name, val, idx, (acFun, acCtx))
        if self.__rowOpWanted.has_key(name):
            debug.logger & debug.flagIns and debug.logger('%s flagged by %s=%s' % (self.__rowOpWanted[name], name, val))
            raise self.__rowOpWanted[name]

    def __delegateWrite(self, subAction, name, val, idx, (acFun, acCtx)):
        if not self.__rowOpWanted.has_key(name):
            getattr(MibScalar, 'write'+subAction)(
                self, name, val, idx, (acFun, acCtx)
                )
            return
        if isinstance(self.__rowOpWanted[name], error.RowCreationWanted):
            getattr(self, 'create'+subAction)(
                name, val, idx, (acFun, acCtx)
                )
        if isinstance(self.__rowOpWanted[name], error.RowDestructionWanted):
            getattr(self, 'destroy'+subAction)(
                name, val, idx, (acFun, acCtx)
                )
        
    def writeCommit(self, name, val, idx, (acFun, acCtx)):
        self.__delegateWrite(
            'Commit', name, val, idx, (acFun, acCtx)
            )
        if self.__rowOpWanted.has_key(name):
            raise self.__rowOpWanted[name]

    def writeCleanup(self, name, val, idx, (acFun, acCtx)):
        self.__delegateWrite(
            'Cleanup', name, val, idx, (acFun, acCtx)
            )
        if self.__rowOpWanted.has_key(name):
            e = self.__rowOpWanted[name]
            del self.__rowOpWanted[name]
            debug.logger & debug.flagIns and debug.logger('%s dropped by %s=%s' % (e, name, val))
            raise e
            
    def writeUndo(self, name, val, idx, (acFun, acCtx)):
        self.__delegateWrite(
            'Undo', name, val, idx, (acFun, acCtx)
            )
        if self.__rowOpWanted.has_key(name):
            e = self.__rowOpWanted[name]
            del self.__rowOpWanted[name]
            debug.logger & debug.flagIns and debug.logger('%s dropped by %s=%s' % (e, name, val))
            raise e

class MibTableRow(MibTree):
    """MIB table row (SMI 'Entry'). Manages a set of table columns.
       Implements row creation/destruction.
    """
    def __init__(self, name):
        MibTree.__init__(self, name)
        self.indexNames = ()
        self.augmentingRows = {}

    # Table indices resolution. Handle almost all possible rfc1902 types
    # explicitly rather than by means of isSuperTypeOf() method because
    # some subtypes may be implicitly tagged what renders base tag
    # unavailable.

    __intValue = Integer()
    __counter32Value = Counter32()
    __uint32Value = Unsigned32()
    __timeticksValue = TimeTicks()
    __counter64Value = Counter64()
    __strValue = OctetString()
    __oidValue = ObjectIdentifier()
    __ipaddrValue = IpAddress()
    __bitsValue = Bits()

    def setFromName(self, obj, value, impliedFlag=None):
        if not value:
            raise error.SmiError('Short OID for index %s' % repr(obj))
        if self.__intValue.isSuperTypeOf(obj) or \
               self.__uint32Value.isSuperTypeOf(obj) or \
               self.__timeticksValue.isSuperTypeOf(obj) or \
               self.__counter32Value.isSuperTypeOf(obj) or \
               self.__counter64Value.isSuperTypeOf(obj):
            return obj.clone(value[0]), value[1:]
        elif self.__ipaddrValue.isSuperTypeOf(obj):
            return obj.clone(string.join(map(str, value[:4]), '.')), value[4:]
        elif self.__strValue.isSuperTypeOf(obj):
            # rfc1902, 7.7
            if impliedFlag: 
                s = reduce(lambda x,y: x+y, map(lambda x: chr(x), value))
                return obj.clone(s), ()                
            elif obj.isFixedLength():
                len = obj.getFixedLength()
                s = reduce(lambda x,y: x+y, map(lambda x: chr(x), value[:len]))
                return obj.clone(s), value[len:]
            else:
                s = reduce(lambda x,y: x+y,
                           map(lambda x: chr(x), value[1:value[0]+1]), '')
                return obj.clone(s), value[value[0]+1:]
        elif self.__oidValue.isSuperTypeOf(obj):
            if impliedFlag:
                return obj.clone(value), ()
            else:
                return obj.clone(value[1:value[0]+1]), value[value[0]+1:]
        # rfc2578, 7.1
        elif self.__bitsValue.isSuperTypeOf(obj):
            s = reduce(
                lambda x,y: x+y, map(lambda x: chr(x),value[1:value[0]+1]),''
                )
            return obj.clone(s), value[value[0]+1:]
        else:
            raise error.SmiError('Unknown value type for index %s' % repr(obj))

    def getAsName(self, obj, impliedFlag=None):
        if self.__intValue.isSuperTypeOf(obj) or \
               self.__uint32Value.isSuperTypeOf(obj) or \
               self.__timeticksValue.isSuperTypeOf(obj) or \
               self.__counter32Value.isSuperTypeOf(obj) or \
               self.__counter64Value.isSuperTypeOf(obj):
            return (int(obj),)
        elif self.__ipaddrValue.isSuperTypeOf(obj):
            return tuple(map(ord, obj))
        elif self.__strValue.isSuperTypeOf(obj):
            if impliedFlag or obj.isFixedLength():
                initial = ()
            else:
                initial = (len(obj),)
            return reduce(
                lambda x,y: x+(y,), map(lambda x: ord(x), obj), initial
                )
        elif self.__oidValue.isSuperTypeOf(obj):
            if impliedFlag:
                return tuple(obj)
            else:
                return (len(self.name),) + tuple(obj)
        # rfc2578, 7.1
        elif self.__bitsValue.isSuperTypeOf(obj):
            return reduce(
                lambda x,y: x+(y,), map(lambda x: ord(x), obj),(len(obj),) 
                )
        else:
            raise error.SmiError('Unknown value type for index %s' % repr(obj))
            
    # Fate sharing mechanics

    def announceManagementEvent(self, action, name, val, idx, (acFun, acCtx)):
        # Convert OID suffix into index vals
        instId = name[len(self.name)+1:]
        baseIndices = []
        for impliedFlag, modName, symName in self.indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            syntax, instId = self.setFromName(
                mibObj.syntax, instId, impliedFlag
                )
            if self.name == mibObj.name[:-1]:
                baseIndices.append((mibObj.name, syntax))
        if instId:
            raise error.SmiError(
                'Excessive instance identifier sub-OIDs left at %s: %s' %
                (self, instId)
                )
        if not baseIndices:
            return
        for modName, mibSym in self.augmentingRows.keys():
            mibObj, = mibBuilder.importSymbols(modName, mibSym)
            debug.logger & debug.flagIns and debug.logger('announceManagementEvent %s to %s' % (action, mibObj))
            mibObj.receiveManagementEvent(
                action, baseIndices, val, idx, (acFun, acCtx)
                )
            
    def receiveManagementEvent(
        self, action, baseIndices, val, idx, (acFun, acCtx)
        ):
        # The default implementation supports one-to-one rows dependency
        newSuffix = ()
        # Resolve indices intersection
        for impliedFlag, modName, symName in self.indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            for name, syntax in baseIndices:
                if name == mibObj.name:
                    newSuffix = newSuffix + self.getAsName(syntax, impliedFlag)
        if newSuffix:
            debug.logger & debug.flagIns and debug.logger('receiveManagementEvent %s for suffix %s' % (action, newSuffix))
            self.__manageColumns(action, (), newSuffix, val, idx,
                                 (acFun, acCtx))

    def registerAugmentions(self, *names):
        for modName, symName in names:
            if self.augmentingRows.has_key((modName, symName)):
                raise error.SmiError(
                    'Row %s already augmented by %s::%s' % \
                    (self.name, modName, symName)
                    )
            self.augmentingRows[(modName, symName)] = 1
        return self
        
    def setIndexNames(self, *names):
        for name in names:
            self.indexNames = self.indexNames + (name,)
        return self

    def getIndexNames(self):
        return self.indexNames
                             
    def __manageColumns(self, action, excludeName, nameSuffix,
                        val, idx, (acFun, acCtx)):
        # Build a map of index names and values for automatic initialization
        indexVals = {}; instId = nameSuffix
        for impliedFlag, modName, symName in self.indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            syntax, instId = self.setFromName(
                mibObj.syntax, instId, impliedFlag
                )
            indexVals[mibObj.name] = syntax
        for name, var in self._vars.items():
            if name == excludeName:
                continue
            if indexVals.has_key(name):
                getattr(var, action)(name + nameSuffix, indexVals[name], idx,
                                     (None, None))
            else:
                getattr(var, action)(name + nameSuffix, val, idx,
                                     (acFun, acCtx))
            debug.logger & debug.flagIns and debug.logger('__manageColumns: action %s name %s suffix %s %svalue %s' % (action, name, nameSuffix, indexVals.has_key(name) and "index " or "", indexVals.get(name, val)))

    def __delegate(self, subAction, name, val, idx, (acFun, acCtx)):
        # Relay operation request to column, expect row operation request.
        try:
            getattr(self.getBranch(name, idx), 'write'+subAction)(
                name, val, idx, (acFun, acCtx)
                )
        except error.RowCreationWanted, why:
            self.__manageColumns(
                'create'+subAction, name[:len(self.name)+1],
                name[len(self.name)+1:], None, idx, (acFun, acCtx)
                )
            self.announceManagementEvent(
                'create'+subAction, name, None, idx, (acFun, acCtx)
                )
        except error.RowDestructionWanted, why:
            self.__manageColumns(
                'destroy'+subAction, name[:len(self.name)+1],
                name[len(self.name)+1:], None, idx, (acFun, acCtx)
                )
            self.announceManagementEvent(
                'destroy'+subAction, name, None, idx, (acFun,acCtx)
                )
    
    def writeTest(self, name, val, idx, (acFun, acCtx)):
        self.__delegate('Test', name, val, idx, (acFun, acCtx))
    def writeCommit(self, name, val, idx, (acFun, acCtx)):
        self.__delegate('Commit', name, val, idx, (acFun, acCtx))
    def writeCleanup(self, name, val, idx, (acFun, acCtx)):
        self.__delegate('Cleanup', name, val, idx, (acFun, acCtx))
    def writeUndo(self, name, val,  idx, (acFun, acCtx)):
        self.__delegate('Undo', name, val, idx, (acFun, acCtx))

    # Table row management
    
    # Table row access by instance name

    def getInstName(self, colId, instId):
        return self.name + (colId,) + instId

    # Table index management

    def getIndicesFromInstId(self, instId):
        """Return index values for instance identification"""
        indices = []
        for impliedFlag, modName, symName in self.indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            syntax, instId = self.setFromName(mibObj.syntax, instId, impliedFlag)
            indices.append(syntax) # to avoid cyclic refs
        if instId:
            raise error.SmiError(
                'Excessive instance identifier sub-OIDs left at %s: %s' %
                (self, instId)
                )
        return tuple(indices)

    def getInstIdFromIndices(self, *indices):
        """Return column instance identification from indices"""
        idx = 0; instId = ()
        for impliedFlag, modName, symName in self.indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            if idx < len(indices):
                instId = instId + self.getAsName(
                    mibObj.syntax.clone(indices[idx]),
                    impliedFlag
                    )
            else:
                break
            idx = idx + 1
        return instId

    # Table access by index
    
    def getInstNameByIndex(self, colId, *indices):
        """Build column instance name from components"""
        return self.name + (colId,) + apply(
            self.getInstIdFromIndices, indices
            )

    def getInstNamesByIndex(self, *indices):
        """Build column instance names from indices"""
        instNames = []
        for columnName in self._vars.keys():
            instNames.append(
                apply(self.getInstNameByIndex,
                      (columnName[-1],) + indices)
                )
        return tuple(instNames)
    
class MibTable(MibTree):
    """MIB table. Manages a set of TableRow's"""
    def __init__(self, name):
        MibTree.__init__(self, name)
        
zeroDotZero = ObjectIdentity((0,0))

#dot = MibTree()
iso = MibTree((1,))
org = MibIdentifier(iso.name + (3,))
dod = MibIdentifier(org.name + (6,))
internet = MibIdentifier(dod.name + (1,))
directory = MibIdentifier(internet.name + (1,))
mgmt = MibIdentifier(internet.name + (2,))
mib_2 = MibIdentifier(mgmt.name + (1,)); mib_2.label = 'mib-2'
transmission = MibIdentifier(mib_2.name + (10,))
experimental = MibIdentifier(internet.name + (3,))
private = MibIdentifier(internet.name + (4,))
enterprises = MibIdentifier(private.name + (1,))
security = MibIdentifier(internet.name + (5,))
snmpV2 = MibIdentifier(internet.name + (6,))

snmpDomains = MibIdentifier(snmpV2.name + (1,))
snmpProxys = MibIdentifier(snmpV2.name +(2,))
snmpModules = MibIdentifier(snmpV2.name +(3,))

mibBuilder.exportSymbols(
    'SNMPv2-SMI', Integer32=Integer32, Bits=Bits, IpAddress=IpAddress,
    Counter32=Counter32,    Gauge32=Gauge32, Unsigned32=Unsigned32,
    TimeTicks=TimeTicks, Opaque=Opaque, Counter64=Counter64,
    ExtUTCTime=ExtUTCTime, MibNode=MibNode,
    ModuleIdentity=ModuleIdentity, ObjectIdentity=ObjectIdentity,
    NotificationType=NotificationType, MibScalar=MibScalar,
    MibScalarInstance=MibScalarInstance,
    MibIdentifier=MibIdentifier, MibTree=MibTree,
    MibTableColumn=MibTableColumn, MibTableRow=MibTableRow,
    MibTable=MibTable, zeroDotZero=zeroDotZero,
    iso=iso, org=org, dod=dod, internet=internet,
    directory=directory, mgmt=mgmt, mib_2=mib_2, transmission=transmission,
    experimental=experimental, private=private, enterprises=enterprises,
    security=security, snmpV2=snmpV2, snmpDomains=snmpDomains,
    snmpProxys=snmpProxys, snmpModules=snmpModules    
    )

# XXX
# getAsName/setFromName goes out of MibRow?
# revisit getNextNode() -- needs optimization
