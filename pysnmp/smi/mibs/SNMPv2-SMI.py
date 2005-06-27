from string import join, split
from pysnmp.smi.indices import OidOrderedDict
from pysnmp.smi import exval, error
from pysnmp.proto import rfc1902
from pyasn1.type import constraint
from pyasn1.error import ValueConstraintError

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

class MibNodeBase:
    def __init__(self, name=()):
        self.name = name
        self.label = ''
        
    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, self.name)

    def setName(self, name):
        self.name = name
        return self

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

class ModuleIdentity(MibNodeBase):
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
    def setRevisions(self, *args):
        self.revisions = args
        return self

class ObjectIdentity(MibNodeBase):
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

# definition for objects

class NotificationType(MibNodeBase):
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
    def setRevisions(self, *args):
        self.revisions = args
        return self

class MibIdentifier(MibNodeBase): pass

class ObjectTypePattern(MibNodeBase):
    maxAccess = None
    def getSyntax(self):
        return getattr(self, 'syntax', None)   # XXX
    def getSyntaxClone(self):
        # May be used to preserve backend instrumentation settings
        # whenever SNMP engine shares the same MIB for manager & agent roles
        if hasattr(self, 'syntaxClone'):
            return self.syntaxClone
        self.syntaxClone = self.getSyntax()
        if self.syntaxClone is not None:
            self.syntaxClone = self.syntaxClone.clone()
        return self.syntaxClone
    def setSyntax(self, v):
        self.syntax = v
        return self
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

class MibVariable(ObjectTypePattern):
    """Scalar MIB variable instance. Implements read/write operations."""
    maxAccess = 'readonly'
    def __init__(self, name=None, syntax=None):
        ObjectTypePattern.__init__(self, name)
        if syntax is not None:
            self.setSyntax(syntax)
        self.__newValue = None
        
    def __repr__(self):
        return '%s(%s, %s)' % (
            self.__class__.__name__, self.name, self.syntax
            )

    def __cmp__(self, other): return cmp(self.syntax, other)
    
    def clone(self, name=None, syntax=None):
        myClone = ObjectTypePattern.clone(self, name)
        myClone.maxAccess = self.maxAccess
        # XXX constr checking on initialisation
        if syntax is not None:
            myClone.syntax = syntax
        elif self.syntax is not None:
            # XXX clone the rest of attrs
            myClone.syntax = self.syntax.clone()
        return myClone

    def getNode(self, name, idx=None):
        # Recursion terminator
        if name == self.name:
            return self
        raise error.NoSuchInstanceError(idx=idx, name=name)

    def getNextNode(self, name, idx=None):
        # Recursion terminator
        raise error.NoSuchInstanceError(idx=idx, name=name)

    # MIB instrumentation methods
    
    # Read operation
    
    def readTest(self, name, val, idx, (acFun, acCtx)):
        if name == self.name:
            if self.maxAccess != 'readonly' and \
               self.maxAccess != 'readwrite' and \
               self.maxAccess != 'readcreate' or \
               acFun and acFun(name, idx, 'read', acCtx):
                raise error.NoAccessError(idx=idx, name=name)
        # missing object's not an error here
#        else:
#            raise error.NoSuchInstanceError(idx=idx, name=name)
    
    def readGet(self, name, val, idx, (acFun, acCtx)):
        # Return current variable (name, value). This is the only API method
        # capable of returning anything!
        if name == self.name:
            return self.name, self.syntax.clone()
        else:
            return name, exval.noSuchInstance
    
    # Two-phase commit implementation

    def writeTest(self, name, val, idx, (acFun, acCtx)):
        # Make sure write's allowed
        if name == self.name:
            # make sure variable is writable
            if self.maxAccess != 'readwrite' and \
               self.maxAccess != 'readcreate' or \
               acFun and acFun(name, idx, 'write', acCtx):
                raise error.NotWritableError(idx=idx, name=name)
        else:
            raise error.NoSuchInstanceError(idx=idx, name=name)
        self.__newSyntax = self.syntax.clone(val)

    def writeCommit(self, name, val, idx, (acFun, acCtx)):
        # Commit new value
        self.syntax, self.__newSyntax = self.__newSyntax, self.syntax
        
    def writeCleanup(self, name, val, idx, (acFun, acCtx)):
        # Drop previous value
        self.__newSyntax = None
    
    def writeUndo(self, name, val, idx, (acFun, acCtx)):
        # Revive previous value
        self.syntax, self.__newSyntax = self.__newSyntax, None

class MibTree(ObjectTypePattern):
    branchVersionId = 0L    # increments on tree structure change XXX
    defaultVars = None
    maxAccess = 'not-accessible'
    def __init__(self, name=None, *vars):
        ObjectTypePattern.__init__(self, name)
        self._vars = OidOrderedDict()            
        if vars:
            apply(self.registerSubtrees, vars)
        if self.defaultVars:
            apply(self.registerSubtrees,
                  map(lambda x: x.clone(), self.defaultVars)
                  )

    # Subtrees registration
    
    def registerSubtrees(self, *subTrees):
        """Register subtrees at this tree. Subtrees are always attached
           at the level of this tree, not subtrees."""
        for subTree in subTrees:
            if self._vars.has_key(subTree.name):
                continue
# XXX complain?
#                 if self._vars[subTree.name] is subTree:
#                     continue
#                 raise error.SmiError(
#                     'MIB subtree %s already registered %s' % \
#                     (subTree.name, self)
#                     )
            self._vars[subTree.name] = subTree
            MibTree.branchVersionId = MibTree.branchVersionId + 1

    def unregisterSubtrees(self, *subTrees):
        """Detach subtrees from this tree"""
        for subTree in subTrees:
            if self._vars.has_key(subTree.name):
                del self._vars[subTree.name]
                MibTree.branchVersionId = MibTree.branchVersionId + 1

    # Tree traversal

    def getBranch(self, name, idx):
        """Return a branch of this tree where the 'name' OID may reside"""
        subName = tuple(name)
        subNameLen = len(self.name)
        while subNameLen < len(subName):
            if self._vars.has_key(subName):
                return self._vars[subName]
            subName = subName[:-1]
        else:
            raise error.NoSuchInstanceError(name=name, idx=idx)

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
        except error.NoSuchInstanceError:
            # Start from the beginning
            if self._vars and name <= self._vars.keys()[0]:
                return self._vars[self._vars.keys()[0]]
            else:
                # Try following the white rabbit at our level
                try:
                    return self._vars[self._vars.nextKey(name)]
                except KeyError:
                    raise error.NoSuchInstanceError(idx=idx, name=name)
        else:
            try:
                return nextNode.getNextNode(name, idx)
            except error.NoSuchInstanceError:
                try:
                    return self._vars[self._vars.nextKey(nextNode.name)]
                except KeyError:
                    raise error.NoSuchInstanceError(idx=idx, name=name)
                
    # Mapping interface to subtree XXX
    
#    def get(self, key, defVal=None): return self._vars.get(key, defVal)
#    def keys(self): return self._vars.keys()
    
    # MIB instrumentation

    # Read operation
    
    def readTest(self, name, val, idx, (acFun, acCtx)):
        if name == self.name:
            if self.maxAccess != 'readonly' and \
                   self.maxAccess != 'readwrite' and \
                   self.maxAccess != 'readcreate' or \
                   acFun and acFun(name, idx, 'read', acCtx):
                raise error.NoAccessError(idx=idx, name=name)
        else:
            try:
                node = self.getBranch(name, idx)
            except error.NoSuchInstanceError:
                return # missing object is not an error here

            node.readTest(name, val, idx, (acFun, acCtx))
        
    def readGet(self, name, val, idx, (acFun, acCtx)):
        try:
            node = self.getBranch(name, idx)
        except error.NoSuchInstanceError:
            return name, exval.noSuchInstance
        else:
            return node.readGet(name, val, idx, (acFun, acCtx))

    # Read next operation is subtree-specific
    
    def readTestNext(self, name, val, idx, (acFun, acCtx)):
        nextName = name
        while 1:  # XXX linear search here
            try:
                nextName = self.getNextNode(nextName, idx).name
            except error.NoSuchInstanceError:
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
            except error.NoSuchInstanceError:
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
            if self.maxAccess != 'readwrite' and \
                   self.maxAccess != 'readcreate' or \
                   acFun and acFun(name, idx, 'write', acCtx):
                raise error.NotWritableError(idx=idx, name=name)
        else:
            node = self.getBranch(name, idx)
# XXX
#            if not isinstance(node, ObjectTypePattern): # XXX
#                raise error.NoAccessError(
#                    'Not ObjectType macro instance at %s' % self
#                    )
            node.writeTest(name, val, idx, (acFun, acCtx))
    
    def writeCommit(self, name, val, idx, (acFun, acCtx)):
        self.getBranch(name, idx).writeCommit(name, val, idx, (acFun, acCtx))
    
    def writeCleanup(self, name, val, idx, (acFun, acCtx)):
        self.getBranch(name, idx).writeCleanup(name, val, idx, (acFun, acCtx))
    
    def writeUndo(self, name, val, idx, (acFun, acCtx)):
        self.getBranch(name, idx).writeUndo(name, val, idx, (acFun, acCtx))

# Conceptual table classes

class MibTableColumn(MibTree):
    """MIB table column. Manages a set of column instance variables"""
    defaultColumnInitializer = None

    def __init__(self, name=None, *vars):
        apply(MibTree.__init__, (self, name) + vars)
        if self.defaultColumnInitializer is not None:
            self.setColumnInitializer(self.defaultColumnInitializer.clone())
        else:
            self.columnInitializer = None
        self.__createdInstances = {}; self.__destroyedInstances = {}
        self.__rowOpWanted = {}

    def setColumnInitializer(self, mibVar):
        self.columnInitializer = mibVar
        self.columnInitializer.name = self.name
        return self

    def getColumnInitializer(self):
        if self.columnInitializer is None:
            raise error.SmiError(
                'Uninitialized column syntax at %s' % (self)
                )
        return self.columnInitializer

    def getSyntax(self):
        if self.columnInitializer is not None:
            return getattr(self.columnInitializer, 'syntax', None)
        
    # Column creation (this should probably be converted into some state
    # machine for clarity). Also, it might be a good idea to inidicate
    # defaulted cols creation in a clearer way than just a val == None.
    
    def createTest(self, name, val, idx, (acFun, acCtx)):
        # Make sure creation allowed, create a new column instance but
        # do not replace the old one
        if self._vars.has_key(name):
            return
        if val is not None and \
               self.columnInitializer.maxAccess != 'readcreate' or \
               acFun and acFun(name, idx, 'write', acCtx):
            raise error.NoCreationError(idx=idx, name=name)
        if not self.__createdInstances.has_key(name):
            self.__createdInstances[name] = self.columnInitializer.clone(
                name
                )
        if val is not None:
            try:
                self.__createdInstances[name].writeTest(
                    name, val, idx, (acFun, acCtx)
                    )
            except (error.RowCreationWanted, error.RowDestructionWanted):
                pass
            
    def createCommit(self, name, val, idx, (acFun, acCtx)):
        # Commit new instance value
        if self._vars.has_key(name):
            if self.__createdInstances.has_key(name):
                if val is not None:
                    self._vars[name].writeCommit(
                        name, val, idx, (acFun, acCtx)
                        )
            return
        if val is not None:
            self.__createdInstances[name].writeCommit(
                name, val, idx, (acFun, acCtx)
                )
        # ...commit new column instance
        self._vars[name], self.__createdInstances[name] = \
                          self.__createdInstances[name], self._vars.get(name)

    def createCleanup(self, name, val, idx, (acFun, acCtx)):
        # Drop previous column instance
        if self.__createdInstances.has_key(name):
            if self.__createdInstances[name] is not None:
                self.__createdInstances[name].writeCleanup(
                    name, val, idx, (acFun, acCtx)
                    )
            del self.__createdInstances[name]
        elif self._vars.has_key(name):
            self._vars[name].writeCleanup(
                name, val, idx, (acFun, acCtx)
                )
        
    def createUndo(self, name, val, idx, (acFun, acCtx)):
        # Set back previous column instance, drop the new one
        if self.__createdInstances.has_key(name):
            self._vars[name] = self.__createdInstances[name]
            del self.__createdInstances[name]            
            # Remove new instance on rollback
            if self._vars[name] is None:
                del self._vars[name]
            else:
                self._vars[name].writeUndo(
                    name, val, idx, (acFun, acCtx)
                    )
                
    # Column destruction
        
    def destroyTest(self, name, val, idx, (acFun, acCtx)):
        # Make sure destruction is allowed
        if self._vars.has_key(name):
            if val is not None and \
                   self.columnInitializer.maxAccess != 'readcreate' or \
                   acFun and acFun(name, idx, 'write', cbCtx):
                raise error.NoAccessError(idx=idx, name=name)

    def destroyCommit(self, name, val, idx, (acFun, acCtx)):
        # Make a copy of column instance and take it off the tree
        if self._vars.has_key(name):
            self.__destroyedInstances[name] = self._vars[name]
            del self._vars[name]
        
    def destroyCleanup(self, name, val, idx, (acFun, acCtx)):
        # Drop instance copy
        if self.__destroyedInstances.has_key(name):
            del self.__destroyedInstances[name]
            
    def destroyUndo(self, name, val, idx, (acFun, acCtx)):
        # Set back column instance
        if self.__destroyedInstances.has_key(name):
            self._vars[name] = self.__destroyedInstances[name]
            del self.__destroyedInstances[name]
            
    # Set/modify column

    def writeTest(self, name, val, idx, (acFun, acCtx)):
        # Besides common checks, request row creation on no-instance
        try:
            # First try the instance
            MibTree.writeTest(self, name, val, idx, (acFun, acCtx))
        # ...otherwise proceed with creating new column
        except (error.NoSuchInstanceError, error.RowCreationWanted):
            self.__rowOpWanted[name] =  error.RowCreationWanted()
            self.createTest(name, val, idx, (acFun, acCtx))
        except error.RowDestructionWanted:
            self.__rowOpWanted[name] =  error.RowDestructionWanted()
            self.destroyTest(name, val, idx, (acFun, acCtx))
        if self.__rowOpWanted.has_key(name):
            raise self.__rowOpWanted[name]

    def __delegateWrite(self, subAction, name, val, idx, (acFun, acCtx)):
        if not self.__rowOpWanted.has_key(name):
            getattr(MibTree, 'write'+subAction)(
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
        raise self.__rowOpWanted[name]

    def writeCommit(self, name, val, idx, (acFun, acCtx)):
        self.__delegateWrite('Commit', name, val, idx, (acFun, acCtx))

    def writeCleanup(self, name, val, idx, (acFun, acCtx)):
        self.__delegateWrite('Cleanup', name, val, idx, (acFun, acCtx))
        if self.__rowOpWanted.has_key(name):
            del self.__rowOpWanted[name]
            
    def writeUndo(self, name, val, idx, (acFun, acCtx)):
        self.__delegateWrite('Undo', name, val, idx, (acFun, acCtx))
        if self.__rowOpWanted.has_key(name):
            del self.__rowOpWanted[name]

class MibTableRow(MibTree):
    """MIB table row (SMI 'Entry'). Manages a set of table columns.
       Implements row creation/destruction.
    """
    defaultIndexNames = None    # XXX indexNames ?
    
    def __init__(self, name=None, *vars):
        apply(MibTree.__init__, (self, name) + vars)
        if self.defaultIndexNames is not None:
            self.setIndexNames(self.defaultIndexNames)
        else:
            self.indexNames = ()
        self.augmentingRows = {}

    # Table indices resolution

    __intValue = Integer()
    __strValue = OctetString()
    __oidValue = ObjectIdentifier()
    __ipaddrValue = IpAddress()

    def setFromName(self, obj, value, impliedFlag=None):
        if self.__intValue.isSuperTypeOf(obj):
            return obj.clone(value[0]), value[1:]
        elif self.__ipaddrValue.isSuperTypeOf(obj):
            return obj.clone(join(map(str, value[:4]), '.')), value[4:]
        elif self.__strValue.isSuperTypeOf(obj):
            if impliedFlag:
                s = reduce(lambda x,y: x+y, map(lambda x: chr(x), value))
                return obj.clone(s), ()                
            else:
                s = reduce(lambda x,y: x+y,
                           map(lambda x: chr(x), value[1:value[0]+1]), '')
                return obj.clone(s), value[value[0]+1:]
        elif self.__oidValue.isSuperTypeOf(obj):
            if impliedFlag:
                return obj.clone(value), ()
            else:
                return obj.clone(value[1:value[0]+1]), value[value[0]+1:]
        else:
            raise error.SmiError('Unknown value type for index %s' % repr(obj))
#            return obj.clone(value), ()

    def getAsName(self, obj, impliedFlag=None):
        if self.__intValue.isSuperTypeOf(obj):
            return (int(obj),)
        elif self.__strValue.isSuperTypeOf(obj):
            if impliedFlag:
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
        elif self.__ipaddrValue.isSuperTypeOf(obj):
            return tuple(map(int, obj))
        else:
            raise error.SmiError('Unknown value type for index %s' % repr(obj))
#            return obj
            
    # Fate sharing mechanics

    def announceManagementEvent(self, action, name, val, idx, (acFun, acCtx)):
        # Convert OID suffix into index vals
        instId = name[len(self.name)+1:]
        baseIndices = []
        for impliedFlag, modName, symName in self.indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            syntax, instId = self.setFromName(
                mibObj.getColumnInitializer().syntax, instId, impliedFlag
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
            self.__manageColumns(action, newSuffix, val, idx, (acFun, acCtx))

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
                             
    def __manageColumns(self, action, nameSuffix, val, idx, (acFun, acCtx)):
        for name, var in self._vars.items():
            getattr(var, action)(name + nameSuffix, val, idx, (acFun, acCtx))

    def __delegate(self, subAction, name, val, idx, (acFun, acCtx)):
        # Relay operation request to column, expect row operation request.
        try:
            getattr(self.getBranch(name, idx), 'write'+subAction)(
                name, val, idx, (acFun, acCtx)
                )
        except error.RowCreationWanted, why:
            self.__manageColumns(
                'create'+subAction, name[len(self.name)+1:],
                None, idx, (acFun, acCtx)
                )
            self.announceManagementEvent(
                'create'+subAction, name, None, idx, (acFun, acCtx)
                )
        except error.RowDestructionWanted, why:
            self.__manageColumns(
                'destroy'+subAction, name[len(self.name)+1:],
                None, idx, (acFun, acCtx)
                )
            self.announceManagementEvent(
                'destroy'+subAction, name, None, idx, (acFun, acCtx)
                )
    
    def writeTest(self, name, val, idx, (acFun, acCtx)):
        self.__delegate('Test', name, val, idx, (acFun, acCtx))
    def writeCommit(self, name, val, idx, (acFun, acCtx)):
        self.__delegate('Commit', name, val, idx, (acFun, acCtx))
    def writeCleanup(self, name, val, idx, (acFun, acCtx)):
        self.__delegate('Cleanup', name, val, idx, (acFun, acCtx))
    def writeUndo(self, name, val, idx, (acFun, acCtx)):
        self.__delegate('Undo', name, val)

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
            val = mibObj.getColumnInitializer().syntax
            syntax, instId = self.setFromName(val, instId, impliedFlag)
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
                    mibObj.getColumnInitializer().syntax.clone(indices[idx]),
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
    ExtUTCTime=ExtUTCTime, MibNodeBase=MibNodeBase,
    ModuleIdentity=ModuleIdentity, ObjectIdentity=ObjectIdentity,
    NotificationType=NotificationType, MibVariable=MibVariable,
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
# maybe re-design tree scheme for clarity and less iters on tree walk?
# getAsName/setFromName goes out of MibRow?
# revisit getNextNode() & getBranch() -- these need optimization
# re-design MibVariable to be a subtree with a single leaf -- MibInstance;
#    MibColumn syntax is also MibVarInstance instead of ColInitializer
