# MIB modules management
from types import InstanceType
from pysnmp.smi import error
from pysnmp import debug

__all__ = [ 'MibInstrumController' ]

class MibInstrumController:
    fsmReadVar = {
        # ( state, status ) -> newState
        ('start', 'ok'): 'readTest',
        ('readTest', 'ok'): 'readGet',
        ('readGet', 'ok'): 'stop',
        ('*', 'err'): 'stop'
    }
    fsmReadNextVar = {
        # ( state, status ) -> newState
        ('start', 'ok'): 'readTestNext',
        ('readTestNext', 'ok'): 'readGetNext',
        ('readGetNext', 'ok'): 'stop',
        ('*', 'err'): 'stop'
    }
    fsmWriteVar = {
        # ( state, status ) -> newState
        ('start', 'ok'): 'writeTest',
        ('writeTest', 'ok'): 'writeCommit',
        ('writeCommit', 'ok'): 'writeCleanup',
        ('writeCleanup', 'ok'): 'readTest',
        # Do read after successful write
        ('readTest', 'ok'): 'readGet',
        ('readGet', 'ok'): 'stop',
        # Error handling
        ('writeTest', 'err'): 'writeCleanup',
        ('writeCommit', 'err'): 'writeUndo',
        ('writeUndo', 'ok'): 'readTest',
        # Ignore read errors (removed columns)
        ('readTest', 'err'): 'stop',
        ('readGet', 'err'): 'stop',
        ('*', 'err'): 'stop'
    }

    def __init__(self, mibBuilder):
        self.mibBuilder = mibBuilder
        self.lastBuildId = -1
        self.lastBuildSyms = {}
            
    # MIB indexing

    def __indexMib(self):
        # Build a tree from MIB objects found at currently loaded modules
        if self.lastBuildId == self.mibBuilder.lastBuildId:
            return

        ( MibScalarInstance,
          MibScalar,
          MibTableColumn,
          MibTableRow,
          MibTable,
          MibTree ) = self.mibBuilder.importSymbols(
            'SNMPv2-SMI',
            'MibScalarInstance',
            'MibScalar',
            'MibTableColumn',
            'MibTableRow',
            'MibTable',
            'MibTree'
            )
            
        mibTree, = self.mibBuilder.importSymbols('SNMPv2-SMI', 'iso')

        #
        # Management Instrumentation gets organized as follows:
        #
        # MibTree
        #   |
        #   +----MibScalar
        #   |        |
        #   |        +-----MibScalarInstance
        #   |
        #   +----MibTable
        #   |
        #   +----MibTableRow
        #          |
        #          +-------MibTableColumn
        #                        |
        #                        +------MibScalarInstance(s)
        #
        # Mind you, only Managed Objects get indexed here, various MIB defs and
        # constants can't be SNMP managed so we drop them.
        #
        scalars = {}; instances = {}; tables = {}; rows = {}; cols = {}

        # Sort by module name to give user a chance to slip-in
        # custom MIB modules (that would be sorted out first)
        mibSymbols = self.mibBuilder.mibSymbols.items()
        mibSymbols.sort(lambda x,y: cmp(y[0], x[0]))
        
        for modName, mibMod in mibSymbols:
            for symObj in mibMod.values():
                if type(symObj) != InstanceType:
                    continue
                if isinstance(symObj, MibTable):
                    tables[symObj.name] = symObj
                elif isinstance(symObj, MibTableRow):
                    rows[symObj.name] = symObj
                elif isinstance(symObj, MibTableColumn):
                    cols[symObj.name] = symObj
                elif isinstance(symObj, MibScalarInstance):
                    instances[symObj.name] = symObj
                elif isinstance(symObj, MibScalar):
                    scalars[symObj.name] = symObj

        # Detach items from each other
        for symName, parentName in self.lastBuildSyms.items():
            if scalars.has_key(parentName):
                scalars[parentName].unregisterSubtrees(symName)
            elif cols.has_key(parentName):
                cols[parentName].unregisterSubtrees(symName)
            elif rows.has_key(parentName):
                rows[parentName].unregisterSubtrees(symName)
            else:
                mibTree.unregisterSubtrees(symName)
                
        lastBuildSyms = {}
        
        # Attach Managed Objects Instances to Managed Objects
        for inst in instances.values():
            if scalars.has_key(inst.typeName):
                scalars[inst.typeName].registerSubtrees(inst)
            elif cols.has_key(inst.typeName):
                cols[inst.typeName].registerSubtrees(inst)
            else:
                raise error.SmiError(
                    'Orphan MIB scalar instance %s at %s' % (inst, self)
                    )
            lastBuildSyms[inst.name] = inst.typeName

        # Attach Table Columns to Table Rows
        for col in cols.values():
            rowName = col.name[:-1] # XXX
            if rows.has_key(rowName):
                rows[rowName].registerSubtrees(col)
            else:
                raise error.SmiError(
                    'Orphan MIB table column %s at %s' % (col, self)
                    )
            lastBuildSyms[col.name] = rowName
            
        # Attach Table Rows to MIB tree
        for row in rows.values():
            mibTree.registerSubtrees(row)
            lastBuildSyms[row.name] = mibTree.name

        # Attach Tables to MIB tree
        for table in tables.values():
            mibTree.registerSubtrees(table)
            lastBuildSyms[table.name] = mibTree.name
            
        # Attach Scalars to MIB tree
        for scalar in scalars.values():
            mibTree.registerSubtrees(scalar)
            lastBuildSyms[scalar.name] = mibTree.name

        self.lastBuildSyms = lastBuildSyms
        
        self.lastBuildId = self.mibBuilder.lastBuildId
        
        debug.logger & debug.flagIns and debug.logger('__indexMib: rebuilt')
        
    # MIB instrumentation
    
    def flipFlopFsm(self, fsmTable, inputNameVals, (acFun, acCtx)):
        self.__indexMib()
        debug.logger & debug.flagIns and debug.logger('flipFlopFsm: inputNameVals %s' % (inputNameVals,))
        mibTree, = self.mibBuilder.importSymbols('SNMPv2-SMI', 'iso')
        outputNameVals = []
        state, status = 'start', 'ok'
        myErr = None
        while 1:
            fsmState = fsmTable.get((state, status))
            if fsmState is None:
                fsmState = fsmTable.get(('*', status))
                if fsmState is None:
                    raise error.SmiError(
                        'Unresolved FSM state %s, %s' % (state, status)
                        )
            debug.logger & debug.flagIns and debug.logger('flipFlopFsm: state %s status %s -> fsmState %s' % (state, status, fsmState))
            state = fsmState
            status = 'ok'
            if state == 'stop':
                break
            idx = 0
            for name, val in inputNameVals:
                f = getattr(mibTree, state, None)
                if f is None:
                    raise error.SmiError(
                        'Unsupported state handler %s at %s' % (state, self)
                        )
                try:
                    # Convert to tuple to avoid ObjectName instantiation
                    # on subscription
                    rval = f(tuple(name), val, idx, (acFun, acCtx))
                except error.SmiError, why:
                    debug.logger & debug.flagIns and debug.logger('flipFlopFsm: fun %s failed %s for %s=%s' % (f, why, name, val))
                    if myErr is None:  # Take the first exception
                        myErr = why
                    status = 'err'
                    break
                else:
                    debug.logger & debug.flagIns and debug.logger('flipFlopFsm: fun %s suceeded for %s=%s' % (f, name, val))                    
                    if rval is not None:
                        outputNameVals.append((rval[0], rval[1]))
                idx = idx + 1
        if myErr:
            raise myErr
        return outputNameVals
    
    def readVars(self, vars, (acFun, acCtx)=(None, None)):
        return self.flipFlopFsm(self.fsmReadVar, vars, (acFun, acCtx))
    def readNextVars(self, vars, (acFun, acCtx)=(None, None)):
        return self.flipFlopFsm(self.fsmReadNextVar, vars, (acFun, acCtx))
    def writeVars(self, vars, (acFun, acCtx)=(None, None)):
        return self.flipFlopFsm(self.fsmWriteVar, vars, (acFun, acCtx))
