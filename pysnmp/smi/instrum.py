# MIB modules management
from types import InstanceType
from pysnmp.smi import error

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
            
    # MIB indexing

    def __indexMib(self):
        # Build a tree from MIB objects found at currently loaded modules
        if self.lastBuildId == self.mibBuilder.lastBuildId:
            return

        MibVariable, = self.mibBuilder.importSymbols('SNMPv2-SMI', 'MibVariable')
        MibTree, = self.mibBuilder.importSymbols('SNMPv2-SMI', 'MibTree')
        MibTableRow, = self.mibBuilder.importSymbols('SNMPv2-SMI', 'MibTableRow')
        MibTableColumn, = self.mibBuilder.importSymbols(
            'SNMPv2-SMI', 'MibTableColumn'
            )

        mibTree, = self.mibBuilder.importSymbols('SNMPv2-SMI', 'iso')
        
        rows = {}; cols = {}
        
        for mibMod in self.mibBuilder.mibSymbols.values():
            for symObj in mibMod.values():
                if type(symObj) != InstanceType:
                    continue
                if symObj is mibTree:
                    continue
                if not isinstance(symObj, MibTree) and \
                       not isinstance(symObj, MibVariable):
                    continue                
                if isinstance(symObj, MibTableRow):
                    rows[symObj.name] = symObj
                elif isinstance(symObj, MibTableColumn):
                    cols[symObj.name] = symObj
                else:
                    mibTree.registerSubtrees(symObj)

        for colName, colObj in cols.items():
            rowName = colObj.name[:-1]
            if rows.has_key(rowName):
                rows[rowName].registerSubtrees(colObj)
            else:
                raise error.SmiError(
                    'Orphan MIB table column %s at %s' % (colName, self)
                    )
        for rowObj in rows.values():
            mibTree.registerSubtrees(rowObj)

        self.lastBuildId = self.mibBuilder.lastBuildId
        
    # MIB instrumentation
    
    def flipFlopFsm(self, fsmTable, *inputNameVals):
        self.__indexMib()
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
            state = fsmState
            if state == 'stop':
                break
            for name, val in inputNameVals:
                f = getattr(mibTree, state, None)
                if f is None:
                    raise error.SmiError(
                        'Unsupported state handler %s at %s' % (state, self)
                        )
                try:
                    rval = f(name, val)
                except error.MibVariableError, why:
                    if myErr is None:  # Take the first exception
                        myErr = why
                    status = 'err'
                    break
                else:
                    status = 'ok'
                    if rval is not None:
                        outputNameVals.append(rval)
        if myErr:
            raise myErr
        return outputNameVals
    
    def readVars(self, *vars):
        return apply(self.flipFlopFsm, (self.fsmReadVar,) + vars)
    
    def readNextVars(self, *vars):
        return apply(self.flipFlopFsm, (self.fsmReadNextVar,) + vars)
    
    def writeVars(self, *vars):
        return apply(self.flipFlopFsm, (self.fsmWriteVar,) + vars)
    
if __name__ == '__main__':
    from pysnmp.smi.builder import MibBuilder

    mibInstrum = MibInstrumController(MibBuilder().loadModules())

    print 'Remote manager access to MIB instrumentation (table walk)'

    name, val = (), None
    while 1:
        try:
            name, val = mibInstrum.readNextVars((name, val))[0]
        except error.NoSuchInstanceError:
            break
        print name, val
