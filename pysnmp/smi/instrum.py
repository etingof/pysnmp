#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import sys
import traceback
import functools
from pysnmp import nextid
from pysnmp.smi import error
from pysnmp import debug

__all__ = ['AbstractMibInstrumController', 'MibInstrumController']


class AbstractMibInstrumController(object):
    def readVars(self, *varBinds, **context):
        raise error.NoSuchInstanceError(idx=0)

    def readNextVars(self, *varBinds, **context):
        raise error.EndOfMibViewError(idx=0)

    def writeVars(self, *varBinds, **context):
        raise error.NoSuchObjectError(idx=0)


class MibInstrumController(AbstractMibInstrumController):
    STATUS_OK = 'ok'
    STATUS_ERROR = 'err'
    
    STATE_START = 'start'
    STATE_STOP = 'stop'
    STATE_ANY = '*'
    # These states are actually methods of the MIB objects
    STATE_READ_TEST = 'readTest'
    STATE_READ_GET = 'readGet'
    STATE_READ_TEST_NEXT = 'readTestNext'
    STATE_READ_GET_NEXT = 'readGetNext'
    STATE_WRITE_TEST = 'writeTest'
    STATE_WRITE_COMMIT = 'writeCommit'
    STATE_WRITE_CLEANUP = 'writeCleanup'
    STATE_WRITE_UNDO = 'writeUndo'

    fsmReadVar = {
        # ( state, status ) -> newState
        (STATE_START, STATUS_OK): STATE_READ_TEST,
        (STATE_READ_TEST, STATUS_OK): STATE_READ_GET,
        (STATE_READ_GET, STATUS_OK): STATE_STOP,
        (STATE_ANY, STATUS_ERROR): STATE_STOP
    }
    fsmReadNextVar = {
        # ( state, status ) -> newState
        (STATE_START, STATUS_OK): STATE_READ_TEST_NEXT,
        (STATE_READ_TEST_NEXT, STATUS_OK): STATE_READ_GET_NEXT,
        (STATE_READ_GET_NEXT, STATUS_OK): STATE_STOP,
        (STATE_ANY, STATUS_ERROR): STATE_STOP
    }
    fsmWriteVar = {
        # ( state, status ) -> newState
        (STATE_START, STATUS_OK): STATE_WRITE_TEST,
        (STATE_WRITE_TEST, STATUS_OK): STATE_WRITE_COMMIT,
        (STATE_WRITE_COMMIT, STATUS_OK): STATE_WRITE_CLEANUP,
        (STATE_WRITE_CLEANUP, STATUS_OK): STATE_READ_TEST,
        # Do read after successful write
        (STATE_READ_TEST, STATUS_OK): STATE_READ_GET,
        (STATE_READ_GET, STATUS_OK): STATE_STOP,
        # Error handling
        (STATE_WRITE_TEST, STATUS_ERROR): STATE_WRITE_CLEANUP,
        (STATE_WRITE_COMMIT, STATUS_ERROR): STATE_WRITE_UNDO,
        (STATE_WRITE_UNDO, STATUS_OK): STATE_READ_TEST,
        # Ignore read errors (removed columns)
        (STATE_READ_TEST, STATUS_ERROR): STATE_STOP,
        (STATE_READ_GET, STATUS_ERROR): STATE_STOP,
        (STATE_ANY, STATUS_ERROR): STATE_STOP
    }

    FSM_CONTEXT = '_fsmContext'

    FSM_SESSION_ID = nextid.Integer(0xffffffff)

    def __init__(self, mibBuilder):
        self.mibBuilder = mibBuilder
        self.lastBuildId = -1
        self.lastBuildSyms = {}

    def getMibBuilder(self):
        return self.mibBuilder

    # MIB indexing

    def __indexMib(self):
        # Build a tree from MIB objects found at currently loaded modules
        if self.lastBuildId == self.mibBuilder.lastBuildId:
            return

        (MibScalarInstance, MibScalar, MibTableColumn, MibTableRow,
         MibTable) = self.mibBuilder.importSymbols(
            'SNMPv2-SMI', 'MibScalarInstance', 'MibScalar',
            'MibTableColumn', 'MibTableRow', 'MibTable'
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
        scalars = {}
        instances = {}
        tables = {}
        rows = {}
        cols = {}

        # Sort by module name to give user a chance to slip-in
        # custom MIB modules (that would be sorted out first)
        mibSymbols = list(self.mibBuilder.mibSymbols.items())
        mibSymbols.sort(key=lambda x: x[0], reverse=True)

        for modName, mibMod in mibSymbols:
            for symObj in mibMod.values():
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
            if parentName in scalars:
                scalars[parentName].unregisterSubtrees(symName)
            elif parentName in cols:
                cols[parentName].unregisterSubtrees(symName)
            elif parentName in rows:
                rows[parentName].unregisterSubtrees(symName)
            else:
                mibTree.unregisterSubtrees(symName)

        lastBuildSyms = {}

        # Attach Managed Objects Instances to Managed Objects
        for inst in instances.values():
            if inst.typeName in scalars:
                scalars[inst.typeName].registerSubtrees(inst)
            elif inst.typeName in cols:
                cols[inst.typeName].registerSubtrees(inst)
            else:
                raise error.SmiError(
                    'Orphan MIB scalar instance %r at %r' % (inst, self)
                )
            lastBuildSyms[inst.name] = inst.typeName

        # Attach Table Columns to Table Rows
        for col in cols.values():
            rowName = col.name[:-1]  # XXX
            if rowName in rows:
                rows[rowName].registerSubtrees(col)
            else:
                raise error.SmiError(
                    'Orphan MIB table column %r at %r' % (col, self)
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

    def _flipFlopFsmCb(self, varBind, **context):
        fsmContext = context[self.FSM_CONTEXT]

        varBinds = fsmContext['varBinds']

        idx = context.pop('idx')

        if idx >= 0:
            fsmContext['count'] += 1

            varBinds[idx] = varBind

            debug.logger & debug.flagIns and debug.logger(
                '_flipFlopFsmCb: var-bind %d, processed %d, expected %d' % (idx, fsmContext['count'], len(varBinds)))

            if fsmContext['count'] < len(varBinds):
                return

        debug.logger & debug.flagIns and debug.logger(
            '_flipFlopFsmCb: finished, output %r' % (varBinds,))

        fsmCallable = fsmContext['fsmCallable']

        fsmCallable(**context)

    def flipFlopFsm(self, fsmTable, *varBinds, **context):
        try:
            fsmContext = context[self.FSM_CONTEXT]

        except KeyError:
            self.__indexMib()

            fsmContext = context[self.FSM_CONTEXT] = dict(
                sessionId=self.FSM_SESSION_ID(),
                varBinds=list(varBinds[:]),
                fsmCallable=functools.partial(self.flipFlopFsm, fsmTable, *varBinds),
                state=self.STATE_START, status=self.STATUS_OK
            )

            debug.logger & debug.flagIns and debug.logger('flipFlopFsm: input var-binds %r' % (varBinds,))

        mibTree, = self.mibBuilder.importSymbols('SNMPv2-SMI', 'iso')

        state = fsmContext['state']
        status = fsmContext['status']

        debug.logger & debug.flagIns and debug.logger(
            'flipFlopFsm: current state %s, status %s' % (state, status))

        try:
            newState = fsmTable[(state, status)]

        except KeyError:
            try:
                newState = fsmTable[(self.STATE_ANY, status)]

            except KeyError:
                raise error.SmiError('Unresolved FSM state %s, %s' % (state, status))

        debug.logger & debug.flagIns and debug.logger(
            'flipFlopFsm: state %s status %s -> new state %s' % (state, status, newState))

        state = newState

        if state == self.STATE_STOP:
            context.pop(self.FSM_CONTEXT, None)

            cbFun = context.get('cbFun')
            if cbFun:
                varBinds = fsmContext['varBinds']
                cbFun(varBinds, **context)

            return

        fsmContext.update(state=state, count=0)

        # the case of no var-binds
        if not varBinds:
            return self._flipFlopFsmCb(None, idx=-1, **context)

        mgmtFun = getattr(mibTree, state, None)
        if not mgmtFun:
            raise error.SmiError(
                'Unsupported state handler %s at %s' % (state, self)
            )

        for idx, varBind in enumerate(varBinds):
            try:
                # TODO: managed objects to run asynchronously
                #mgmtFun(varBind, idx=idx, **context)
                self._flipFlopFsmCb(mgmtFun(varBind, idx=idx, **context), idx=idx, **context)

            except error.SmiError:
                exc = sys.exc_info()
                debug.logger & debug.flagIns and debug.logger(
                    'flipFlopFsm: fun %s exception %s for %r with traceback: %s' % (
                        mgmtFun, exc[0], varBind, traceback.format_exception(*exc)))

                varBind = varBind[0], exc

                fsmContext['status'] = self.STATUS_ERROR

                self._flipFlopFsmCb(varBind, idx=idx, **context)

                return

            else:
                debug.logger & debug.flagIns and debug.logger(
                    'flipFlopFsm: func %s initiated for %r' % (mgmtFun, varBind))

    def readVars(self, *varBinds, **context):
        self.flipFlopFsm(self.fsmReadVar, *varBinds, **context)

    def readNextVars(self, *varBinds, **context):
        self.flipFlopFsm(self.fsmReadNextVar, *varBinds, **context)

    def writeVars(self, *varBinds, **context):
        self.flipFlopFsm(self.fsmWriteVar, *varBinds, **context)
