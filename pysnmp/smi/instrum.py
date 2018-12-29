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
from pysnmp.proto import rfc1905
from pysnmp.smi import error
from pysnmp import debug

__all__ = ['AbstractMibInstrumController', 'MibInstrumController']


class AbstractMibInstrumController(object):
    def readMibObjects(self, *varBinds, **context):
        raise error.NoSuchInstanceError(idx=0)

    def readNextMibObjects(self, *varBinds, **context):
        raise error.EndOfMibViewError(idx=0)

    def writeMibObjects(self, *varBinds, **context):
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
        # (state, status) -> newState
        (STATE_START, STATUS_OK): STATE_READ_TEST,
        (STATE_READ_TEST, STATUS_OK): STATE_READ_GET,
        (STATE_READ_GET, STATUS_OK): STATE_STOP,
        (STATE_ANY, STATUS_ERROR): STATE_STOP
    }
    fsmReadNextVar = {
        # (state, status) -> newState
        (STATE_START, STATUS_OK): STATE_READ_TEST_NEXT,
        (STATE_READ_TEST_NEXT, STATUS_OK): STATE_READ_GET_NEXT,
        (STATE_READ_GET_NEXT, STATUS_OK): STATE_STOP,
        (STATE_ANY, STATUS_ERROR): STATE_STOP
    }
    fsmWriteVar = {
        # (state, status) -> newState
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

    def __init__(self, mibBuilder):
        self.mibBuilder = mibBuilder
        self.lastBuildId = -1
        self.lastBuildSyms = {}

    def getMibBuilder(self):
        return self.mibBuilder

    def __indexMib(self):
        """Rebuild a tree from MIB objects found at currently loaded modules.

        If currently existing tree is out of date, walk over all Managed Objects
        and Instances to structure Management Instrumentation objects into a tree
        of the following layout:

        MibTree
          |
          +----MibScalar
          |        |
          |        +-----MibScalarInstance
          |
          +----MibTable
          |
          +----MibTableRow
                   |
                   +-------MibTableColumn
                                 |
                                 +------MibScalarInstance(s)

        Notes
        -----
        Only Managed Objects (i.e. `OBJECT-TYPE`) get indexed here, various MIB
        definitions and constants can't be SNMP managed so we drop them.
        """
        if self.lastBuildId == self.mibBuilder.lastBuildId:
            return

        (MibScalarInstance, MibScalar, MibTableColumn, MibTableRow,
         MibTable) = self.mibBuilder.importSymbols(
            'SNMPv2-SMI', 'MibScalarInstance', 'MibScalar',
            'MibTableColumn', 'MibTableRow', 'MibTable'
        )

        mibTree, = self.mibBuilder.importSymbols('SNMPv2-SMI', 'iso')

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

    def flipFlopFsm(self, fsmTable, *varBinds, **context):
        """Read, modify, create or remove Managed Objects Instances.

        Given one or more py:class:`~pysnmp.smi.rfc1902.ObjectType`, recursively
        transitions corresponding Managed Objects Instances through the Finite State
        Machine (FSM) states till it reaches its final stop state.

        Parameters
        ----------
        fsmTable: :py:class:`dict`
            A map of (`state`, `status`) -> `state` representing FSM transition matrix.
            See :py:class:`RowStatus` for FSM transition logic.

        varBinds: :py:class:`tuple` of :py:class:`~pysnmp.smi.rfc1902.ObjectType` objects
            representing Managed Objects Instances to work with.

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
                pass the new value of the Managed Object Instance or an error.

            * `acFun` (callable) - user-supplied callable that is invoked to
                authorize access to the requested Managed Object Instance. If
                not supplied, no access control will be performed.

        Notes
        -----
        The callback functions (e.g. `cbFun`, `acFun`) have the same signature
        as this method where `varBind` contains the new Managed Object Instance
        value.

        In case of errors, the `errors` key in the `context` dict will contain
        a sequence of `dict` objects describing one or more errors that occur.

        Such error `dict` will have the `error`, `idx` and `state` keys providing
        the details concerning the error, for which variable-binding and in what
        state the system has failed.
        """
        count = [0]

        cbFun = context.get('cbFun')

        def _cbFun(varBind, **context):
            idx = context.pop('idx', None)

            err = context.pop('error', None)
            if err:
                # Move other errors into the errors sequence
                errors = context['errors']
                errors.append(
                    {'error': err,
                     'idx': idx,
                     'varbind': varBind,
                     'state': context['state']}
                )

                context['status'] = self.STATUS_ERROR

            if idx is None:
                if cbFun:
                    cbFun((), **context)
                return

            _varBinds = context['varBinds']

            _varBinds[idx] = varBind

            count[0] += 1

            debug.logger & debug.flagIns and debug.logger(
                '_cbFun: var-bind %d, processed %d, expected %d' % (
                idx, count[0], len(varBinds)))

            if count[0] < len(varBinds):
                return

            debug.logger & debug.flagIns and debug.logger(
                '_cbFun: finished, output var-binds %r' % (_varBinds,))

            self.flipFlopFsm(fsmTable, *varBinds, **dict(context, cbFun=cbFun))

        debug.logger & debug.flagIns and debug.logger('flipFlopFsm: input var-binds %r' % (varBinds,))

        mibTree, = self.mibBuilder.importSymbols('SNMPv2-SMI', 'iso')

        try:
            state = context['state']
            status = context['status']
            instances = context['instances']
            errors = context['errors']
            _varBinds = context['varBinds']

        except KeyError:
            state, status = self.STATE_START, self.STATUS_OK
            instances = {}
            errors = []
            _varBinds = list(varBinds)

            self.__indexMib()

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
            'flipFlopFsm: state %s status %s -> transitioned into state %s' % (state, status, newState))

        state = newState

        if state == self.STATE_STOP:
            context.pop('state', None)
            context.pop('status', None)
            context.pop('instances', None)
            context.pop('varBinds', None)
            if cbFun:
                cbFun(_varBinds, **context)
            return

        # the case of no var-binds
        if not varBinds:
            _cbFun(None, **context)
            return

        actionFun = getattr(mibTree, state, None)
        if not actionFun:
            raise error.SmiError(
                'Unsupported state handler %s at %s' % (state, self)
            )

        for idx, varBind in enumerate(varBinds):
            actionFun(varBind,
                      **dict(context, cbFun=_cbFun,
                             state=state, status=status,
                             idx=idx, total=len(varBinds),
                             instances=instances, errors=errors,
                             varBinds=_varBinds, nextName=None))

            debug.logger & debug.flagIns and debug.logger(
                'flipFlopFsm: func %s initiated for %r' % (actionFun, varBind))

    @staticmethod
    def _defaultErrorHandler(varBinds, **context):
        """Raise exception on any error if user callback is missing"""
        errors = context.get('errors')
        if errors:
            error = errors[-1]
            raise error['error']

    def readMibObjects(self, *varBinds, **context):
        """Read Managed Objects Instances.

        Given one or more py:class:`~pysnmp.smi.rfc1902.ObjectType` objects, read
        all or none of the referenced Managed Objects Instances.

        Parameters
        ----------
        varBinds: :py:class:`tuple` of :py:class:`~pysnmp.smi.rfc1902.ObjectType` objects
            representing Managed Objects Instances to read.

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
                pass the new value of the Managed Object Instance or an error.
                If not provided, default function will raise exception in case
                of an error.

            * `acFun` (callable) - user-supplied callable that is invoked to
                authorize access to the requested Managed Object Instance. If
                not supplied, no access control will be performed.

        Notes
        -----
        The signature of the callback functions (e.g. `cbFun`, `acFun`) is this:

        .. code-block: python

            def cbFun(varBinds, **context):
                errors = context.get(errors)
                if errors:
                    print(errors[0].error)

                else:
                    print(', '.join('%s = %s' % varBind for varBind in varBinds))

        In case of errors, the `errors` key in the `context` dict will contain
        a sequence of `dict` objects describing one or more errors that occur.

        If a non-existing Managed Object is referenced, no error will be
        reported, but the values returned in the `varBinds` would be either
        :py:class:`NoSuchObject` (indicating non-existent Managed Object) or
        :py:class:`NoSuchInstance` (if Managed Object exists, but is not
        instantiated).
        """
        if 'cbFun' not in context:
            context['cbFun'] = self._defaultErrorHandler

        self.flipFlopFsm(self.fsmReadVar, *varBinds, **context)

    def readNextMibObjects(self, *varBinds, **context):
        """Read Managed Objects Instances next to the given ones.

        Given one or more py:class:`~pysnmp.smi.rfc1902.ObjectType` objects, read
        all or none of the Managed Objects Instances next to the referenced ones.

        Parameters
        ----------
        varBinds: :py:class:`tuple` of :py:class:`~pysnmp.smi.rfc1902.ObjectType` objects
            representing Managed Objects Instances to read next to.

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
                pass the new value of the Managed Object Instance or an error.
                If not provided, default function will raise exception in case
                of an error.

            * `acFun` (callable) - user-supplied callable that is invoked to
                authorize access to the requested Managed Object Instance. If
                not supplied, no access control will be performed.

        Notes
        -----
        The signature of the callback functions (e.g. `cbFun`, `acFun`) is this:

        .. code-block: python

            def cbFun(varBinds, **context):
                errors = context.get(errors)
                if errors:
                    print(errors[0].error)

                else:
                    print(', '.join('%s = %s' % varBind for varBind in varBinds))

        In case of errors, the `errors` key in the `context` dict will contain
        a sequence of `dict` objects describing one or more errors that occur.

        If a non-existing Managed Object is referenced, no error will be
        reported, but the values returned in the `varBinds` would be one of:
        :py:class:`NoSuchObject` (indicating non-existent Managed Object) or
        :py:class:`NoSuchInstance` (if Managed Object exists, but is not
        instantiated) or :py:class:`EndOfMibView` (when the last Managed Object
        Instance has been read).

        When :py:class:`NoSuchObject` or :py:class:`NoSuchInstance` values are
        returned, the caller is expected to repeat the same call with some
        or all `varBinds` returned to progress towards the end of the
        implemented MIB.
        """
        if 'cbFun' not in context:
            context['cbFun'] = self._defaultErrorHandler

        self.flipFlopFsm(self.fsmReadNextVar, *varBinds, **context)

    def writeMibObjects(self, *varBinds, **context):
        """Create, destroy or modify Managed Objects Instances.

        Given one or more py:class:`~pysnmp.smi.rfc1902.ObjectType` objects, create,
        destroy or modify  all or none of the referenced Managed Objects Instances.

        If a non-existing Managed Object Instance is written, the new Managed Object
        Instance will be created with the value given in the `varBinds`.

        If existing Managed Object Instance is being written, its value is changed
        to the new one.

        Unless it's a :py:class:`RowStatus` object of a SMI table, in which case the
        outcome of the *write* operation depends on the :py:class:`RowStatus`
        transition. The whole table row could be created or destroyed or brought
        on/offline.

        When SMI table row is brought online (i.e. into the *active* state), all
        columns will be checked for consistency. Error will be reported and write
        operation will fail if inconsistency is found.

        Parameters
        ----------
        varBinds: :py:class:`tuple` of :py:class:`~pysnmp.smi.rfc1902.ObjectType` objects
            representing Managed Objects Instances to modify.

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
                pass the new value of the Managed Object Instance or an error.
                If not provided, default function will raise exception in case
                of an error.

            * `acFun` (callable) - user-supplied callable that is invoked to
                authorize access to the requested Managed Object Instance. If
                not supplied, no access control will be performed.

        Notes
        -----
        The signature of the callback functions (e.g. `cbFun`, `acFun`) is this:

        .. code-block: python

            def cbFun(varBinds, **context):
                errors = context.get(errors)
                if errors:
                    print(errors[0].error)

                else:
                    print(', '.join('%s = %s' % varBind for varBind in varBinds))

        In case of errors, the `errors` key in the `context` dict will contain
        a sequence of `dict` objects describing one or more errors that occur.

        If a non-existing Managed Object is referenced, no error will be
        reported, but the values returned in the `varBinds` would be one of:
        :py:class:`NoSuchObject` (indicating non-existent Managed Object) or
        :py:class:`NoSuchInstance` (if Managed Object exists, but can't be
        modified.
        """
        if 'cbFun' not in context:
            context['cbFun'] = self._defaultErrorHandler

        self.flipFlopFsm(self.fsmWriteVar, *varBinds, **context)
