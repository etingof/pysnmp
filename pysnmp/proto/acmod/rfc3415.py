#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.smi.error import NoSuchInstanceError
from pysnmp.proto import errind, error
from pysnmp import debug


# 3.2
class Vacm(object):
    """View-based Access Control Model"""
    accessModelID = 3

    _powOfTwoSeq = (128, 64, 32, 16, 8, 4, 2, 1)

    def __init__(self):
        self._contextBranchId = -1
        self._groupNameBranchId = -1
        self._accessBranchId = -1
        self._viewTreeBranchId = -1

        self._contextMap = {}
        self._groupNameMap = {}
        self._accessMap = {}
        self._viewTreeMap = {}

    def _addAccessEntry(self, groupName, contextPrefix, securityModel,
                        securityLevel, prefixMatch, readView, writeView,
                        notifyView):
        if not groupName:
            return

        groups = self._accessMap

        try:
            views = groups[groupName]

        except KeyError:
            views = groups[groupName] = {}

        for viewType, viewName in (
                ('read', readView), ('write', writeView),
                ('notify', notifyView)):

            try:
                matches = views[viewType]

            except KeyError:
                matches = views[viewType] = {}

            try:
                contexts = matches[prefixMatch]

            except KeyError:
                contexts = matches[prefixMatch] = {}

            try:
                models = contexts[contextPrefix]

            except KeyError:
                models = contexts[contextPrefix] = {}

            try:
                levels = models[securityModel]

            except KeyError:
                levels = models[securityModel] = {}

            levels[securityLevel] = viewName

    def _getFamilyViewName(self, groupName, contextName, securityModel, securityLevel, viewType):
        groups = self._accessMap

        try:
            views = groups[groupName]

        except KeyError:
            raise error.StatusInformation(errorIndication=errind.noGroupName)

        try:
            matches = views[viewType]

        except KeyError:
            raise error.StatusInformation(errorIndication=errind.noAccessEntry)

        try:
            # vacmAccessTable #2: exact match shortcut
            return matches[1][contextName][securityModel][securityLevel]

        except KeyError:
            pass

        # vacmAccessTable #2: fuzzy look-up

        candidates = []

        for match, names in matches.items():

            for context, models in names.items():

                if match == 1 and contextName != context:
                    continue

                if match == 2 and contextName[:len(context)] != context:
                    continue

                for model, levels in models.items():
                    for level, viewName in levels.items():

                        # priorities:
                        # - matching securityModel
                        # - exact context name match
                        # - longer partial match
                        # - highest securityLevel
                        rating = securityModel == model, match == 1, len(context), level

                        candidates.append((rating, viewName))

        if not candidates:
            raise error.StatusInformation(errorIndication=errind.notInView)

        candidates.sort()

        rating, viewName = candidates[0]
        return viewName

    def isAccessAllowed(self,
                        snmpEngine,
                        securityModel,
                        securityName,
                        securityLevel,
                        viewType,
                        contextName,
                        variableName):

        mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController

        debug.logger & debug.flagACL and debug.logger(
            'isAccessAllowed: securityModel %s, securityName %s, '
            'securityLevel %s, viewType %s, contextName %s for '
            'variableName %s' % (securityModel, securityName,
                                 securityLevel, viewType, contextName,
                                 variableName))

        # Rebuild contextName map if changed

        vacmContextName, = mibInstrumController.mibBuilder.importSymbols(
            'SNMP-VIEW-BASED-ACM-MIB', 'vacmContextName')

        if self._contextBranchId != vacmContextName.branchVersionId:

            self._contextMap.clear()

            nextMibNode = vacmContextName

            while True:
                try:
                    nextMibNode = vacmContextName.getNextNode(nextMibNode.name)

                except NoSuchInstanceError:
                    break

                self._contextMap[nextMibNode.syntax] = True

            self._contextBranchId = vacmContextName.branchVersionId

        # 3.2.1
        if contextName not in self._contextMap:
            raise error.StatusInformation(errorIndication=errind.noSuchContext)

        # Rebuild groupName map if changed

        vacmGroupName, = mibInstrumController.mibBuilder.importSymbols(
            'SNMP-VIEW-BASED-ACM-MIB', 'vacmGroupName')

        if self._groupNameBranchId != vacmGroupName.branchVersionId:

            vacmSecurityToGroupEntry, = mibInstrumController.mibBuilder.importSymbols(
                'SNMP-VIEW-BASED-ACM-MIB', 'vacmSecurityToGroupEntry')

            self._groupNameMap.clear()

            nextMibNode = vacmGroupName

            while True:
                try:
                    nextMibNode = vacmGroupName.getNextNode(nextMibNode.name)

                except NoSuchInstanceError:
                    break

                instId = nextMibNode.name[len(vacmGroupName.name):]

                indices = vacmSecurityToGroupEntry.getIndicesFromInstId(instId)

                self._groupNameMap[indices] = nextMibNode.syntax

            self._groupNameBranchId = vacmGroupName.branchVersionId

        # 3.2.2
        indices = securityModel, securityName

        try:
            groupName = self._groupNameMap[indices]

        except KeyError:
            raise error.StatusInformation(errorIndication=errind.noGroupName)

        # Rebuild access map if changed

        vacmAccessStatus, = mibInstrumController.mibBuilder.importSymbols(
            'SNMP-VIEW-BASED-ACM-MIB', 'vacmAccessStatus')

        if self._accessBranchId != vacmAccessStatus.branchVersionId:

            (vacmAccessEntry,
             vacmAccessContextPrefix,
             vacmAccessSecurityModel,
             vacmAccessSecurityLevel,
             vacmAccessContextMatch,
             vacmAccessReadViewName,
             vacmAccessWriteViewName,
             vacmAccessNotifyViewName) = mibInstrumController.mibBuilder.importSymbols(
                'SNMP-VIEW-BASED-ACM-MIB',
                'vacmAccessEntry',
                'vacmAccessContextPrefix',
                'vacmAccessSecurityModel',
                'vacmAccessSecurityLevel',
                'vacmAccessContextMatch',
                'vacmAccessReadViewName',
                'vacmAccessWriteViewName',
                'vacmAccessNotifyViewName')

            self._accessMap.clear()

            nextMibNode = vacmAccessStatus

            while True:
                try:
                    nextMibNode = vacmAccessStatus.getNextNode(nextMibNode.name)

                except NoSuchInstanceError:
                    break

                if nextMibNode.syntax != 1:  # active row
                    continue

                instId = nextMibNode.name[len(vacmAccessStatus.name):]

                indices = vacmAccessEntry.getIndicesFromInstId(instId)

                vacmGroupName = indices[0]

                self._addAccessEntry(
                    vacmGroupName,
                    vacmAccessContextPrefix.getNode(
                        vacmAccessContextPrefix.name + instId).syntax,
                    vacmAccessSecurityModel.getNode(
                        vacmAccessSecurityModel.name + instId).syntax,
                    vacmAccessSecurityLevel.getNode(
                        vacmAccessSecurityLevel.name + instId).syntax,
                    vacmAccessContextMatch.getNode(
                        vacmAccessContextMatch.name + instId).syntax,
                    vacmAccessReadViewName.getNode(
                        vacmAccessReadViewName.name + instId).syntax,
                    vacmAccessWriteViewName.getNode(
                        vacmAccessWriteViewName.name + instId).syntax,
                    vacmAccessNotifyViewName.getNode(
                        vacmAccessNotifyViewName.name + instId).syntax
                )

            self._accessBranchId = vacmAccessStatus.branchVersionId

        viewName = self._getFamilyViewName(
            groupName, contextName, securityModel, securityLevel, viewType)

        # Rebuild family subtree map if changed

        vacmViewTreeFamilyViewName, = mibInstrumController.mibBuilder.importSymbols(
            'SNMP-VIEW-BASED-ACM-MIB', 'vacmViewTreeFamilyViewName')

        if self._viewTreeBranchId != vacmViewTreeFamilyViewName.branchVersionId:

            (vacmViewTreeFamilySubtree,
             vacmViewTreeFamilyMask,
             vacmViewTreeFamilyType) = mibInstrumController.mibBuilder.importSymbols(
                'SNMP-VIEW-BASED-ACM-MIB',
                'vacmViewTreeFamilySubtree',
                'vacmViewTreeFamilyMask',
                'vacmViewTreeFamilyType')

            self._viewTreeMap.clear()

            powerOfTwo = [2 ** exp for exp in range(7, -1, -1)]

            nextMibNode = vacmViewTreeFamilyViewName

            while True:
                try:
                    nextMibNode = vacmViewTreeFamilyViewName.getNextNode(
                        nextMibNode.name)

                except NoSuchInstanceError:
                    break

                if nextMibNode.syntax not in self._viewTreeMap:
                    self._viewTreeMap[nextMibNode.syntax] = []

                instId = nextMibNode.name[len(vacmViewTreeFamilyViewName.name):]

                subtree = vacmViewTreeFamilySubtree.getNode(
                    vacmViewTreeFamilySubtree.name + instId).syntax

                mask = vacmViewTreeFamilyMask.getNode(
                    vacmViewTreeFamilyMask.name + instId).syntax

                mode = vacmViewTreeFamilyType.getNode(
                    vacmViewTreeFamilyType.name + instId).syntax

                mask = mask.asNumbers()
                maskLength = min(len(mask) * 8, len(subtree))

                ignoredSubOids = [
                    i * 8 + j for i, octet in enumerate(mask)
                    for j, bit in enumerate(powerOfTwo)
                    if not (bit & octet) and i * 8 + j < maskLength
                ]

                if ignoredSubOids:
                    pattern = list(subtree)

                    for ignoredSubOid in ignoredSubOids:
                        pattern[ignoredSubOid] = 0

                    subtree = subtree.clone(pattern)

                entry = subtree, ignoredSubOids, mode == 1

                self._viewTreeMap[nextMibNode.syntax].append(entry)

            for entries in self._viewTreeMap.values():
                entries.sort(key=lambda x: (len(x[0]), x[0]))

            self._viewTreeBranchId = vacmViewTreeFamilyViewName.branchVersionId

        # 3.2.5a
        indices = viewName

        try:
            entries = self._viewTreeMap[indices]

        except KeyError:
            return error.StatusInformation(errorIndication=errind.notInView)

        accessAllowed = False

        for entry in entries:
            subtree, ignoredSubOids, included = entry

            if ignoredSubOids:
                subOids = list(variableName)

                for ignoredSubOid in ignoredSubOids:
                    subOids[ignoredSubOid] = 0

                normalizedVariableName = subtree.clone(subOids)

            else:
                normalizedVariableName = variableName

            if subtree.isPrefixOf(normalizedVariableName):
                accessAllowed = included

        # 3.2.5c
        if not accessAllowed:
            raise error.StatusInformation(errorIndication=errind.notInView)
