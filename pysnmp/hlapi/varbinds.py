#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.smi import builder
from pysnmp.smi import view
from pysnmp.smi.rfc1902 import *

__all__ = ['CommandGeneratorVarBinds', 'NotificationOriginatorVarBinds']


class MibViewControllerManager(object):
    @staticmethod
    def getMibViewController(userCache):
        try:
            mibViewController = userCache['mibViewController']

        except KeyError:
            mibViewController = view.MibViewController(builder.MibBuilder())
            userCache['mibViewController'] = mibViewController

        return mibViewController


class CommandGeneratorVarBinds(MibViewControllerManager):
    def makeVarBinds(self, userCache, varBinds):
        mibViewController = self.getMibViewController(userCache)

        resolvedVarBinds = []

        for varBind in varBinds:
            if isinstance(varBind, ObjectType):
                pass

            elif isinstance(varBind[0], ObjectIdentity):
                varBind = ObjectType(*varBind)

            elif isinstance(varBind[0][0], tuple):  # legacy
                varBind = ObjectType(ObjectIdentity(varBind[0][0][0], varBind[0][0][1], *varBind[0][1:]), varBind[1])

            else:
                varBind = ObjectType(ObjectIdentity(varBind[0]), varBind[1])

            resolvedVarBinds.append(varBind.resolveWithMib(mibViewController))

        return resolvedVarBinds

    def unmakeVarBinds(self, userCache, varBinds, lookupMib=True):
        if lookupMib:
            mibViewController = self.getMibViewController(userCache)
            varBinds = [ObjectType(ObjectIdentity(x[0]), x[1]).resolveWithMib(mibViewController) for x in varBinds]

        return varBinds


class NotificationOriginatorVarBinds(MibViewControllerManager):
    def makeVarBinds(self, userCache, varBinds):
        mibViewController = self.getMibViewController(userCache)

        if isinstance(varBinds, NotificationType):
            return varBinds.resolveWithMib(mibViewController)

        resolvedVarBinds = []

        for varBind in varBinds:
            if isinstance(varBind, NotificationType):
                resolvedVarBinds.extend(varBind.resolveWithMib(mibViewController))
                continue

            if isinstance(varBind, ObjectType):
                pass

            elif isinstance(varBind[0], ObjectIdentity):
                varBind = ObjectType(*varBind)

            else:
                varBind = ObjectType(ObjectIdentity(varBind[0]), varBind[1])

            resolvedVarBinds.append(varBind.resolveWithMib(mibViewController))

        return resolvedVarBinds

    def unmakeVarBinds(self, userCache, varBinds, lookupMib=False):
        if lookupMib:
            mibViewController = self.getMibViewController(userCache)
            varBinds = [ObjectType(ObjectIdentity(x[0]), x[1]).resolveWithMib(mibViewController) for x in varBinds]
        return varBinds
