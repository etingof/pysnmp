#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2017, Ilya Etingof <etingof@gmail.com>
# License: http://pysnmp.sf.net/license.html
#
MibNode, = mibBuilder.importSymbols('SNMPv2-SMI', 'MibNode')


class ObjectGroup(MibNode):
    objects = ()
    description = ''

    def getObjects(self):
        return getattr(self, 'objects', ())

    def setObjects(self, *args):
        self.objects = args
        return self

    def getDescription(self):
        return getattr(self, 'description', '')

    def setDescription(self, v):
        self.description = v
        return self

    def asn1Print(self):
        return '\
OBJECT-GROUP\n\
  OBJECTS { %s }\n\
  DESCRIPTION \"%s\"\
' % (', '.join([x for x in self.getObjects()]), self.getDescription())


class NotificationGroup(MibNode):
    objects = ()
    description = ''

    def getObjects(self):
        return getattr(self, 'objects', ())

    def setObjects(self, *args):
        self.objects = args
        return self

    def getDescription(self):
        return getattr(self, 'description', '')

    def setDescription(self, v):
        self.description = v
        return self

    def asn1Print(self):
        return '\
NOTIFICATION-GROUP\n\
  NOTIFICATIONS { %s }\n\
  DESCRIPTION \"%s\"\
' % (', '.join([x for x in self.getObjects()]), self.getDescription())


class ModuleCompliance(MibNode):
    objects = ()
    description = ''

    def getObjects(self):
        return getattr(self, 'objects', ())

    def setObjects(self, *args):
        self.objects = args
        return self

    def getDescription(self):
        return getattr(self, 'description', '')

    def setDescription(self, v):
        self.description = v
        return self

    def asn1Print(self):
        return '\
MODULE-COMPLIANCE\n\
  OBJECT { %s } \n\
  DESCRIPTION \"%s\"\n\
' % (', '.join([x for x in self.getObjects()]), self.getDescription())


class AgentCapabilities(MibNode):
    description = ''

    def getDescription(self):
        return getattr(self, 'description', '')

    def setDescription(self, v):
        self.description = v
        return self

    def asn1Print(self):
        return '\
AGENT-CAPABILITIES\n\
  DESCRIPTION \"%s\"\n\
' % self.getDescription()


mibBuilder.exportSymbols('SNMPv2-CONF', ObjectGroup=ObjectGroup, NotificationGroup=NotificationGroup,
                         ModuleCompliance=ModuleCompliance, AgentCapabilities=AgentCapabilities)
