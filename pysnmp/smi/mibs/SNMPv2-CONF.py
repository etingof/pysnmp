#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# PySNMP MIB module SNMPv2-CONF (http://snmplabs.com/pysnmp)
# ASN.1 source http://mibs.snmplabs.com:80/asn1/SNMPv2-CONF
# Produced by pysmi-0.1.3 at Tue Apr 18 00:51:39 2017
# On host grommit.local platform Darwin version 16.4.0 by user ilya
# Using Python version 3.4.2 (v3.4.2:ab2c023a9432, Oct  5 2014, 20:42:22)
#
MibNode, = mibBuilder.importSymbols('SNMPv2-SMI', 'MibNode')


class ObjectGroup(MibNode):
    status = 'current'
    objects = ()
    description = ''

    def getStatus(self):
        return self.status

    def setStatus(self, v):
        self.status = v
        return self

    def getObjects(self):
        return getattr(self, 'objects', ())

    def setObjects(self, *args, **kwargs):
        if kwargs.get('append'):
            self.objects += args
        else:
            self.objects = args
        return self

    def getDescription(self):
        return getattr(self, 'description', '')

    def setDescription(self, v):
        self.description = v
        return self

    def asn1Print(self):
        return """\
OBJECT-GROUP
  OBJECTS { %s }
  DESCRIPTION "%s"
""" % (', '.join([x for x in self.getObjects()]), self.getDescription())


class NotificationGroup(MibNode):
    status = 'current'
    objects = ()
    description = ''

    def getStatus(self):
        return self.status

    def setStatus(self, v):
        self.status = v
        return self

    def getObjects(self):
        return getattr(self, 'objects', ())

    def setObjects(self, *args, **kwargs):
        if kwargs.get('append'):
            self.objects += args
        else:
            self.objects = args
        return self

    def getDescription(self):
        return getattr(self, 'description', '')

    def setDescription(self, v):
        self.description = v
        return self

    def asn1Print(self):
        return """\
NOTIFICATION-GROUP
  NOTIFICATIONS { %s }
  DESCRIPTION "%s"
""" % (', '.join([x for x in self.getObjects()]), self.getDescription())


class ModuleCompliance(MibNode):
    status = 'current'
    objects = ()
    description = ''

    def getStatus(self):
        return self.status

    def setStatus(self, v):
        self.status = v
        return self

    def getObjects(self):
        return getattr(self, 'objects', ())

    def setObjects(self, *args, **kwargs):
        if kwargs.get('append'):
            self.objects += args
        else:
            self.objects = args
        return self

    def getDescription(self):
        return getattr(self, 'description', '')

    def setDescription(self, v):
        self.description = v
        return self

    def asn1Print(self):
        return """\
MODULE-COMPLIANCE
  OBJECT { %s }
  DESCRIPTION "%s"
""" % (', '.join([x for x in self.getObjects()]), self.getDescription())


class AgentCapabilities(MibNode):
    status = 'current'
    description = ''
    reference = ''
    productRelease = ''

    def getStatus(self):
        return self.status

    def setStatus(self, v):
        self.status = v
        return self

    def getDescription(self):
        return getattr(self, 'description', '')

    def setDescription(self, v):
        self.description = v
        return self

    def getReference(self):
        return self.reference

    def setReference(self, v):
        self.reference = v
        return self

    def getProductRelease(self):
        return self.productRelease

    def setProductRelease(self, v):
        self.productRelease = v
        return self

    # TODO: implement the rest of properties

    def asn1Print(self):
        return """\
AGENT-CAPABILITIES
  STATUS "%s"
  PRODUCT-RELEASE "%s"
  DESCRIPTION "%s"
""" % (self.getStatus(), self.getProductRelease(), self.getDescription())


mibBuilder.exportSymbols('SNMPv2-CONF', ObjectGroup=ObjectGroup, NotificationGroup=NotificationGroup, ModuleCompliance=ModuleCompliance, AgentCapabilities=AgentCapabilities)
