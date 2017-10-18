
.. toctree::
   :maxdepth: 2

Common operations
=================

In this tutorial we will gradually build and run a few different
SNMP command requests and notifications. We will be using PySNMP
synchronous :doc:`high-level API </docs/api-reference>`
which is the simplest to use.

Creating SNMP Engine
--------------------

SNMP engine is a central, umbrella object in PySNMP. All PySNMP
opetations involve :py:class:`~pysnmp.hlapi.SnmpEngine` class
instance. PySNMP app can run multiple independent SNMP engines each
guided by its own *SnmpEngine* object.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> SnmpEngine()
   SnmpEngine(snmpEngineID=OctetString(hexValue='80004fb80567'))

SNMP engine has unique identifier that can be assigned automatically
or administratively. This identifier is used in SNMP protocol
operations.

Making SNMP query
-----------------

We will send SNMP GET command to read a MIB object from SNMP agent.
For that purpose we will call synchronous, high-level
:py:func:`~pysnmp.hlapi.getCmd` function.
Other SNMP commands can be used in a vary similar way by calling
corresponding functions.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>> [ x for x in dir() if 'Cmd' in x]
   ['bulkCmd', 'getCmd', 'nextCmd', 'setCmd']
   >>> getCmd
   <function getCmd at 0x222b330>

Choosing SNMP protocol and credentials
--------------------------------------

We have a choice of three SNMP protocol versions. To employ
SNMP versions 1 or 2c, we pass properly initialized instance of
:py:class:`~pysnmp.hlapi.CommunityData` class. For the third
SNMP version we pass :py:class:`~pysnmp.hlapi.UsmUserData` class
instance.

SNMP community name, as well as the choice between SNMP v1 and v2c,
is conveyed to SNMP LCD via :py:class:`~pysnmp.hlapi.CommunityData`
object.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> CommunityData('public', mpModel=0)  # SNMPv1
   CommunityData('public')
   >>> CommunityData('public', mpModel=1)  # SNMPv2c
   CommunityData('public')

Use of :py:class:`~pysnmp.hlapi.UsmUserData` object for LCD
configuration implies using SNMPv3. Besides setting up USM user name,
*UsmUserData* object can also carry crypto keys and crypto protocols
to SNMP engine LCD.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> UsmUserData('testuser', authKey='myauthkey')
   UsmUserData(userName='testuser', authKey=<AUTHKEY>)
   >>> UsmUserData('testuser', authKey='myauthkey', privKey='myenckey')
   UsmUserData(userName='testuser', authKey=<AUTHKEY>, privKey=<PRIVKEY>)

PySNMP supports MD5 and SHA message authentication algorithms, DES,
AES128/192/256 and 3DES encryption algoritms.

For sake of simplicity, let's use SNMPv2. Although completely
insecure, it's still the most popular SNMP version in use.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> g = getCmd(SnmpEngine(), CommunityData('public'),
   ...

Setting transport and target
----------------------------

PySNMP supports UDP-over-IPv4 and UDP-over-IPv6 network transports.
In this example we will query 
`public SNMP Simulator <http://snmpsim.sourceforge.net/public-snmp-simulator.html>`_
available over IPv4 on the Internet at *demo.snmplabs.com*. Transport
configuration is passed to SNMP LCD in form of properly initialized
:py:class:`~pysnmp.hlapi.UdpTransportTarget` or
:py:class:`~pysnmp.hlapi.Udp6TransportTarget` objects
respectively.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> g = getCmd(SnmpEngine(),
   ...            CommunityData('public'),
   ...            UdpTransportTarget(('demo.snmplabs.com', 161)),
   ...

Addressing SNMP context
-----------------------

SNMP context is a parameter in SNMP (v3) message header that
addresses specific collection of MIBs served by SNMP engine
at managed entity. SNMP engine could serve many identical MIB
objects representing completely different instances of hardware
or software being managed. This is where SNMP context could
be used.

To indicate SNMP context at high-level API a preperly initialized
:py:class:`~pysnmp.hlapi.ContextData` object should be used.
For this example we will use the 'empty' context (default).

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> g = getCmd(SnmpEngine(),
   ...            CommunityData('public'),
   ...            UdpTransportTarget(('demo.snmplabs.com', 161)),
   ...            ContextData(),
   ...


Specifying MIB object
---------------------

Finally, we have to specify the MIB object we want to read.
On protocol level, MIB objects are identified by OIDs, but
humans tend to address them by name:

.. code-block:: bash

   $ snmpget -v2c -c public demo.snmplabs.com SNMPv2-MIB::sysDescr.0
   SNMPv2-MIB::sysDescr.0 = STRING: SunOS zeus.snmplabs.com
   $
   $ snmpget -v2c -c public demo.snmplabs.com 1.3.6.1.2.1.1.1.0
   SNMPv2-MIB::sysDescr.0 = STRING: SunOS zeus.snmplabs.com

Both object name and OID come from MIB. Name and OID linking is done
by high-level SMI construct called *OBJECT-TYPE*. Here is an example MIB
object definition for *sysUpTime* with OID ...mgmt.mib-2.system.3
and value type *TimeTicks*.

.. code-block:: bash

   sysUpTime OBJECT-TYPE
       SYNTAX      TimeTicks
       MAX-ACCESS  read-only
       STATUS      current
       DESCRIPTION
               "The time (in hundredths of a second) since
               the network management portion of the system
               was last re-initialized."
       ::= { system 3 }

In PySNMP we use the :py:class:`~pysnmp.smi.rfc1902.ObjectIdentity` class
that is responsible for MIB objects identification. *ObjectIdentity*
represents ways to address MIB object from human perspective. It needs
to consult MIB to enter a fully "resolved" state. ObjectIdentity could
be initialized with MIB object name, after a MIB look up it starts
behaving like an OID.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> x = ObjectIdentity('SNMPv2-MIB', 'system')
   >>> # ... calling MIB lookup ...
   >>> tuple(x)
   (1, 3, 6, 1, 2, 1, 1, 1)
   >>> x = ObjectIdentity('iso.org.dod.internet.mgmt.mib-2.system.sysDescr')
   >>> # ... calling MIB lookup ...
   >>> str(x)
   '1.3.6.1.2.1.1.1'

MIB resolution means the service of MIB object name into OID
transformation or vice versa.

The :py:class:`~pysnmp.smi.rfc1902.ObjectType` class instance
represents *OBJECT-TYPE* SMI constuct in PySNMP. ObjectType is a 
container object that references ObjectIdentity and SNMP
type instances. As a Python object it looks like a tuple of
(OID, value).

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>> x = ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0), 'Linux i386 box'))
   >>> # ... calling MIB lookup ...
   >>> x[0].prettyPrint()
   'SNMPv2-MIB::sysDescr.0'
   >>> x[1].prettyPrint()
   'Linux i386 box'

The trailing zero is an indication of MIB object *instance*. Objects
described in MIBs are just declarations, they never contain any data.
Data is stored in MIB object instances addressed by appending extra
information (known as *index*) to MIB object identifiers.

For scalar MIB objects index is '0' by convention. The
*ObjectIdentity* class takes indices as its initializers.

.. code-block:: python

   >>> x = ObjectIdentity('SNMPv2-MIB', 'system', 0)
   >>> # ... calling MIB lookup ...
   >>> tuple(x)
   (1, 3, 6, 1, 2, 1, 1, 1, 0)

We will be reading *sysDescr* scalar MIB object instance as defined
in `SNMPv2-MIB <http://mibs.snmplabs.com/asn1/SNMPv2-MIB>`_ module.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>> g = getCmd(SnmpEngine(),
   ...            CommunityData('public'),
   ...            UdpTransportTarget(('demo.snmplabs.com', 161)),
   ...            ContextData(),
   ...            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))

By default PySNMP will search your local filesystem for ASN.1 MIB files
you refer to. It can also be configured to automatically download
them from remote hosts, as
:doc:`shown </examples/hlapi/asyncore/sync/manager/cmdgen/mib-tweaks>`
in the examples. We maintain a
`collection <http://mibs.snmplabs.com/asn1/>`_ of ASN.1 MIB modules
that you can use in your SNMP projects.

Reading scalar value
--------------------

We are finally in a position to send SNMP query and hopefully receive
something meaningful in response.

The distinctive feature of synchronous API is that it is built around
the idea of Python generator. Any function invocation ends up with a
generator object. Iteration over the generator object performs actual
SNMP communication. On each iteration SNMP message gets built and sent
out, response is awaited, received and parsed.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> g = getCmd(SnmpEngine(),
   ...            CommunityData('public'),
   ...            UdpTransportTarget(('demo.snmplabs.com', 161)),
   ...            ContextData(),
   ...            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysUpTime', 0)))
   >>> next(g)
   (None, 0, 0, [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'), TimeTicks(44430646))])

Working with SNMP tables
------------------------

SNMP defines a concept of table. Tables are used when a single given
MIB object may apply to many instances of a property. For example,
properties of network interfaces are put into SNMP table. Each
instance of a property is addressed by a suffix appended to base MIB
object.

Tables are specified in MIBs, their index (or indices) are declared
via the *INDEX* clause. Table index is non-zero integer, or string
or any base SNMP type.

At the protocol level all indices take shape of OID parts. For humans
to work with indices comfortably, SNMP management applications rely on
DISPLAY-HINT clause for automatic indices conversion between their
OID and SNMP type-specific, human-friendly representation.

.. code-block:: bash

   ifEntry OBJECT-TYPE
       SYNTAX      IfEntry
       INDEX   { ifIndex }
   ::= { ifTable 1 }

   ifIndex OBJECT-TYPE
       SYNTAX      InterfaceIndex
   ::= { ifEntry 1 }

   ifDescr OBJECT-TYPE
       SYNTAX      DisplayString (SIZE (0..255))
   ::= { ifEntry 2 }

   InterfaceIndex ::= TEXTUAL-CONVENTION
       DISPLAY-HINT "d"
       SYNTAX       Integer32 (1..2147483647)

In PySNMP parlance:

.. code-block:: python

   >>> x = ObjectIdentity('IF-MIB', 'ifDescr', 123)
   >>> # ... calling MIB lookup ...
   >>> str(x)
   '1.3.6.1.2.1.2.2.1.2.123'

Some SNMP tables are indexed by many indices. Each of these indices
become parts of OID concatinated to each other and ultimately to
MIB object OID.

From semantic standpoint, each index reflects an important and
distinct property of a MIB object.

.. code-block:: bash

   tcpConnectionEntry OBJECT-TYPE
       SYNTAX  TcpConnectionEntry
       INDEX   { tcpConnectionLocalAddressType,
                 tcpConnectionLocalAddress,
                 tcpConnectionLocalPort,
                 tcpConnectionRemAddressType,
                 tcpConnectionRemAddress,
                 tcpConnectionRemPort }
   ::= { tcpConnectionTable 1 }

   tcpConnectionLocalPort OBJECT-TYPE
       SYNTAX     InetPortNumber
   ::= { tcpConnectionEntry 3 }

PySNMP's :py:class:`~pysnmp.smi.rfc1902.ObjectIdentity` class takes
any number of indices in human-friendly representation and converts
them into full OID:

.. code-block:: python

   >>> x = ObjectIdentity('TCP-MIB', 'tcpConnectionState',
   ...                    'ipv4', '195.218.254.105', 41511,
   ...                    'ipv4', '194.67.1.250', 993)
   >>> # ... calling MIB lookup ...
   >>> str(x)
   '1.3.6.1.2.1.6.19.1.7.1.4.195.218.254.105.41511.1.4.194.67.1.250.993'

Let's read TCP-MIB::tcpConnectionState object for a TCP connection:

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> g = getCmd(SnmpEngine(),
   ...            CommunityData('public'),
   ...            UdpTransportTarget(('demo.snmplabs.com', 161)),
   ...            ContextData(),
   ...            ObjectType(ObjectIdentity('TCP-MIB', 'tcpConnectionState',
   ...                                      'ipv4', '195.218.254.105', 41511,
   ...                                      'ipv4', '194.67.1.250', 993)
   >>> next(g)
   (None, 0, 0, [ObjectType(ObjectIdentity(ObjectName('1.3.6.1.2.1.6.19.1.7.1.4.195.218.254.105.41511.1.4.194.67.1.250.993')), Integer(5))])

SNMP command operations
-----------------------

SNMP allows you to request a MIB object that is "next" to the given
one. That way you can read MIB objects you are not aware about in
advance. MIB objects are conceptually sorted by their OIDs.
This feature is implemented by the :py:func:`~pysnmp.hlapi.nextCmd`
function.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>> g = nextCmd(SnmpEngine(),
   ...             CommunityData('public'),
   ...             UdpTransportTarget(('demo.snmplabs.com', 161)),
   ...             ContextData(),
   ...             ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr')))
   >>> next(g)
   (None, 0, 0, [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'), DisplayString('SunOS zeus.snmplabs.com'))])
   >>> next(g)
   (None, 0, 0, [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.2.0'), ObjectIdentity(ObjectIdentifier('1.3.6.1.4.1.8072.3.2.10')))])

Iteration over the generator object "walk" over SNMP agent's MIB objects.

SNMPv2c introduced significant optimization to the *GETNEXT* command -
the revised version is called *GETBULK* and is capable to gather and
respond a bunch of "next" MIB objects at once. Additional
non-repeaters and max-repetitions parameters can be used to influence
MIB objects batching.

PySNMP hides this *GETBULK* optimization at the protocol level, the
:py:func:`~pysnmp.hlapi.bulkCmd` function exposes the same generator
API as *getNext()* for convenience.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> N, R = 0, 25
   >>> g = bulkCmd(SnmpEngine(),
   ...             CommunityData('public'),
   ...             UdpTransportTarget(('demo.snmplabs.com', 161)),
   ...             ContextData(),
   ...             N, R,
   ...             ObjectType(ObjectIdentity('1.3.6')))
   >>>
   >>> next(g)
   (None, 0, 0, [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'), DisplayString('SunOS zeus.snmplabs.com'))])
   >>> next(g)
   (None, 0, 0, [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.2.0'), ObjectIdentifier('1.3.6.1.4.1.20408'))])

Python generators can not only produce data, but it is also possible
to send data into running generator object. That feature is used by
the high-level API to repeat the same SNMP operation for a new set
of MIB objects.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> g = nextCmd(SnmpEngine(),
   ...             CommunityData('public'),
   ...             UdpTransportTarget(('demo.snmplabs.com', 161)),
   ...             ContextData(),
   ...             ObjectType(ObjectIdentity('IF-MIB', 'ifTable')))
   >>>
   >>> g.send([ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets'))])
   (None, 0, 0, [(ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.10.1'), Counter32(284817787))])

You could operate on many unrelated MIB object just by listing them in
a single PDU. Response PDU will carry a list of MIB objects and their
values in exactly the same order as they were in request message.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> g = getCmd(SnmpEngine(),
   ...            CommunityData('public'),
   ...            UdpTransportTarget(('demo.snmplabs.com', 161)),
   ...            ContextData(),
   ...            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
   ...            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysUpTime', 0))
   ... )
   >>> next(g)
   (None, 0, 0, [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'), DisplayString('SunOS zeus.snmplabs.com')), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'), TimeTicks(44430646))])

Configuration management part of SNMP relies on SNMP *SET* command.
Although its implementation on managed entity's side proved to be
somewhat demanding (due to locking and transactional behavior
requirements). So vendors tend to leave it out thus rendering
managed entity being read-only.

PySNMP supports *SET* uniformly through :py:func:`~pysnmp.hlapi.setCmd`
function.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> g = setCmd(SnmpEngine(),
   ...            CommunityData('public'),
   ...            UdpTransportTarget(('demo.snmplabs.com', 161)),
   ...            ContextData(),
   ...            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0), 'Linux i386')
   ... )
   >>> next(g)
   (None, 0, 0, [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'), DisplayString('Linux i386'))])

Sending SNMP notifications
--------------------------

Managed entity could send unsolicited messages to the managing entity.
That is called notification in SNMP. Notifications help reduce
polling, what may become a problem for large networks.

SNMP notifications are enumerated and each has definite semantics.
This is done through a special, high-level SMI construct called
*NOTIFICATION-TYPE*. Like *OBJECT-TYPE*, that defines a MIB object,
*NOTIFICATION-TYPE* has a unique OID, but instead of SNMP value
references a sequence of other MIB objects. These MIB objects
are specified with the *OBJECTS* clause and when notification is being
sent, their current values are included into the notification message.

.. code-block:: bash

   linkUp NOTIFICATION-TYPE
       OBJECTS { ifIndex, ifAdminStatus, ifOperStatus }
       STATUS  current
       DESCRIPTION
           "..."
   ::= { snmpTraps 4 }

To model *NOTIFICATION-TYPE* construct in PySNMP, we have the
:py:class:`~pysnmp.smi.rfc1902.NotificationType` class that is a
container object. It is identified by the
:py:class:`~pysnmp.smi.rfc1902.ObjectIdentity` class and reference a
sequence of :py:class:`~pysnmp.smi.rfc1902.ObjectType` class
instances.

From behavior standpoint, *NotificationType* looks like a sequence of
*ObjectType* class instances.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> x = NotificationType(ObjectIdentity('IF-MIB', 'linkUp'))
   >>> # ... calling MIB lookup ...
   >>> >>> [ str(y) for x in n ]
   ['SNMPv2-MIB::snmpTrapOID.0 = 1.3.6.1.6.3.1.1.5.3', 'IF-MIB::ifIndex = ', 'IF-MIB::ifAdminStatus = ', 'IF-MIB::ifOperStatus = ']

Sending notification with PySNMP is not much different than sending
SNMP command. The difference is in how PDU var-binds are built.
There are two different kinds of notifications in SNMP: *trap* and
*inform*.

With *trap*, agent-to-manager communication is one-way - no response
or acknowledgement is sent.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> g = sendNotification(SnmpEngine(),
   ...                      CommunityData('public'),
   ...                      UdpTransportTarget(('demo.snmplabs.com', 162)),
   ...                      ContextData(),
   ...                      'trap',
   ...                      NotificationType(ObjectIdentity('IF-MIB', 'linkUp'), instanceIndex=(123,))
   ... )
   >>> next(g)
   (None, 0, 0, [])

The *inform* notification is much like a command. The difference is in
PDU format. Informs are used for manager-to-manager communication as
well as for agent-to-manager.

   >>> from pysnmp.hlapi import *
   >>>
   >>> g = sendNotification(SnmpEngine(),
   ...                      CommunityData('public'),
   ...                      UdpTransportTarget(('demo.snmplabs.com', 162)),
   ...                      ContextData(),
   ...                      'inform',
   ...                      NotificationType(ObjectIdentity('IF-MIB', 'linkUp'), instanceIndex=(123,))
   ... )
   >>> next(g)
   (None, 0, 0, [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'), TimeTicks(0)), ObjectType(ObjectIdentity('1.3.6.1.6.3.1.1.4.1.0'), ObjectIdentity('1.3.6.1.6.3.1.1.5.4')), ObjectType(ObjectName('1.3.6.1.2.1.2.2.1.1.123'), Null('')), ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.7.123'), Null('')), ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.8.123'), Null(''))])

In the latter example you can see MIB objects (ifIndex, ifAdminStatus,
ifOperStatus) being automatically expanded from IF-MIB::linkUp notification.
To address specific row of SNMP table objects by index, the index part
of MIB objects could be passed to *NotificationType* via
*instanceIndex* parameter.

As you can see, the actual values for expanded MIB objects are NULLs.
That's because in these examples our simple scripts do not have access
to those MIB objects. We can supply that missing information by
passing *NotificationType* a dictionary-like object that maps MIB
object OIDs to current values.

   >>> from pysnmp.hlapi import *
   >>>
   >>> mib = {ObjectIdentifier('1.3.6.1.2.1.2.2.1.1.123'): 123,
   ...        ObjectIdentifier('1.3.6.1.2.1.2.2.1.7.123'): 'testing',
   ...        ObjectIdentifier('1.3.6.1.2.1.2.2.1.8.123'): 'up'}
   >>>
   >>> g = sendNotification(SnmpEngine(),
   ...                      CommunityData('public'),
   ...                      UdpTransportTarget(('demo.snmplabs.com', 162)),
   ...                      ContextData(),
   ...                      'inform',
   ...                      NotificationType(ObjectIdentity('IF-MIB', 'linkUp'), instanceIndex=(123,), objects=mib)
   ... )
   >>> next(g)
   (None, 0, 0, [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'), TimeTicks(0)), ObjectType(ObjectIdentity('1.3.6.1.6.3.1.1.4.1.0'), ObjectIdentity('1.3.6.1.6.3.1.1.5.4')), ObjectType(ObjectName('1.3.6.1.2.1.2.2.1.1.123'), InterfaceIndex(123)), ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.7.123'), Integer(3)), ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.8.123'), Integer(1))]) 

High-volume messaging
---------------------

When in comes to managing large network, reading MIB objects
sequentially introduces latency. By some point the latency becomes
intolerable. Solutions to parallelize queries are well known - you
could do that by offloading individual operations into multiple
processes, or multiple threads of execution or build your application
around the asynchronous I/O model.

Compared to other solutions, asynchronous model is most lightweight
and scalable. The idea is simple: never wait for I/O - do something
else whenever possible. The back side of this is that execution flow
becomes non-linear what hurts program analysis by human reader.

PySNMP high-level API is adapted to work with three popular
asynchronous I/O frameworks - :mod:`asyncore`, :mod:`twisted` and
:mod:`asyncio`.
Please, refer to PySNMP :doc:`library reference </docs/api-reference>`
and :doc:`examples </examples/contents>` for more information on
asynchronous API.

