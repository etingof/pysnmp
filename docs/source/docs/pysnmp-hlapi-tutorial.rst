
.. toctree::
   :maxdepth: 2

High-level PySNMP tutorial
==========================

In this tutorial we will gradually build and run a few different
SNMP command requests and notifications. We will be using PySNMP
synchronous high-level API which is the simplest to use.

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
   >>> g = getCmd(

Choosing SNMP protocol and credentials
--------------------------------------

We have a choice of three SNMP protocol versions. To employ
SNMP versions 1 or 2c, we pass properly initialized instance of
:py:class:`~pysnmp.hlapi.CommunityData` class. For the third
SNMP version we pass :py:class:`~pysnmp.hlapi.UsmUserData` class
instance.

SNMP community name, as well as the choice between SNMP v1 and v2c,
is conveyed to SNMP LCD via :py:class:`~pysnmp.hlapi.auth.CommunityData`
object.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>>
   >>> CommunityData('public', mpModel=0)  # SNMPv1
   CommunityData('public')
   >>> CommunityData('public', mpModel=1)  # SNMPv2c
   CommunityData('public')

Use of :py:class:`~pysnmp.hlapi.auth.UsmUserData` object for LCD
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
   >>> g = getCmd(CommunityData('public'),
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
   >>> g = getCmd(CommunityData('public'),
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
   >>> g = getCmd(CommunityData('public'),
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
Data is stored in MIB object instances that are addressed by appending
For scalar MIB objects index is '0' by convention. The
*ObjectIdentity* class takes indices as its initializers.

.. code-block:: python

   >>> x = ObjectIdentity('SNMPv2-MIB', 'system', 0)
   >>> # ... calling MIB lookup ...
   >>> tuple(x)
   (1, 3, 6, 1, 2, 1, 1, 1, 0)

We will be reading *sysDescr* scalar MIB object instance as defined
in *SNMPv2-MIB* module.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>> g = getCmd(CommunityData('public'),
   ...            UdpTransportTarget(('demo.snmplabs.com', 161)),
   ...            ContextData(),
   ...            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))


Reading scalar value
--------------------

We are finally in a position to send SNMP query and hopefully receive
something meaningful in response.

The distinctive feature of synchronous API is that it is build around
the idea of Python generator. Any function invocation ends up with a
generator object. Iteration over the generator object performs actual
SNMP communication. On each iteration SNMP message gets build and send
out, response is awaited, received and parsed.

.. code-block:: python

   >>> from pysnmp.hlapi import *
   >>> g = getCmd(CommunityData('public'),
   ...            UdpTransportTarget(('demo.snmplabs.com', 161)),
   ...            ContextData(),
   ...            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysUpTime', 0)))
   >>> next(g)
   (None, 0, 0, [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'), TimeTicks(44430646))])

Reading SNMP table
------------------

