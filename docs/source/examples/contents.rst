 
Example scripts
===============

.. toctree::
   :maxdepth: 2

SNMP is not simple (PySNMP implementation takes over 15K lines of
Python code), but PySNMP tries to hide the complexities and let you
carry out typical SNMP operations in a quick and intuitive way.

PySNMP offers high and low-level programming interfaces to deal with
SNMP protocol.

The other dimension of differences in the PySNMP APIs is that there are
two different SNMP implementations - the initial architecture
(`RFC1901 <https://tools.ietf.org/html/rfc1901>`_ ..
`RFC1905 <https://tools.ietf.org/html/rfc1905>`_) also known as SNMP v1 architecture
and the redesigned variant (`RFC3413 <https://tools.ietf.org/html/rfc3413>`_
and others) -- SNMPv3 architecture.

.. note::

   The SNMP v1 architecture supports SNMP protocol versions 1 and 2c,
   while SNMP v3 architecture supports versions 1, 2c and 3. Whatever
   new amendments to the SNMP protocol may come up in the future, they
   will be implemented within the v3 model.

High-level SNMP
---------------

The high-level API (`hlapi`) is designed to be simple, concise and
suitable for the most typical client-side operations. For that matter,
only Command Generator and Notification Originator Applications are
wrapped into a nearly one-line Python expression.

The `hlapi` interfaces come in several flavours: one synchronous
and a bunch of asynchronous, adapted to work withing the event loops
of popular asynchronous I/O frameworks.

The primary reason for maintaining high-level API over both `v1arch` and
`v3arch` is performance - `v3arch` machinery is much more functional and complicated
internally, that translates to being heavier on resources and therefore slower.

The v3 architecture
+++++++++++++++++++

.. toctree::
   :maxdepth: 2

   /examples/hlapi/v3arch/asyncore/sync/contents

.. toctree::
   :maxdepth: 2

   /examples/hlapi/v3arch/asyncore/contents

.. toctree::
   :maxdepth: 2

   /examples/hlapi/v3arch/asyncio/contents

.. toctree::
   :maxdepth: 2

   /examples/hlapi/v3arch/trollius/contents

.. toctree::
   :maxdepth: 2

   /examples/hlapi/v3arch/twisted/contents

The v1 architecture
+++++++++++++++++++

.. toctree::
   :maxdepth: 2

   /examples/hlapi/v1arch/asyncore/sync/contents

.. toctree::
   :maxdepth: 2

   /examples/hlapi/v1arch/asyncore/contents

.. toctree::
   :maxdepth: 2

   /examples/hlapi/v1arch/asyncio/contents

Low-level v3 architecture
-------------------------

Complete implementation of all official Standard SNMP Applications. It 
should let you implement any SNMP operation defined in the standard
at the cost of working at a somewhat low level.

This API also comes in several transport varieties depending on I/O
framework being used.

.. toctree::
   :maxdepth: 2

   /examples/v3arch/asyncore/contents
   /examples/v3arch/asyncio/contents
   /examples/v3arch/trollius/contents
   /examples/v3arch/twisted/contents

Low-level v1 architecture
-------------------------

In cases where performance is your top priority and you only need to 
work with SNMP v1 and v2c systems and you do not mind writing much 
more code, then there is a low-level API to SNMP v1/v2c PDU and 
PySNMP I/O engine. There's practically no SNMP engine or SMI 
infrastructure involved in the operations of these almost wire-level 
interfaces. Although MIB services can still be used separately.

A packet-level API-based application typically manages both SNMP 
message building/parsing and network communication via one or more 
transports. It's fully up to the application to handle failures on 
message and transport levels.

Command Generator
+++++++++++++++++

.. toctree::

   /examples/v1arch/asyncore/manager/cmdgen/fetching-variables
   /examples/v1arch/asyncore/manager/cmdgen/modifying-variables
   /examples/v1arch/asyncore/manager/cmdgen/walking-operations
   /examples/v1arch/asyncore/manager/cmdgen/transport-tweaks

Command Responder
+++++++++++++++++

.. toctree::

   /examples/v1arch/asyncore/agent/cmdrsp/agent-side-mib-implementations

Notification Originator
+++++++++++++++++++++++

.. toctree::

   /examples/v1arch/asyncore/agent/ntforg/transport-tweaks

Notification Receiver
+++++++++++++++++++++

.. toctree::

   /examples/v1arch/asyncore/manager/ntfrcv/transport-tweaks

Low-level SMI/MIB
-----------------

.. toctree::

   /examples/smi/manager/browsing-mib-tree
   /examples/smi/agent/implementing-mib-objects

Using these examples
--------------------

Before doing cut&paste of the code below into your Python interpreter, 
make sure to install pysnmp and its dependencies by running pip or 
easy_install: ::

    # pip pysnmp

There's a public, multilingual SNMP Command Responder and Notification
Receiver configured at
`demo.snmplabs.com <http://snmplabs.com/snmpsim/public-snmp-simulator.html>`_ to let you run PySNMP examples scripts in a cut&paste fashion. If you
wish to use your own SNMP Agent with these scripts, make sure to either
configure your local snmpd and/or snmptrapd or use a valid address and
SNMP credentials of your SNMP Agent in the examples to let them work.

Should you want to use a MIB to make SNMP operations more human-friendly,
you are welcome to search for it and possibly download one from our
`public MIB repository <http://mibs.snmplabs.com/asn1/>`_. Alternatively,
you can configure PySNMP to fetch and cache required MIBs from there
automatically.

If you find your PySNMP application behaving unexpectedly, try to enable 
a /more or less verbose/ built-in PySNMP debugging by adding the 
following snippet of code at the beginning of your application:

.. code-block:: python

    from pysnmp import debug

    # use specific flags or 'all' for full debugging
    debug.setLogger(debug.Debug('dsp', 'msgproc', 'secmod'))

Then run your app and watch stderr. The Debug initializer enables debugging 
for a particular PySNMP subsystem, 'all' enables full debugging. More 
specific flags are:

* io
* dsp
* msgproc
* secmod
* mibbuild
* mibview
* mibinstrum
* acl
* proxy
* app

For more details on PySNMP programming model and interfaces, please 
refer to :doc:`library documentation</docs/api-reference>`.
