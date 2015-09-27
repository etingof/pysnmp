 
Examples scripts
================

.. toctree::
   :maxdepth: 2

SNMP is not really simple (PySNMP implementation takes over 15K lines of
Python code), but PySNMP tries to isolate the complexities and let you 
perform typical SNMP operations in a quick and intuitive way.

PySNMP offers three groups of programming interfaces to deal with 
SNMP protocol. In the order from most consice to most detailed those 
APIs follow.

High-level SNMP
---------------

The so called high-level API (hlapi) is designed to be simple, concise and
suitable for the most frequent operations. For that matter only
Command Generator and Notification Originator Applications are currently
wrapped into a nearly one-line Python expression.

It comes in several flavours: one synchronous and a bunch of bindings to
popular asynchronous I/O frameworks. Those varieties of APIs bring
subtile differences, mostly to better match particular I/O framework
customs. Unless you have a vary specific task, one of high-level APIs might
solve your SNMP needs.

.. toctree::
   :maxdepth: 2

   /examples/hlapi/asyncore/sync/contents

.. toctree::
   :maxdepth: 2

   /examples/hlapi/asyncore/contents

.. toctree::
   :maxdepth: 2

   /examples/hlapi/asyncio/contents

.. toctree::
   :maxdepth: 2

   /examples/hlapi/trollius/contents

.. toctree::
   :maxdepth: 2

   /examples/hlapi/twisted/contents

Native SNMP API
---------------

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

Packet-level SNMP
-----------------

Low-level API that lets you build SNMP messages from Python 
objects and exchange them through asyncore transport (or you could 
write your own). These interfaces are very low-level and aimed at 
a rather specific programming tasks.

.. toctree::
   :maxdepth: 2

   /examples/v1arch/asyncore/contents

Using these examples
--------------------

Before doing cut&paste of the code below into your Python interpreter, 
make sure to install pysnmp and its dependencies by running pip or 
easy_install: ::

    # pip pysnmp

There's a `public SNMP responder <http://snmpsim.sourceforge.net/public-snmp-simulator.html>`_ 
configured at *demo.snmplabs.com:161* to let you run PySNMP examples
scripts in a cut&paste fashion. If you wish to use your own SNMP Agent
with these scripts, make sure to either configure your local snmpd and/or
snmptrapd or use a valid address and SNMP credentials of your SNMP Agent
in the examples to let them work.

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
    debug.setLogger(debug.Debug('dsp', 'msgproc', 'secmode'))

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
refer to :doc:`library documentation</docs/contents>`.
