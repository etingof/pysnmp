
SNMP with Twisted
=================

`Twisted <http://twistedmatrix.com/>`_ is event-driven networking engine 
written in Python. It takes shape of a Python library which is used by many 
Python applications mostly for network communication purposes. Twisted can 
be seen as a predecessor of eventlet, asyncio.

Twisted offers similar functionality to asyncio and twisted, it can 
replace twisted in PySNMP wrapped by a thin PySNMP Transport Dispatcher
abstraction layer. All SNMP-related functionality of Native API to 
Standard SNMP Applications remains available to Twisted applications.

Command Generator Applications
------------------------------

.. toctree::

   /examples/v3arch/twisted/manager/cmdgen/snmp-versions
   /examples/v3arch/twisted/manager/cmdgen/modifying-variables
   /examples/v3arch/twisted/manager/cmdgen/walking-operations
   /examples/v3arch/twisted/manager/cmdgen/table-operations
   /examples/v3arch/twisted/manager/cmdgen/transport-tweaks
   /examples/v3arch/twisted/manager/cmdgen/advanced-topics


Command Responder Applications
------------------------------

.. toctree::

   /examples/v3arch/twisted/agent/cmdrsp/snmp-versions
   /examples/v3arch/twisted/agent/cmdrsp/agent-side-mib-implementations
   /examples/v3arch/twisted/agent/cmdrsp/transport-tweaks

Notification Originator Applications
------------------------------------

.. toctree::

   /examples/v3arch/twisted/agent/ntforg/common-notifications
   /examples/v3arch/twisted/agent/ntforg/multiple-managers-operations

Notification Receiver Applications
----------------------------------

.. toctree::

   /examples/v3arch/twisted/manager/ntfrcv/snmp-versions
   /examples/v3arch/twisted/manager/ntfrcv/transport-tweaks

For more details on PySNMP programming model and interfaces, please 
refer to the documentation


