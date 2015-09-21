
High-level SNMP
===============

This chapter illustrates various uses of the high-level programming 
interfaces to some of Standard SNMP Applicaitons, as defined in 
`RFC3413 <https://tools.ietf.org/html/rfc3413>`_. 
The so called high-level API (hlapi) is designed to be simple, concise and 
suitable for the most frequent operations. For that matter only 
Command Generator and Notification Originator Applications are currently 
wrapped into a nearly one-line Python expression.

.. note:: The following examples involve creating Python iterator, 
          the next() call is used to invoke iterator just once.

In most examples approximate analogues of well known Net-SNMP snmp* tools
command line options are shown. That may help those readers who, by chance
are familiar with Net-SNMP tools, better understanding what example code doe

Command Generator Applications
------------------------------

Here's a quick example on a simple SNMP GET by high-level API:

.. include:: /../../examples/hlapi/asyncore/manager/cmdgen/v1-get.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/asyncore/manager/cmdgen/v1-get.py
   :start-after: """#
   :language: python

To make use of SNMPv3 and USM, the following code performs a series of
SNMP GETNEXT operations effectively fetching a table of SNMP variables
from SNMP Agent:

.. include:: /../../examples/hlapi/asyncore/manager/cmdgen/pull-whole-mib.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/asyncore/manager/cmdgen/pull-whole-mib.py
   :start-after: """#
   :language: python

More examples on Command Generator API usage follow.

.. toctree::

   /examples/hlapi/asyncore/manager/cmdgen/snmp-versions
   /examples/hlapi/asyncore/manager/cmdgen/modifying-variables
   /examples/hlapi/asyncore/manager/cmdgen/walking-operations
   /examples/hlapi/asyncore/manager/cmdgen/table-operations
   /examples/hlapi/asyncore/manager/cmdgen/mib-tweaks
   /examples/hlapi/asyncore/manager/cmdgen/transport-tweaks
   /examples/hlapi/asyncore/manager/cmdgen/asynchronous-operations
   /examples/hlapi/asyncore/manager/cmdgen/advanced-topics

Notification Originator Application
-----------------------------------

Sending SNMP TRAP's and INFORM's is as easy with PySNMP library.
The following code sends SNMP TRAP:

.. include:: /../../examples/hlapi/asyncore/agent/ntforg/default-v1-trap.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/asyncore/agent/ntforg/default-v1-trap.py
   :start-after: """#
   :language: python

More examples on Notification Originator API usage follow.

.. toctree::

   /examples/hlapi/asyncore/agent/ntforg/snmp-versions
   /examples/hlapi/asyncore/agent/ntforg/common-notifications
   /examples/hlapi/asyncore/agent/ntforg/snmp-v1-trap-variants
   /examples/hlapi/asyncore/agent/ntforg/evaluating-notification-type
   /examples/hlapi/asyncore/agent/ntforg/asynchronous-operations
   /examples/hlapi/asyncore/agent/ntforg/advanced-topics

More sophisticated or less popular SNMP operations can still be performed 
with PySNMP through its Native API to Standard SNMP Applications.
