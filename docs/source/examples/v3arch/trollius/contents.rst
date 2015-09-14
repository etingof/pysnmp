
SNMP with Trollius
==================

`Trollius <http://trollius.readthedocs.org/>`_ framework offers 
infrastructure that allows you writing single-threaded, concurrent code
using Python coroutines.

Trollius is a backport of `asyncio <https://docs.python.org/3/library/asyncio.html>`_ to Python versions older than 3.3. Trollius supports nearly the same 
API as asyncio. Full support of both asyncio and trollius modules is
built into pysnmp.

All SNMP-related functionality of Native PySNMP API to Standard SNMP 
Applications (`RFC3413 <https://tools.ietf.org/html/rfc3413>`_)
remains available to asyncio-backed applications.

Command Generator Applications
------------------------------

.. toctree::

   /examples/v3arch/trollius/manager/cmdgen/fetching-values
   /examples/v3arch/trollius/manager/cmdgen/modifying-variables
   /examples/v3arch/trollius/manager/cmdgen/walking-operations
   /examples/v3arch/trollius/manager/cmdgen/transport-tweaks

Notification Originator Applications
------------------------------------

.. toctree::

   /examples/v3arch/trollius/agent/ntforg/common-notifications

For more details on PySNMP programming model and interfaces, please 
refer to the documentation


