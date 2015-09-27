
Asynchronous: trollius
======================

`Trollius <http://trollius.readthedocs.org/>`_ framework offers 
infrastructure that allows you writing single-threaded, concurrent code
using Python coroutines.

Trollius is a backport of `asyncio <https://docs.python.org/3/library/asyncio.html>`_ to Python versions older than 3.3. Trollius supports nearly the same 
API as asyncio. Full support of both asyncio and trollius modules is
built into pysnmp.

All SNMP-related functionality of Native PySNMP API to Standard SNMP 
Applications (`RFC3413 <https://tools.ietf.org/html/rfc3413>`_)
remains available to asyncio-backed applications.

We do not provide Command Generator and Notification Originator examples,
as it is much easier to use 
:doc:`high-level interfaces </examples/hlapi/trollius/contents>` instead.
As for Command Responder and Notification Receiver, those could be use
in the same way as with :doc:`asyncio </examples/v3arch/asyncio/contents>`.

For more details on PySNMP programming model and interfaces, please 
refer to the documentation
