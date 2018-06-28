
SNMP library for Python
=======================

.. toctree::
   :maxdepth: 2

PySNMP is a cross-platform, pure-`Python <http://www.python.org/>`_
`SNMP <http://en.wikipedia.org/wiki/Simple_Network_Management_Protocol>`_
engine implementation. It features fully-functional SNMP engine capable 
to act in Agent/Manager/Proxy roles, talking SNMP v1/v2c/v3 protocol 
versions over IPv4/IPv6 and other network transports.

Despite its name, SNMP is not really a simple protocol. For instance its
third version introduces complex and open-ended security framework, 
multilingual capabilities, remote configuration and other features. 
PySNMP implementation closely follows intricate system details and features 
bringing most possible power and flexibility to its users.

Current PySNMP stable version is 4.4. It runs with Python 2.4 through 3.7
and is recommended for new applications as well as for migration from
older, now obsolete, PySNMP releases. All site documentation and 
examples are written for the 4.4 and later versions in mind.
Older materials are still available under the obsolete section.

Besides the libraries, a set of pure-Python 
`command-line tools <https://pypi.python.org/pypi/snmpclitools/>`_
are shipped along with the system. Those tools mimic the interface
and behaviour of popular Net-SNMP snmpget/snmpset/snmpwalk utilities.
They may be useful in a cross-platform situations as well as a testing
and prototyping instrument for pysnmp users.

PySNMP software is free and open-source. Source code is hosted in 
a `Github repo <https://github.com/etingof/pysnmp>`_.
The library is being distributed under 2-clause BSD-style license.

PySNMP library development has been initially sponsored 
by a `PSF <http://www.python.org/psf/>`_ grant.

Quick start
-----------

You already know something about SNMP and have no courage to dive into
this implementation? Try out quick start page!

.. toctree::
   :maxdepth: 2

   /quick-start

Documentation
-------------

.. toctree::
   :maxdepth: 2

   /docs/tutorial
   /docs/api-reference

Examples
--------

.. toctree::
   :maxdepth: 2

   /examples/contents

Download
--------

Best way is usually to

.. code-block:: bash

   # pip install pysnmp
   
If that does not work for you for some reason, you might need to read the 
following page.

.. toctree::
   :maxdepth: 2

   /download

License
-------

.. toctree::
   :maxdepth: 2

   /license

FAQ
---

.. toctree::
   :maxdepth: 2

   /faq

Further development
-------------------

We fanatically document all fixes, changes and new features in changelog.
There you could also download the latest unreleased pysnmp tarball
containing the latest fixes and improvements.

.. toctree::
   :maxdepth: 1

   /changelog

Our development plans and new features we consider for eventual implementation
are collected in the following section.

.. toctree::
   :maxdepth: 2

   /development

Contact
-------

In case of questions or troubles using PySNMP, please open up an
`issue <https://github.com/etingof/pysnmp/issues>`_ at GitHub or ask at
`Stack Overflow <http://stackoverflow.com/questions/tagged/pysnmp>`_ .

Old site archive
----------------

.. toctree::
   :maxdepth: 2

   /oldsite
