
Library reference
=================

.. toctree::
   :maxdepth: 2

As dealing with many features may overwhelm developers who aim at a 
quick and trivial task, PySNMP employs a layered architecture approach
where the topmost programming API tries to be as simple as possible 
to allow immediate solutions for most common use cases. For instance
it will let you perform SNMP GET/SET/WALK operations by pasting code
snippets from this web-site right into your Python interactive session.

.. toctree::
   /docs/v3arch/asyncore/oneliner/contents

At the basic level, PySNMP offers a complete set of Standard SNMP 
Applications to give you maximum flexibility with integration of SNMP 
facilities into other applications, building special purpose SNMP Agents,
TRAP collectors, Proxy entities and all kinds of SNMP-related things.

Many user applications are built within some input/output framework.
PySNMP offers native bindings to some of these framework.

.. toctree::
..   /docs/v3arch/asyncore/contents
..   /docs/v3arch/asyncio/contents
..   /docs/v3arch/trollius/contents
..   /docs/v3arch/twisted/contents

All programming interfaces mentioned above revolve around the notion
of SNMP Engine:

.. toctree::
   /docs/v3arch/snmp-engine

At the other end of the complexity spectrum, PySNMP offers packet-level 
ASN.1 data structures that let you build, parse and analyze SNMP messages 
travelling over network. This extremely low-level programming interface is 
explained by the SNMPv1/v2c example scripts. If your goal is to conduct 
experiments on the protocol level or optimize for highest possible 
performance - this is a way to go.

.. toctree::
..   /docs/v1arch/asyncore/contents

.. comment::
  MIB support
  -----------

  SNMP suite of standards defines a data model for objects being managed 
  (known as `SMI <http://en.wikipedia.org/wiki/Structure_of_Management_Information>`_), 
  it takes shape of `MIB <http://en.wikipedia.org/wiki/Management_information_base>`_  
  files semi-formally listing and describing capabilities of a SNMP-managed 
  system. In PySNMP, MIB files are converted into Python code objects which 
  could be loaded and executed at run-time by both SNMP Manager (for purposes 
  of data presentation to human beings) and SNMP Agents (as a gateway to 
  backend systems like DBMS).

  MIB conversion is handled automatically by `PySMI <http://pysmi.sf.net>`_
  library. Large collection of original MIB files is maintained at
  `our MIB repository <http://mibs.snmplabs.com/asn1/>`_ .

  .. toctree::
  ..   /docs/smi/contents

