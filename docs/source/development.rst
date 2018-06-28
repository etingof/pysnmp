
Further development
-------------------

Although PySNMP is already a mature software and it is being used at many 
places, the ultimate goal of the project is to implement most of the useful
features that SNMP standards can offer. What follows is a list of most 
prominent missing features that PySNMP developers are planning to put their 
hands on in the future.

PySNMP library
++++++++++++++

#. Built-in MIB parser. PySNMP uses a data model of its own to work with
   information contained in MIB files. To convert ASN.1-based MIB texts
   into Python modules, an off-line, third-party tool is employed. As it
   turns out, this approach has two major drawback: one is that PySNMP
   users may need to pre-process MIB texts to use them with their
   PySNMP-based applications. Another is that LibSMI's Python driver
   seems to miss some information carried by MIBs. Thus the solution would
   be to write another MIB parser and code generator which would produce
   PySNMP compliant Python code right from MIB text files all by itself.

   **Done:** see `PySMI project <http://snmplabs.com/pysmi/>`_ in conjuction with the latest PySNMP codebase.

#. Reverse MIB index. The variable-bindings received by the system whilst 
   in Manager role could be post-processed using the information kept in 
   MIB files to include human-friendly OIDs names, tables indices and 
   values representation. However, there is currently no provisioning in 
   the PySNMP system for locating and loading up MIB files containing 
   additional information on arbitrary OIDs. So the idea is to maintain 
   an OID-to-MIB index to let PySNMP load relevant MIB automatically on 
   demand.

#. Stream sockets support. Currently, PySNMP transport subsystem only 
   supports datagram-type network sockets. That covers UDP-over-IPv4 and 
   UDP-over-IPv6. However, SNMP engine can potentially run over 
   stream-oriented protocols what would let it support TCP-over-IPv4, 
   TCP-over-IPv6 and SSL/TSL transports. Neither of these is currently 
   implemented with PySNMP.

#. AgentX implementation. We anticipate many uses of this. For instance,
   having AgentX protocol support in pure-Python would let us write AgentX 
   modules in pure-Python and attach them to high-performance Net-SNMP 
   Agent. Or we could build and maintain a fully-featured, stand-alone 
   PySNMP-based Agent so that users would write their own AgentX extensions 
   what would comprise a complete SNMP Agent solution at lesser effort.

#. A DBMS-based SMI. Currently implemented SMI takes shape of live Python 
   objects that let user hook up his own handler on any existing Managed 
   Object Instance. That's flexible and working approach in many cases,
   however sometimes, for instance when Management Instrumentation is 
   inherently DBMS-based, it may be more efficient to move the entire 
   SMI/MIB subsystem into a database. PySNMP engine would talk to it 
   through its simple and well defined SMI API.

Stand-alone PySNMP-based tools
++++++++++++++++++++++++++++++

#. SNMP Proxy Forwarder. That would be a stand-alone, application-level 
   proxy service supporting all SNMP versions, multiple network transports, 
   Command and Notification SNMP message types. Its anticipated features 
   include extensive configuration facilities, fine-graned access 
   control and logging.

   **Done:** see `SNMP Proxy Forwarder <http://snmplabs.com/snmpfwd/>`_.

#. SNMP Trap Receiver. We see this application as a simple yet flexible 
   SNMP TRAP collector. It would listen on network sockets of different 
   types receiving SNMP TRAP/INFORM notifications over any SNMP version 
   and putting all the details into a database and possibly triggering 
   external events.

#. Database backend for SNMP Simulator. We have already built a tool for 
   simulating SNMP Agents based on a snapshot of their Management 
   Instrumentation state. Current implementation uses a plain-text file 
   for keeping and possibly managing the snapshot. Many users of the 
   Simulator software requested a value variation feature to be supported 
   so that simulated Agents would look live, not static. We consider this 
   variation and also dependencies features would be best implemented as 
   a relational database application. So we are planning to put some more 
   efforts into the Simulator project as time permits. 

   **Done:** since `snmpsim-0.2.4 <http://snmplabs.com/snmpsim/>`_ 

If you need some particular feature - please, 
`open a feature request <https://github.com/etingof/pysnmp/issues/new>`_ . Once we 
see a greater demand in particular area, we would re-arrange our 
development resources to meet it sooner. 

You could greater speed up the development of particular feature by 
sponsoring it. Please get back to us to discuss details.

Contributions to the PySNMP source code is greatly appreciated as well. 
We require contributed code to run with Python 2.4 through the latest 
Python version (which is 3.7 at the time of this writing). Contributed
code will be redistributed under the terms of the same 
`license <http://snmplabs.com/pysnmp/>`_ as PySNMP is.

