
.. toctree::
   :maxdepth: 2

SNMP overview
=============

As networks become more complex, in terms of device population, topology
and distances, it has been getting more and more important for network
administrators to have some easy and convenient way for controlling all
pieces of the whole network.

Basic features of a network management system include device information
retrieval and device remote control. Former often takes shape of gathering
device operation statistics, while latter can be seen in device remote
configuration facilities.

For any information to be exchanged between entities, some agreement on
information format and transmission procedure needs to be settled
beforehand. This is what is conventionally called a Protocol.

Large networks nowdays, may host thousands of different devices. To benefit
network manager's interoperability and simplicity, any device on the
network should carry out most common and important management operations in
a well known, unified way. Therefore, an important feature of a network
management system would be a Convention on management information naming
and presentation.

Sometimes, management operations should be performed on large number of
managed devices. For a network manager to complete such a management round
in a reasonably short period of time, an important feature of a network
management software would be Performance.

Some of network devices may run on severely limited resources what invokes
another property of a proper network management facility: Low resource
consumption.

In practice, the latter requirement translates into low CPU cycles and
memory footprint for management software aboard device being managed.

As networking becomes a more crucial part of our daily lives, security
issues have become more apparent. As a side note, even Internet
technologies, having military roots, did not pay much attention to security
initially. So, the last key feature of network management appears to be
Security.

Data passed back and forth through the course of management operations
should be at least authentic and sometimes hidden from possible observers.

All these problems were approached many times through about three decades
of networking history. Some solutions collapsed over time for one reason or
another, while others, such as Simple Network Management Protocol (SNMP),
evolve into an industry standard.

SNMP management architecture
----------------------------

The SNMP management model includes three distinct entities -- Agent,
Manager and Proxy talking to each other over network.

Agent entity is basically a software running somewhere in a networked
device and having the following distinguishing properties:

* SNMP protocol support
* Access to managed device's internals

The latter feature is a source of management information for Agent, as well
as a target for remote control operations.

Modern SNMP standards suggest splitting Agent functionality on two parts.
Such Agents may run SNMP for local processes called Subagents, which
interface with managed devices internals. Communication between Master
Agent and its Subagents is performed using a simplified version of original
SNMP protocol, known as AgentX, which is designed to run only within a
single host.

Manager entity is usually an application used by humans (or daemons) for
performing various network management tasks, such as device statistics
retrieval or remote control.

Sometimes, Agents and Managers may run peer-to-peer within a single entity
that is called Proxy. Proxies can often be seen in application-level
firewalling or may serve as SNMP protocol translators between otherwise
SNMP version-incompatible Managers and Agents.

For Manager to request Agent for an operation on a particular part of
managed device, some convention on device's components naming is needed.
Once some components are identified, Manager and Agent would have to agree
upon possible components' states and their semantics.

SNMP approach to both problems is to represent each component of a device
as a named object, similar to named variables seen in programming
languages, and state of a component maps to a value associated with this
imaginary variable. These are called Managed Objects in SNMP.

For representing a group of similar components of a device, such as network
interfaces, Managed Objects can be organized into a so-called conceptual
table.

Manager talks to Agent by sending it messages of several types. Message
type implies certain action to be taken. For example, GET message instructs
Agent to report back values of Managed Objects whose names are indicated in
message.

There's also a way for Agent to notify Manager of an event occurred to
Agent. This is done through so-called Trap messages. Trap message also
carries Managed Objects and possibly Values, but besides that it has an ID
of event in form of integer number or a Managed Object.

For naming Managed Objects, SNMP uses the concept of Object Identifier. As
an example of Managed Object,
.iso.org.dod.internet.mgmt.mib-2.system.sysName.0 represents human-readable
name of a device where Agent is running.

Managed Objects values are always instances of ASN.1 types (such as
Integer) or SNMP-specific subtypes (such as IpAddress). As in programming
languages, type has an effect of restricting possible set of states Managed
Object may ever enter.

Whenever SNMP entities talk to each other, they refer to Managed Objects
whose semantics (and value type) must be known in advance by both parties.
SNMP Agent may be seen as a primary source of information on Managed
Objects, as they are implemented by Agent. In this model, Manager should
have a map of Managed Objects contained within each Agent to talk to.

SNMP standard introduces a set of ASN.1 language constructs (such as ASN.1
subtypes and MACROs) which is called Structure of Management Information
(SMI). Collections of related Managed Objects described in terms of SMI
comprise Management Information Base (MIB) modules.

Commonly used Managed Objects form core MIBs that become part of SNMP
standard. The rest of MIBs are normally created by vendors who build SNMP
Agents into their products.

More often then not, Manager implementations could parse MIB files and use
Managed Objects information for names resolution, value type determination,
pretty printing and so on. This feature is known as MIB parser support.

The history of SNMP
-------------------

First SNMP version dates back to 1988 when a set of IETF RFC's were first
published (`RFC1065 <http://www.ietf.org/rfc/rfc1065.txt>`_ , 
`RFC1066 <http://www.ietf.org/rfc/rfc1066.txt>`_ ,
`RFC1067 <http://www.ietf.org/rfc/rfc1067.txt>`_ ).
These documents describe protocol operations (in terms of message syntax 
and semantics), SMI and a few core MIBs. The first version appears to 
be lightweight and easy to implement.
Although, its poor security became notorious over years *(Security? 
Not My Problem!)*, because cleartext password used for authentication (AKA
Community String) is extremely easy to eavesdrop and replay, even after
almost 20 years, slightly refined standard ( 
`RFC1155 <http://www.ietf.org/rfc/rfc1155.txt>`_ ,
`RFC1157 <http://www.ietf.org/rfc/rfc1157.txt>`_ , 
`RFC1212 <http://www.ietf.org/rfc/rfc1212.txt>`_ )
still seems to be the most frequent encounter in modern SNMP devices.

In effort to fix security issues of SNMPv1 and to make protocol faster for
operations on large number of Managed Objects, SNMP Working Group at IETF
came up with SNMPv2. This new protocol offers bulk transfers of Managed
Objects information (by means of new, GETBULK message payload), improved
security and re-worked SMI. But its new party-based security system turned
out to be too complicated. In the end, security part of SNMPv2 has been
dropped in favor of community-based authentication system used in SNMPv1.
The result of this compromise is known as SNMPv2c (where "c" stands for
community) and is still widely supported without being a standard (
`RFC1902 <http://www.ietf.org/rfc/rfc1902.txt>`_,
`RFC1903 <http://www.ietf.org/rfc/rfc1903.txt>`_,
`RFC1904 <http://www.ietf.org/rfc/rfc1904.txt>`_,
`RFC1905 <http://www.ietf.org/rfc/rfc1905.txt>`_,
`RFC1906 <http://www.ietf.org/rfc/rfc1906.txt>`_,
`RFC1907 <http://www.ietf.org/rfc/rfc1907.txt>`_,
`RFC1908 <http://www.ietf.org/rfc/rfc1908.txt>`_ ).

The other compromise targeted at offering greater security than SNMPv1,
without falling into complexities of SNMPv2, has been attempted by
replacing SNMPv2 party-based security system with newly developed
user-based security model. This variant of protocol is known as SNMPv2u.
Although neither widely implemented nor standardized, User Based Security
Model (USM) of SNMPv2u got eventually adopted as one of possibly many
SNMPv3 security models.

As of this writing, SNMPv3 is current standard for SNMP. Although it's
based heavily on previous SNMP specifications, SNMPv3 offers many
innovations but also brings significant complexity. Additions to version 3
are mostly about protocol operations. SMI part of standard is inherited
intact from SNMPv2.

SNMPv3 system is designed as a framework that consists of a core, known as
Message and PDU Dispatcher, and several abstract subsystems: Message
Processing Subsystem (MP), responsible for SNMP message handling, Transport
Dispatcher, used for carrying over messages, and Security Subsystem, which
deals with message authentication and encryption issues. The framework
defines subsystems interfaces to let feature-specific modules to be plugged
into SNMPv3 core thus forming particular feature-set of SNMP system.
Typical use of this modularity feature could be seen in multiprotocol
systems -- legacy SNMP protocols are implemented as version-specific MP and
security modules. Native SNMPv3 functionality relies upon v3 message
processing and User-Based Security modules.

Besides highly detailed SNMP system specification, SNMPv3 standard also
defines a typical set of SNMP applications and their behavior. These
applications are Manager, Agent and Proxy ( 
`RFC3411 <http://www.ietf.org/rfc/rfc3411.txt>`_,
`RFC3412 <http://www.ietf.org/rfc/rfc3412.txt>`_, 
`RFC3413 <http://www.ietf.org/rfc/rfc3413.txt>`_,
`RFC3414 <http://www.ietf.org/rfc/rfc3414.txt>`_,
`RFC3415 <http://www.ietf.org/rfc/rfc3415.txt>`_,
`RFC3416 <http://www.ietf.org/rfc/rfc3416.txt>`_, 
`RFC3417 <http://www.ietf.org/rfc/rfc3417.txt>`_,
`RFC3418 <http://www.ietf.org/rfc/rfc3418.txt>`_ ).

PySNMP architecture
-------------------

PySNMP is a pure-Python SNMP engine implementation. This software deals
with the darkest corners of SNMP specifications all in Python programming
language.

This paper is dedicated to PySNMP revisions 4.2.3 and up. Since PySNMP
API's evolve over time, older revisions may provide slightly different
interfaces than those described in this tutorial. Please refer to
release-specific documentation for a more precise information.

From Programmer's point of view, the layout of PySNMP software reflects
SNMP protocol evolution. It has been written from ground up, from trivial
SNMPv1 up to fully featured SNMPv3. Therefore, several levels of API to
SNMP functionality are available:

* The most ancient and low-level is SNMPv1/v2c protocol scope. Here
  programmer is supposed to build/parse SNMP messages and their payload --
  Protocol Data Unit (PDU), handle protocol-level errors, transport issues
  and so on.

  Although considered rather complex to deal with, this API probably gives
  best performance, memory footprint and flexibility, unless MIB access
  and/or SNMPv3 support is needed.

* Parts of SNMPv3 standard is expressed in terms of some abstract API to SNMP
  engine and its components. PySNMP implementation adopts this abstract API
  to a great extent, so it's available at Programmer's disposal. As a side
  effect, SNMP RFCs could be referenced for API semantics when programming
  PySNMP at this level.

  This API is much more higher-level than previous; here Programmer would
  have to manage two major issues: setting up Local Configuration Datastore
  (LCD) of SNMP engine and build/parse PDUs. PySNMP system is shipped
  multi-lingual, thus at this level all SNMPv1, SNMPv2c and SNMPv3 features
  are available.

* At last, the highest-level API to SNMP functionality is available through
  the use of standard SNMPv3 applications. These applications cover the most
  frequent needs. That's why this API is expected to be the first to start
  with.

  The Applications API further simplifies Programmer's job by hiding LCD
  management issues (contrary to SNMPv3 engine level). This API could be
  exploited in a oneliner fashion, for quick and simple prototyping.

As for its internal structure, PySNMP consists of a handful of large,
dedicated components. They normally take shape of classes which turn into
linked objects at runtime. So here are the main components:

* SNMP Engine is an object holding references to all other components of the
  SNMP system. Typical user application has a single instance of SNMP Engine
  class possibly shared by many SNMP Applications of all kinds. As the other
  linked-in components tend to buildup various configuration and housekeeping
  information in runtime, SNMP Engine object appears to be expensive to
  configure to a usable state.

* Transport subsystem is used for sending SNMP messages to and accepting them
  from network. The I/O subsystem consists of an abstract Dispatcher and one
  or more abstract Transport classes. Concrete Dispatcher implementation is
  I/O method-specific, consider BSD sockets for example. Concrete Transport
  classes are transport domain-specific. SNMP frequently uses UDP Transport
  but others are also possible. Transport Dispatcher interfaces are mostly
  used by Message And PDU Dispatcher. However, when using the
  SNMPv1/v2c-native API (the lowest-level one), these interfaces would be
  invoked directly.

* Message And PDU Dispatcher is a heart of SNMP system. Its main
  responsibilities include dispatching PDUs from SNMP Applications through
  various subsystems all the way down to Transport Dispatcher, and passing
  SNMP messages coming from network up to SNMP Applications. It maintains
  logical connection with Management Instrumentation Controller which carries
  out operations on Managed Objects, here for the purpose of LCD access.

* Message Processing Modules handle message-level protocol operations for
  present and possibly future versions of SNMP protocol. Most importantly,
  these include message parsing/building and possibly invoking security
  services whenever required. All MP Modules share standard API used by
  Message And PDU Dispatcher.

* Message Security Modules perform message authentication and/or encryption.
  As of this writing, User-Based (for v3) and Community (for v1/2c) modules
  are implemented in PySNMP. All Security Modules share standard API used by
  Message Processing subsystem.

* Access Control subsystem uses LCD information to authorize remote access to
  Managed Objects. This is used when serving Agent Applications or Trap
  receiver in Manager Applications.

* A collection of dedicated Managed Objects Instances are used by PySNMP for
  its internal purposes. They are collectively called Local Configuration
  Datastore (LCD). In PySNMP, all SNMP engine configuration and statistics is
  kept in LCD. LCD Configurator is a wrapper aimed at simplifying LCD
  operations.

In most cases user is expected to only deal with the high-level, oneliner
API to all these PySNMP components. However implementing SNMP Agents,
Proxies and some other fine features of Managers require using the Standard
Applications API. In those cases general understanding of SNMP operations
and SNMP Engine components would be helpful.
