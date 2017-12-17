
.. toctree::
   :maxdepth: 2

SNMP history
============

In the early days of networking, when computer networks were research
artifacts rather than a critical infrastructure used by almost every
second human on Earth, "network management" was practically unknown.
Whenever one encountered a network problem, he might run a few pings
to locate the source of the problem and then modify system settings,
reboot hardware or software, or call a remote colleague to check
console at the machine room.

An interesting discussion of the first major "crash" of the ARPAnet in
1980, long before network management tools were available, and the
efforts taken to recover from and understand the crash can be read in
:RFC:`789`. The astonishment of the engineers taking part in
post-mortem investigation could be read between the lines.  As the
public Internet and private intranets have grown from small networks
into a large global infrastructure, the need to more systematically
manage the huge number of hardware and software components within
these networks has grown more important as well.   

SNMP was quickly designed and deployed by a group of university
network researchers and users at a time when the need for network
management was becoming painfully clear.

SNMP milestones:

* Research project, successor of SGMP
* SNMPv1 in 1988: initial revision
* SNMPv2 in 1993: improvements
* SNMPv3 in 1999: full redesign
* SNMPv3: backward compatible
* SNMPv3: full Internet standard (STD0062)

SNMP was initially thought as an interim solution to fill the need for
network management tool while a more theoretically sound system was
being developed by the ISO.  Anticipating the transition to the new
network management system, SNMP designers made SNMP modular. Although
that transition never occurred, the modularity of SNMP help it
evolving through three major versions and found widespread use and
acceptance.

The IETF recognizes SNMP version 3 as defined by :RFC:`3411` ..
:RFC:`3418` as the current standard version of SNMP. The IETF has
designated SNMPv3 a full Internet standard, the highest maturity level
for an RFC. In practice, SNMP implementations often support multiple
versions: typically SNMPv1, SNMPv2c, and SNMPv3

Is it still relevant?
---------------------

Considering how old SNMP is you might be wondering why it is still in
use and is there a more modern alternative? Apparently, SNMP is still
the primary way to do performance and fault management. SNMP is
universally supported by all networking hardware manufactures and
network management applications.

Perhaps one reason for SNMP being so tenacious is that, considering
SNNP's wide deployment, it takes too much effort to migrate to
anything else.  But the other reason is that no significant drawbacks
have been found in SNMP at least in the areas of fault and performance
management.

Additionally, SNMP is free and not controlled by any particular
vendor. No copyright or licensing fees are required, so anyone can use
it or build SNMP products on it.

Despite significant efforts made by technology companies and standards
bodies over all these years, no other network monitoring standard
was adopted so far. The most prominent open alternative is probably
NETCONF (:RFC:`6241`). However it mostly targets configuration
management tasks rather than fault or performance monitoring.
Additionally, NETCONF is significantly more resource intensive than
SNMP is.

It is obviously possible to for everybody to come up with its own
ad-hoc management system. That can be done very easily on top of
HTTPS/JSON, for example. However that would only work with your
application. Also, SSL engine might be heavier on resources.

Current and future uses
-----------------------

As for current SNMP deployment, its virtually impossible to estimate 
how many SNMP-enabled devices run on the modern Internet today.
For example, every home router and most of the desktop printers have
embedded SNMP agent inside.

Expanding on that, you may found SNMP useful for your home network monitoring.
For instance you could easily setup an open source network monitoring
application to watch, collect and graph bandwidth utilization of your
home Wi-Fi router.

A significant innovation might be coming in the following years. And that
is Internet of Things. All those small and low-power gadgets need to
be monitored and managed. And that may bring new life to the SNMP
technology. Almost three decades ago SNMP was designed for heavily
resource-constrained computers of that time. Later on the computers
grew in power and resources. But now we are back to building a massive
amount of low-power computers for "things" where original lightweight
and well-understood SNMP can serve us again!
