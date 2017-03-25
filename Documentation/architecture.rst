Cilium Architecture Guide
=========================

The goal of this document is to describe the components of the Cilium architecture, and the different models for deploying Cilium within
your datacenter or cloud environment.  It focuses on the higher-level understanding required to run a full Cilium deployment and understand
its behavior.  You can then use the more detailed Cilium Installation & Configuration Guide to understand the details of setting up Cilium.

The concepts sections introduces you to the base concepts of Cilium and
introduces you to all the components.

Cilium Components
-----------------

A deployment of Cilium consists of the following components running on each Linux container host in the container cluster:

* **Cilium Agent:** Userspace daemon that interacts with the container runtime to setup networking for each container.  Has an API
  for configuring network security policies, extracting network visibility data, etc.

* **Cilium CLI Client:** Simple CLI client for communicating with the local Cilium Agent, for example, to configure network security or visibility
  policies.

* **Linux Kernel BPF:** Integrated capability of the Linux kernel to accept compiled bytecode that is run at various hook/trace points within
  the kernel.  Cilium compiles BPF programs and has the kernel run them at key points in the network stack to have visibility and control over all
  network traffic in/out of all containers.


In addition to the components that run on each Linux container host, Cilium leverages a key-value store (e.g., etcd, consul) to
share data between Cilium Agents running on differnet nodes.

TODO: need a graphic here.

Cilium Agent
^^^^^^^^^^^^

TODO

Cilium CLI Client
^^^^^^^^^^^^^^^^^

TODO

Linux Kernel BPF
^^^^^^^^^^^^^^^^

TODO

Key-Value Store
^^^^^^^^^^^^^^^
The Key-Value (KV) Store is used for the following state:
* policy identities: list of labels <=> policy identity identifier
* gloabl services: global service id to VIP association (optional)
* Encapsulation VTEP mapping (optional)

To simplify things in a larger key-value store can be the same one used by the container
orchestrator (e.g., Kubenetes using etcd).  In single node Cilium deployments used for basic
testing/learning, Cilium can use a "local store", avoiding the need to setup a dedicated K-V store.

Networking
----------

The networking model implemented by Cilium is kept as simple as possible
to require as little networking knowledge as possible. The following
document describes the model in detail and is mainly aimed at developers
and users who want to gain deep understanding.

Addressing
^^^^^^^^^^

Each container receives a global IPv6 plus an optional private IPv4
address which empowers the container to initiate connections to any
other container in the cluster.

It is recommend to use globally unique IPv6 addresses for containers to
avoid NAT. For IPv4, it is unlikely possible to assign individual global
IPv4 addresses so a NAT action must be performed to reach any external
endpoints.

IPv6
~~~~

Cilium allocates addresses for all containers from a single ``/48`` IPv6
prefix called the cluster prefix. If left unspecified, this prefix will
be ``f00d::/48``. Within that prefix, a ``/96`` prefix is dedicated to
each node in the cluster. Although the default prefix will enable
communication within an isolated environment, the prefix is not publicly
routable. It is strongly recommended to specify a public prefix owned by
the user using the ``--node-addr`` option.

If no node address is specified, Cilium will try and generate a unique
node prefix by using the first global scope IPv4 address as a 32 bit
node identifier, e.g. ``f00d:0:0:0:<ipv4-address>::/96``. Within that
``/96`` prefix, each node will independently allocate addresses for
local containers.

Note that only 16 bits out of the ``/96`` node prefix are currently used
when allocating container addresses. This allows to use the remaining 16
bits to store arbitrary connection state when sending packets between
nodes. A typical use for the state is direct server return.

Assuming 32 bits are being used to identify nodes, this leaves another
48 bits unused which can be used to store state when extending Cilium.
The specific allocation of bits in the ``/48`` cluster prefix is
entirely in the control of the user.

Based on the node prefix, two node addresses are automatically generated
by replacing the last 32 bits of the address with ``0:0`` respectively
``0:ffff``. The former is used as the nexthop address for the default
route inside containers, i.e. all packets from a container will be sent
to that address for further routing. The latter represents the Linux
stack and is used to reach the local network stack, e.g. Kubernetes
health checks. See [host connectivity] for additional details.

Example
~~~~~~~

::

    Cluster:        f00d::/48

    Node A prefix:  f00d:0:0:0:A:A::/96
    Node A address: f00d:0:0:0:A:A:0:0/128
    Container on A: f00d:0:0:0:A:A:0:1111/128

    Node B prefix:  f00d:0:0:0:B:B::/96
    Node B address: f00d:0:0:0:B:B:0:0/128
    Container on B: f00d:0:0:0:B:B:0:2222/128

IPv4
~~~~

Cilium will allocate IPv4 addresses to containers out of a ``/16`` node
prefix. This prefix can be specified with the ``--ipv4-range`` option.
If left unspecified, Cilium will try and generate a unique prefix using
the format ``10.X.0.0/16`` where X is replace with the last byte of the
first global scope IPv4 address discovered on the node. This generated
prefix is relatively weak in uniqueness so it is highly recommended to
always specify the IPv4 range.

The address ``10.X.0.1`` is reserved and represents the local node.

IPv6 vs IPv4
------------

Cilium is specifically designed with IPv6 in mind and with native IPv6
as the long term model to address containers in a scalable fashion. For
this purpose, IPv6 is being treated as the primary citizen and although
IPv4 connectivity is supported, its existence is to provide legacy
support.

NAT46
^^^^^

In order to allow for an IPv4 transition period. Cilium can freely
translate between IPv6 and IPv4 within some restrictions. For this
purpose, each container can be assigned an IPv4 address with a host
scope (valid only within the scope of the cluster node). Packets sent to
that IPv4 address get translated to IPv6 and addresses to the IPv6 of
the container. The container is thus reachable via IPv4 without having
an actual IPv4 address assigned to it.

FIXME: Describe options to enable NAT46

For legacy applications which do not make use of ``getaddrinfo()``
properly and thus open an IPv4 socket regardless of the DNS response, a
legacy IPv4 address can be assigned. This behaviour can be enabled per
container to create an incentive for application developers to move to
IPv6.

DNS46
^^^^^

DNS46 is implemented by various DNS servers including BIND and PowerDNS.
It allows to convert IPv4 ``A`` responses into IPV6 ``AAAA`` responses
which represent an IPv4 address. This allows for an IPv6 only container
to reach an IPv4 only endpoint without any changes to the application or
container.

Connecting multiple nodes together
----------------------------------

Cilium supports multiple methods to connect nodes together depending on
your existing network topology.

Regardless of the option chosen, the container itself has no awareness
of the underlying network it runs on, it only contains a default route
which points to the IP address of the node. Given the removal of the
routing cache in the Linux kernel, this reduces the amount of state to
keep to the per connection flow cache (TCP metrics) which allows to
terminate millions of connections in each container.

Direct Routing
^^^^^^^^^^^^^^

This is the standard method and selected if no additional configuration
is provided. In this mode, Cilium will hand all packets which are not
addresses to a local container and not addresses to the local node to
the Linux stack causing it to route the packet as it would route any
other non-local packet. This mode requires the node to enable forwarding
mode:

This requires Linux to be made aware how to reach all other node
prefixes. If all nodes share a common L2 network this will not require
any additional logic. If nodes are only reachable across L3 gateways
then this will require distribution of node prefix routes. It is left up
to the user how to distribute these. Options include running routing
daemons or using a gossip based protocol to distribute routes to each
cluster node.

IPv6
^^^^

Assuming that containers are assigned public IPv6 addresses. This mode
does not require further configuration besides enabling forwarding of
IPv6 packets:

::

    sysctl -w net.ipv6.conf.all.forwarding=1

NAT46
^^^^^

For the special case of NAT46, the private IPv4 source address of the
container must be translated to the pubic IPv4 address of the node if
the packet is to leave the cluster.

FIXME: Provide more details

IPv4
^^^^

FIXME

UDP Encapsulation (Overlay)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The overlay mode encapsulates all packets for non local containers in a
UDP frame which allows to use either IPv4 or IPv6 on the outer header
and can thus integrate nodes across arbitrary L3 networks.

The node ID of a node is automatically derived based on the first global
scope IPv4 address on the node which allows to identify the overlay
endpoint of any container address without requiring to distribute any
additional routes. This again allows to scale unicast traffic to
millions of containers.

Security
--------


