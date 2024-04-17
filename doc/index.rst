Lukko
=====

What is Lukko?
--------------

Lukko is a SSH server.

This project is work in progress.


Configuration
=============

Lukko loads the configuration file
:file:`/etc/cm4all/lukko/lukko.conf`.

The following top-level settings are recognized:

- ``translation_server``: consult this :ref:`translation server <ts>`
  to configure child processes; must start with :file:`/` (absolute
  path) or :file:`@` (abstract socket).


Listener
--------

The ``listener`` section describes how Lukko listens for incoming SSH
connections.  Example::

  listener {
    bind "*:22"
    #interface "eth0"
    #zeroconf_service "lukko"
  }

Known attributes:

- ``bind``: an adddress to bind to. May be the wildcard ``*`` or an
  IPv4/IPv6 address followed by a port. IPv6 addresses should be
  enclosed in square brackets to disambiguate the port
  separator. Local sockets start with a slash :file:`/`, and abstract
  sockets start with the symbol ``@``.

- ``interface``: limit this listener to the given network interface.

- ``mode``: for local socket files, this specifies the octal file
  mode.

- ``mptcp``: ``yes`` enables Multi-Path TCP

- ``ack_timeout``: close the connection if transmitted data remains
  unacknowledged by the client for this number of seconds. By default,
  dead connections can remain open for up to 20 minutes.

- ``keepalive``: ``yes`` enables the socket option ``SO_KEEPALIVE``.
  This causes some traffic for the keepalive probes, but allows
  detecting disappeared clients even when there is no traffic.

- ``v6only``: ``no`` disables IPv4 support on IPv6 listeners
  (``IPV6_V6ONLY``).  The default is ``yes``.

- ``reuse_port``: ``yes`` enables the socket option ``SO_REUSEPORT``,
  which allows multiple sockets to bind to the same port.

- ``zeroconf_service``: if specified, then register this listener as
  Zeroconf service in the local Avahi daemon.

- ``zeroconf_interface``: publish the Zeroconf service only on the
  given interface.

- ``tag``: a string sent to the :ref:`translation server <ts>` in a
  ``LISTENER_TAG`` packet.

- ``max_connections_per_ip``: specifies the maximum number of
  connections from each IP address.

- ``tarpit``: ``yes`` enables a naive denial-of-service protection:
  clients that connect too often or fail authentication get delayed
  responses.  The exact conditions and the delay is currently
  hard-coded.  The default is ``no``.


Control Listener
----------------

The ``control`` section creates a listener for control datagrams that
can be used to control certain behavior at runtime.  Example::

   control {
     bind "@lukko-control"
   }

   control {
     bind "*"
     interface "eth1"
     multicast_group "224.0.0.123"
   }

Known attributes:

- ``bind``: an adddress to bind to. May be the wildcard ``*`` or an
  IPv4/IPv6 address followed by a port. IPv6 addresses should be
  enclosed in square brackets to disambiguate the port
  separator. Local sockets start with a slash :file:`/`, and abstract
  sockets start with the symbol ``@``.

- ``multicast_group``: join this multicast group, which allows
  receiving multicast commands. Value is a multicast IPv4/IPv6
  address.  IPv6 addresses may contain a scope identifier after a
  percent sign (``%``).

- ``interface``: limit this listener to the given network interface.

The protocol is defined here:
https://github.com/CM4all/libcommon/blob/master/src/net/control/Protocol.hxx

Lukko implements only a subset of the commands:

- ``VERBOSE``
- ``DISABLE_ZEROCONF``
- ``ENABLE_ZEROCONF``
- ``TERMINATE_CHILDREN``


.. _ts:

Translation Server
==================

Lukko can delegate certain decisions (user database, how to execute
commands) to a different process running on the same computer, called
a "translation server".  This translation server may, for example,
consult a database to look up user accounts instead of reading
:file:`/etc/passwd` and can make complex decicions based on that data.
Only the translation server has access to all of Lukko's process
spawner features, which includes a light-weight container engine.

Information about the translation protocol can be found here:

- `documentation
  <https://beng-proxy.readthedocs.io/en/latest/translation.html#login-translation>`__

- `definitions for C++ <https://github.com/CM4all/libcommon/blob/master/src/translation/Protocol.hxx>`__

- `asynchronous framework for C++
  <https://github.com/CM4all/libcommon/tree/master/src/translation/server>`__
