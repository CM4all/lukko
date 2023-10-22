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

- ``translation_server``: consult this translation server to configure
  child processes; must start with :file:`/` (absolute path) or
  :file:`@` (abstract socket).


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
