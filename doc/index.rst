Lukko
=====

What is Lukko?
--------------

Lukko is a SSH server.

It is not (yet) a drop-in for other SSH implementations such as
OpenSSH.  Lukko is currently used for shared hosting environments with
a large number of user accounts where each session runs in a separate
container.  Maybe it will evolve into a general-purpose SSH server
eventually, but that is not a priority.


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

- ``verbose_errors``: ``yes`` sends internal error messages to the
  client on ``stderr``.

- ``exec_reject_stderr``: ``yes`` means when an ``exec`` request on a
  session channel is rejected (e.g. for SFTP-only accounts), Lukko
  pretends the request has succeeded, but prints an error message on
  ``stderr``.  This is a slight protocol violation but may be less
  confusing for users than the normal OpenSSH client error message
  "shell request failed on channel 0".

- ``pond_server``: send log messages to this Pond server.

- ``proxy_to_zeroconf``: act as proxy, forward all incoming
  connections after the authentication phase to the specified Zeroconf
  cluster.  The connection to this Zeroconf cluster is authenticated
  using the SSH host key with the :ref:`"hostbased" method
  <hostbased>`.  Therefore, this server's host key must be in the
  destination's ``authorized_host_keys`` file.


Zeroconf cluster
----------------

The ``zeroconf_cluster`` section describes a destination for the
``proxy_to_zeroconf`` setting::

  zeroconf_cluster "name" {
    service "lukko-internal"
    interface "internal"
  }

Known attributes:

- ``service``: The name of the Zeroconf service.

- ``domain`` (optional): The name of the Zeroconf service.

- ``interface`` (optional): Look up only on this network interface.

- ``protocol`` (optional): Limit lookups to ``inet`` or ``inet6``.


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


Prometheus Exporter
-------------------

The ``prometheus_exporter`` section is optional and can describe a
simple HTTP listener which exposes statistics in the `Prometheus
format
<https://prometheus.io/docs/instrumenting/writing_exporters/>`__.
Example::

  prometheus_exporter {
    bind "*:8022"
    interface "eth1"
  }

  prometheus_exporter {
    bind "/run/cm4all/lukko/prometheus_exporter.socket"
  }

Known attributes (same meaning as in a ``listener`` block):

- ``bind``
- ``interface``
- ``mode``
- ``v6only``
- ``reuse_port``


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


Authentication
==============

Public Key Authentication
-------------------------

Public keys in :file:`~/.ssh/authorized_keys` and
:file:`/etc/cm4all/lukko/authorized_keys` are allowed to log in.
Lukko supports the OpenSSH file format and implements the following
options:

- ``command``: Forced command.

- ``port-forwarding``, ``no-port-forwarding``: Allow or disallow port
  forwarding.

- ``pty``, ``no-pty``: Allow or disallow tty allocation.

- ``restrict``: Enable all restrictions, i.e. is an alias for
  ``no-port-forwarding`` and ``no-pty``.

- ``home-read-only``: Mount the home directory read-only.

The following OpenSSH options are not implemented and are ignored
silently:

- ``user-rc``, ``no-user-rc``
- ``agent-forwarding``, ``no-agent-forwarding``
- ``X11-forwarding``, ``no-X11-forwarding``


Password Authentication
-----------------------

Passwords are verified by the :ref:`translation server <ts>`,
therefore this authentication method is only available if a
translation server is configured.


.. _hostbased:

Host-Based Authentication
-------------------------

Public keys in :file:`/etc/cm4all/lukko/authorized_host_keys` are
allowed to log in.  This authentication method is only implemented to
allow a proxying/load-balancing feature that is planned for Lukko.
