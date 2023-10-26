Lukko
=====

*Lukko* is a SSH server.

This project is work in progress.

For more information, `read the manual
<https://lukko.readthedocs.io/en/latest/>`__ in the ``doc`` directory.


Building Lukko
--------------

You need:

- a C++20 compliant compiler
- `Meson 0.56 <http://mesonbuild.com/>`__ and `Ninja <https://ninja-build.org/>`__
- `libfmt <https://fmt.dev/>`__
- `libsodium <https://www.libsodium.org/>`__
- `libcap2 <https://sites.google.com/site/fullycapable/>`__
- `libseccomp <https://github.com/seccomp/libseccomp>`__

Optional dependencies:

- `Avahi <https://www.avahi.org/>`__
- `systemd <https://www.freedesktop.org/wiki/Software/systemd/>`__
- `OpenSSL <https://www.openssl.org/>`__
- `libmd <https://www.hadrons.org/software/libmd/>`__ for SHA2-384
  digest support

Get the source code::

 git clone --recursive https://github.com/CM4all/lukko.git

Run ``meson``::

 meson setup output

Compile and install::

 ninja -C output
 ninja -C output install
