key_sources = []

if ssh_openssl_dep.found()
  key_sources += [
    'ECDSAKey.cxx',
    'RSAKey.cxx',
  ]
endif

libkey = static_library(
  'key',
  key_sources,
  'List.cxx',
  'Ed25519Key.cxx',
  'Parser.cxx',
  'LoadFile.cxx',
  'Options.cxx',
  'Set.cxx',
  'TextFile.cxx',
  'Fingerprint.cxx',
  include_directories: inc,
  dependencies: [
    ssh_openssl_dep,
    digest_dep,
    system_dep,
    io_dep,
  ],
)

key_dep = declare_dependency(
  link_with: libkey,
  dependencies: [
  ],
)
