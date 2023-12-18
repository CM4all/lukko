libssh_sources = []

if ssh_openssl_dep.found()
  libssh_sources += [
    'KexECDH.cxx',
  ]
endif

libssh = static_library(
  'ssh',
  libssh_sources,
  'Input.cxx',
  'Output.cxx',
  'Connection.cxx',
  'CConnection.cxx',
  'Channel.cxx',
  'BufferedChannel.cxx',
  'KexFactory.cxx',
  'KexCurve25519.cxx',
  'KexHash.cxx',
  'KexProposal.cxx',
  'KexState.cxx',
  'TerminalMode.cxx',
  include_directories: inc,
  dependencies: [
    cipher_dep,
    key_dep,
    sodium_dep,
    crypto_dep,
    event_net_dep,
    memory_dep,
    thread_pool_dep,
    system_dep,
    util_dep,
  ],
)

ssh_dep = declare_dependency(
  link_with: libssh,
  dependencies: [
    event_net_dep,
  ],
)
