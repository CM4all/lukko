if not crypto_dep.found()
  ssh_openssl_dep = crypto_dep
  subdir_done()
endif

ssh_openssl = static_library(
  'ssh_openssl',
  'DeserializeBN.cxx',
  'DeserializeEC.cxx',
  'DeserializeRSA.cxx',
  'SerializeBN.cxx',
  'SerializeEVP.cxx',
  'Sign.cxx',
  'Verify.cxx',
  include_directories: inc,
  dependencies: [
    digest_dep,
    sodium_dep,
    crypto_dep,
  ],
)

ssh_openssl_dep = declare_dependency(
  link_with: ssh_openssl,
  dependencies: [
    crypto_dep,
  ],
)
