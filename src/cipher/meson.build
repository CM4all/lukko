cipher_sources = [
  'Factory.cxx',
  'ChaCha20Poly1305Cipher.cxx',
  'HmacSHA256Cipher.cxx',
]

if crypto_dep.found()
  cipher_sources += 'OsslCipher.cxx'
endif

libcipher = static_library(
  'cipher',
  cipher_sources,
  include_directories: inc,
  dependencies: [
    sodium_dep,
  ],
)

cipher_dep = declare_dependency(
  link_with: libcipher,
  dependencies: [
  ],
)
