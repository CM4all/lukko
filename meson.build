project('CM4all Lukko', 'cpp', version: '0.7',
  meson_version: '>= 0.56',
  default_options: [
    'cpp_std=c++2a',
    'warning_level=3',
  ],
)

version_h = configuration_data()
version_h.set_quoted('VERSION', meson.project_version())
configure_file(output: 'version.h', configuration: version_h)

debug = get_option('b_ndebug') != 'true'

compiler = meson.get_compiler('cpp')

conf = configuration_data()

common_flags = [
  '-D_GNU_SOURCE',
]

test_common_flags = [
  '-Wcast-align',
  '-Wcast-qual',
  '-Wdouble-promotion',
  '-Wfloat-equal',
  '-Wmissing-declarations',
  '-Wmissing-noreturn',
  '-Wmissing-format-attribute',
  '-Wredundant-decls',
  '-Wshadow',
  '-Wundef',
  '-Wunused',
  '-Wvla',
  '-Wwrite-strings',

  # clang specific warning options:
  '-Wunreachable-code-aggressive',
  #'-Wused-but-marked-unused', (disabled due to OpenSSL)
]

test_global_common_flags = [
  '-fvisibility=hidden',
]

add_global_link_arguments(
  compiler.get_supported_link_arguments(
    # make relocations read-only (hardening)
    '-Wl,-z,relro',

    # no lazy binding, please - not worth it for a daemon
    '-Wl,-z,now',
  ),
  language: 'cpp'
)

if not debug
  test_global_common_flags += [
    '-ffunction-sections',
    '-fdata-sections',
  ]

  add_global_link_arguments(
    compiler.get_supported_link_arguments(
      '-Wl,--gc-sections',
      '-Wl,--icf=all',
    ),
    language: 'cpp'
  )
endif

test_global_cxxflags = test_global_common_flags + [
]

test_cxxflags = test_common_flags + [
  '-fno-threadsafe-statics',
  '-fmerge-all-constants',

  '-Wcomma-subscript',
  '-Wextra-semi',
  '-Wmismatched-tags',
  '-Woverloaded-virtual',
  '-Wsign-promo',
  '-Wvolatile',
  '-Wvirtual-inheritance',

  '-Wno-missing-field-initializers',

  # a vtable without a dtor is just fine
  '-Wno-non-virtual-dtor',

  # clang specific warning options:
  '-Wcomma',
  '-Wheader-hygiene',
  '-Winconsistent-missing-destructor-override',
]

add_global_arguments(common_flags, language: 'c')
add_global_arguments(common_flags, language: 'cpp')

add_global_arguments(compiler.get_supported_arguments(test_global_cxxflags), language: 'cpp')
add_project_arguments(compiler.get_supported_arguments(test_cxxflags), language: 'cpp')

libsystemd = dependency('libsystemd', required: get_option('systemd'))
libmd = dependency('libmd', required: get_option('libmd'))

inc = include_directories('src', 'libcommon/src')

libcommon_require_avahi = get_option('zeroconf')
libcommon_require_cap = get_option('cap')
libcommon_require_libcrypto = get_option('openssl')
libcommon_enable_libssl = false
libcommon_enable_libsystemd = libsystemd.found()
libcommon_enable_json = get_option('json')
libcommon_enable_seccomp = get_option('seccomp')
libcommon_enable_spawn_local = false

openssl_min_version = '3.0.8'
openssl_api_compat = '0x30000000L'

subdir('libcommon/src/util')
subdir('libcommon/src/co')
subdir('libcommon/src/time')
subdir('libcommon/src/lib/fmt')
subdir('libcommon/src/lib/nlohmann_json')
subdir('libcommon/src/lib/sodium')
subdir('libcommon/src/lib/openssl')
subdir('libcommon/src/lib/cap')
subdir('libcommon/src/io')
subdir('libcommon/src/io/config')
subdir('libcommon/src/io/linux')
subdir('libcommon/src/system')
subdir('libcommon/src/event')
subdir('libcommon/src/net')
subdir('libcommon/src/event/net')
subdir('libcommon/src/lib/avahi')

if libsystemd.found()
  subdir('libcommon/src/lib/dbus')

  # systemd support also enables the systemd-resolved client which
  # uses a protocol with JSON payloads
  subdir('libcommon/src/event/systemd')
else
  nlohmann_json_dep = dependency('', required: false)
  event_systemd_dep = dependency('', required: false)
endif

subdir('libcommon/src/adata')
subdir('libcommon/src/spawn')

sources = []

if get_option('translation')
  subdir('libcommon/src/translation')
  sources += [
    'src/translation/LoginClient.cxx',
    'src/translation/LoginGlue.cxx',
  ]
else
  translation_dep = dependency('', required: false)
endif

conf.set('HAVE_LIBSYSTEMD', libsystemd.found())
conf.set('HAVE_LIBCAP', cap_dep.found())
conf.set('HAVE_AVAHI', avahi_dep.found())
conf.set('HAVE_OPENSSL', crypto_dep.found())
conf.set('HAVE_LIBMD', libmd.found())
conf.set('HAVE_NLOHMANN_JSON', nlohmann_json_dep.found())
conf.set('ENABLE_TRANSLATION', get_option('translation'))
configure_file(output: 'config.h', configuration: conf)

key_sources = []

if crypto_dep.found()
  key_sources += [
    'src/openssl/DeserializeBN.cxx',
    'src/openssl/DeserializeEC.cxx',
    'src/openssl/DeserializeRSA.cxx',
    'src/openssl/SerializeBN.cxx',
    'src/openssl/SerializeEVP.cxx',
    'src/openssl/Sign.cxx',
    'src/openssl/Verify.cxx',
    'src/key/ECDSAKey.cxx',
    'src/key/RSAKey.cxx',
    'src/ssh/KexECDH.cxx',
  ]
endif

libkey = static_library(
  'key',
  key_sources,
  'src/Digest.cxx',
  'src/key/List.cxx',
  'src/key/Ed25519Key.cxx',
  'src/key/Parser.cxx',
  'src/key/LoadFile.cxx',
  'src/key/Options.cxx',
  'src/key/Set.cxx',
  'src/key/TextFile.cxx',
  'src/key/Fingerprint.cxx',
  include_directories: inc,
  dependencies: [
    sodium_dep,
    crypto_dep,
    libmd,
    system_dep,
    io_dep,
  ],
)

key_dep = declare_dependency(
  link_with: libkey,
  dependencies: [
  ],
)

cipher_sources = [
  'src/cipher/Factory.cxx',
  'src/cipher/ChaCha20Poly1305Cipher.cxx',
  'src/cipher/HmacSHA256Cipher.cxx',
]

if crypto_dep.found()
  cipher_sources += 'src/cipher/OsslCipher.cxx'
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

executable(
  'cm4all-lukko',
  sources,
  'src/Main.cxx',
  'src/CommandLine.cxx',
  'src/Config.cxx',
  'src/Instance.cxx',
  'src/Listener.cxx',
  'src/Connection.cxx',
  'src/SessionChannel.cxx',
  'src/SocketChannel.cxx',
  'src/RConnect.cxx',
  'src/DelegateOpen.cxx',
  'src/AllocatorPtr.cxx',
  'src/ssh/Connection.cxx',
  'src/ssh/CConnection.cxx',
  'src/ssh/Channel.cxx',
  'src/ssh/KexFactory.cxx',
  'src/ssh/KexCurve25519.cxx',
  'src/ssh/KexHash.cxx',
  'src/ssh/KexProposal.cxx',
  'src/ssh/KexState.cxx',
  'src/ssh/TerminalMode.cxx',
  'src/system/SetupProcess.cxx',
  include_directories: inc,
  dependencies: [
    libsystemd,
    fmt_dep,
    event_net_dep,
    event_systemd_dep,
    system_dep,
    io_dep,
    io_config_dep,
    avahi_dep,
    sodium_dep,
    spawn_dep,
    translation_dep,
    key_dep,
    cipher_dep,
    cap_dep,
    coroutines_dep,
  ],
  install: true,
  install_dir: 'sbin',
)

subdir('doc')

if get_option('test')
  subdir('test')
endif
