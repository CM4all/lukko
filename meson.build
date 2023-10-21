project('CM4all Lukko', 'cpp', version: '0.1',
  meson_version: '>= 0.56',
  default_options: [
    'cpp_std=c++2a',
    'warning_level=3',
  ],
)

debug = get_option('b_ndebug') != 'true'

compiler = meson.get_compiler('cpp')

conf = configuration_data()

common_flags = [
  '-D_GNU_SOURCE',

  # disable boost specific code in libcommon
  '-DNO_BOOST',
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

inc = include_directories('src', 'libcommon/src')

libcommon_enable_boost = false
libcommon_require_avahi = get_option('zeroconf')
libcommon_enable_libssl = false

subdir('libcommon/src/util')
subdir('libcommon/src/time')
subdir('libcommon/src/lib/fmt')
subdir('libcommon/src/lib/sodium')
subdir('libcommon/src/lib/openssl')
subdir('libcommon/src/io')
subdir('libcommon/src/system')
subdir('libcommon/src/event')
subdir('libcommon/src/net')
subdir('libcommon/src/event/net')
subdir('libcommon/src/lib/avahi')

conf.set('HAVE_LIBSYSTEMD', libsystemd.found())
conf.set('HAVE_AVAHI', avahi_dep.found())
configure_file(output: 'config.h', configuration: conf)

executable(
  'cm4all-lukko',
  'src/Main.cxx',
  'src/Instance.cxx',
  'src/Listener.cxx',
  'src/Connection.cxx',
  'src/Digest.cxx',
  'src/ssh/Cipher.cxx',
  'src/ssh/Connection.cxx',
  'src/ssh/CConnection.cxx',
  'src/ssh/Channel.cxx',
  'src/ssh/KexCurve25519.cxx',
  'src/ssh/KexHash.cxx',
  'src/ssh/KexProposal.cxx',
  'src/ssh/KexState.cxx',
  'src/openssl/SerializeBN.cxx',
  'src/openssl/SerializeEC.cxx',
  'src/openssl/SerializeEVP.cxx',
  'src/openssl/SignECDSA.cxx',
  'src/key/ECDSAKey.cxx',
  'src/key/Curve25519Key.cxx',
  'src/key/Ed25519Key.cxx',
  'src/system/SetupProcess.cxx',
  include_directories: inc,
  dependencies: [
    libsystemd,
    fmt_dep,
    event_net_dep,
    system_dep,
    io_dep,
    avahi_dep,
    crypto_dep,
    sodium_dep,
    dependency('libmd'),
  ],
  install: true,
  install_dir: 'sbin',
)
