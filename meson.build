project('CM4all Lukko', 'cpp', version: '0.19',
  meson_version: '>= 0.56',
  default_options: [
    'cpp_std=c++2a',
    'warning_level=3',

    'fmt:cpp_std=c++2a',
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

inc = include_directories('.', 'src', 'libcommon/src')

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
subdir('libcommon/src/thread')
subdir('libcommon/src/lib/avahi')
subdir('libcommon/src/memory')
subdir('src/memory')

if libsystemd.found()
  subdir('libcommon/src/lib/dbus')

  # systemd support also enables the systemd-resolved client which
  # uses a protocol with JSON payloads
  subdir('libcommon/src/event/systemd')
else
  nlohmann_json_dep = dependency('', required: false)
  event_systemd_dep = dependency('', required: false)
endif

alloc = static_library(
  'alloc',
  'src/AllocatorPtr.cxx',
  include_directories: inc,
)

alloc_dep = declare_dependency(
  link_with: alloc,
)

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

if get_option('control')
  subdir('libcommon/src/event/net/control')
  sources += [
    'src/Control.cxx',
  ]
else
  control_server_dep = dependency('', required: false)
endif

conf.set('HAVE_LIBSYSTEMD', libsystemd.found())
conf.set('HAVE_LIBCAP', cap_dep.found())
conf.set('HAVE_AVAHI', avahi_dep.found())
conf.set('HAVE_OPENSSL', crypto_dep.found())
conf.set('HAVE_LIBMD', libmd.found())
conf.set('HAVE_NLOHMANN_JSON', nlohmann_json_dep.found())
conf.set('ENABLE_TRANSLATION', get_option('translation'))
conf.set('ENABLE_CONTROL', get_option('control'))
configure_file(output: 'config.h', configuration: conf)

libdigest = static_library(
  'digest',
  'src/Digest.cxx',
  include_directories: inc,
  dependencies: [
    libmd,
    sodium_dep,
  ],
)

digest_dep = declare_dependency(
  link_with: libdigest,
)

subdir('src/openssl')
subdir('src/key')
subdir('src/cipher')
subdir('src/ssh')

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
  'src/SocketForwardListener.cxx',
  'src/RConnect.cxx',
  'src/RBind.cxx',
  'src/DelegateOpen.cxx',
  'src/OutgoingConnection.cxx',
  'src/net/ClientAccounting.cxx',
  'src/system/SetupProcess.cxx',
  include_directories: inc,
  dependencies: [
    ssh_dep,
    libsystemd,
    fmt_dep,
    event_net_dep,
    event_systemd_dep,
    system_dep,
    io_dep,
    io_config_dep,
    avahi_dep,
    spawn_dep,
    translation_dep,
    control_server_dep,
    key_dep,
    cap_dep,
    coroutines_dep,
    memory_dep,
    thread_pool_dep,
  ],
  install: true,
  install_dir: 'sbin',
)

subdir('doc')

if get_option('test')
  subdir('test')
endif
