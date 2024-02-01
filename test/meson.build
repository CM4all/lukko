gtest_main_dep = dependency('gtest', main: true, fallback: ['gtest', 'gtest_main_dep'])
gtest = declare_dependency(
  dependencies: [gtest_main_dep],
  #compile_args: gtest_compile_args,
)

test_sources = []

if crypto_dep.found()
  test_sources += 'TestBignumSerializer.cxx'
endif

test(
  'TestLukko',
  executable(
    'TestLukko',
    test_sources,
    'TestKeys.cxx',
    'TestAuthorizedKeys.cxx',
    'TestWriteBignum2.cxx',
    include_directories: inc,
    dependencies: [
      gtest,
      key_dep,
    ],
  ),
)
