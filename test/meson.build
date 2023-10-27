gtest_main_dep = dependency('gtest', main: true, fallback: ['gtest', 'gtest_main_dep'])
gtest = declare_dependency(
  dependencies: [gtest_main_dep],
  #compile_args: gtest_compile_args,
)

test(
  'TestLukko',
  executable(
    'TestLukko',
    'TestKeys.cxx',
    include_directories: inc,
    dependencies: [
      gtest,
      key_dep,
    ],
  ),
)
