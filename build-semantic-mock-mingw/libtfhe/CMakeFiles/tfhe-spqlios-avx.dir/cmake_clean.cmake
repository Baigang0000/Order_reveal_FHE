file(REMOVE_RECURSE
  "libtfhe-spqlios-avx.dll"
  "libtfhe-spqlios-avx.dll.a"
  "libtfhe-spqlios-avx.dll.manifest"
  "libtfhe-spqlios-avx.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang ASM CXX)
  include(CMakeFiles/tfhe-spqlios-avx.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
