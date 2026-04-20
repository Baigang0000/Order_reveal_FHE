file(REMOVE_RECURSE
  "libtfhe-spqlios-fma.dll"
  "libtfhe-spqlios-fma.dll.a"
  "libtfhe-spqlios-fma.dll.manifest"
  "libtfhe-spqlios-fma.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang ASM CXX)
  include(CMakeFiles/tfhe-spqlios-fma.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
