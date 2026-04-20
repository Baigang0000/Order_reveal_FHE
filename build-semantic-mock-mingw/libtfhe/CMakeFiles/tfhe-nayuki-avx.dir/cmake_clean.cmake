file(REMOVE_RECURSE
  "libtfhe-nayuki-avx.dll"
  "libtfhe-nayuki-avx.dll.a"
  "libtfhe-nayuki-avx.dll.manifest"
  "libtfhe-nayuki-avx.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang ASM C CXX)
  include(CMakeFiles/tfhe-nayuki-avx.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
