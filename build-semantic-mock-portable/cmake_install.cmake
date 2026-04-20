# Install script for directory: C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Program Files (x86)/tfhe")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "optim")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "C:/msys64/ucrt64/bin/objdump.exe")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/tfhe" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/lagrangehalfc_arithmetic.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/lwe-functions.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/lwebootstrappingkey.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/lwekey.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/lwekeyswitch.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/lweparams.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/lwesamples.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/numeric_functions.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/orhe.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/orhe_metrics.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/orhe_plonky2_backend.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/polynomials.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/polynomials_arithmetic.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/tfhe.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/tfhe_core.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/tfhe_garbage_collector.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/tfhe_gate_bootstrapping_functions.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/tfhe_gate_bootstrapping_structures.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/tfhe_generic_streams.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/tfhe_generic_templates.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/tfhe_io.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/tgsw.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/tgsw_functions.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/tlwe.h"
    "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/src/include/tlwe_functions.h"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/build-semantic-mock-portable/libtfhe/cmake_install.cmake")

endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/build-semantic-mock-portable/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
if(CMAKE_INSTALL_COMPONENT)
  if(CMAKE_INSTALL_COMPONENT MATCHES "^[a-zA-Z0-9_.+-]+$")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
  else()
    string(MD5 CMAKE_INST_COMP_HASH "${CMAKE_INSTALL_COMPONENT}")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INST_COMP_HASH}.txt")
    unset(CMAKE_INST_COMP_HASH)
  endif()
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "C:/Users/baiga/OneDrive/Desktop/orhe-benchmarking/build-semantic-mock-portable/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
