# Install script for directory: /Users/ericbrigham/tfhe/src

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
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
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/tfhe" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/Users/ericbrigham/tfhe/src/include/lagrangehalfc_arithmetic.h"
    "/Users/ericbrigham/tfhe/src/include/lwe-functions.h"
    "/Users/ericbrigham/tfhe/src/include/lwebootstrappingkey.h"
    "/Users/ericbrigham/tfhe/src/include/lwekey.h"
    "/Users/ericbrigham/tfhe/src/include/lwekeyswitch.h"
    "/Users/ericbrigham/tfhe/src/include/lweparams.h"
    "/Users/ericbrigham/tfhe/src/include/lwesamples.h"
    "/Users/ericbrigham/tfhe/src/include/numeric_functions.h"
    "/Users/ericbrigham/tfhe/src/include/orhe.h"
    "/Users/ericbrigham/tfhe/src/include/orhe_metrics.h"
    "/Users/ericbrigham/tfhe/src/include/orhe_plonky2_backend.h"
    "/Users/ericbrigham/tfhe/src/include/polynomials.h"
    "/Users/ericbrigham/tfhe/src/include/polynomials_arithmetic.h"
    "/Users/ericbrigham/tfhe/src/include/tfhe.h"
    "/Users/ericbrigham/tfhe/src/include/tfhe_core.h"
    "/Users/ericbrigham/tfhe/src/include/tfhe_garbage_collector.h"
    "/Users/ericbrigham/tfhe/src/include/tfhe_gate_bootstrapping_functions.h"
    "/Users/ericbrigham/tfhe/src/include/tfhe_gate_bootstrapping_structures.h"
    "/Users/ericbrigham/tfhe/src/include/tfhe_generic_streams.h"
    "/Users/ericbrigham/tfhe/src/include/tfhe_generic_templates.h"
    "/Users/ericbrigham/tfhe/src/include/tfhe_io.h"
    "/Users/ericbrigham/tfhe/src/include/tgsw.h"
    "/Users/ericbrigham/tfhe/src/include/tgsw_functions.h"
    "/Users/ericbrigham/tfhe/src/include/tlwe.h"
    "/Users/ericbrigham/tfhe/src/include/tlwe_functions.h"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/Users/ericbrigham/tfhe/build/libtfhe/cmake_install.cmake")

endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/Users/ericbrigham/tfhe/build/install_local_manifest.txt"
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
  file(WRITE "/Users/ericbrigham/tfhe/build/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
