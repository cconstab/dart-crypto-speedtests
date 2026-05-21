cmake_minimum_required(VERSION 3.6.0)
project(boringssl_dart LANGUAGES C ASM)

enable_language(ASM)

# BORINGSSL_ROOT must be set to the boringssl source directory WITH a trailing slash.
# Pass via: cmake -DBORINGSSL_ROOT=/path/to/boringssl/
if(NOT DEFINED BORINGSSL_ROOT)
  message(FATAL_ERROR "BORINGSSL_ROOT must be set to the BoringSSL source directory (with trailing slash)")
endif()

# sources.cmake provides crypto_sources + crypto_sources_<platform>_<arch>.
# It requires BORINGSSL_ROOT to be set before include.
include(${BORINGSSL_ROOT}sources.cmake)

# Architecture detection
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "amd64")
  set(ARCH "x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
  set(ARCH "aarch64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^arm")
  set(ARCH "arm")
else()
  set(ARCH "generic")
endif()

# Platform detection  (matches variable names in sources.cmake)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(PLATFORM "linux")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(PLATFORM "apple")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(PLATFORM "win")
else()
  set(PLATFORM "linux")
endif()

# Fall back to no-ASM if this platform+arch combo has no assembly sources.
if(NOT DEFINED crypto_sources_${PLATFORM}_${ARCH})
  add_definitions(-DOPENSSL_NO_ASM)
  set(crypto_sources_${PLATFORM}_${ARCH} "")
endif()

add_library(boringssl_dart SHARED
  ${crypto_sources}
  ${crypto_sources_${PLATFORM}_${ARCH}}
)

target_include_directories(boringssl_dart PRIVATE ${BORINGSSL_ROOT}src/include/)

# Export all symbols so our FFI bindings can look them up by name.
set_target_properties(boringssl_dart PROPERTIES
  C_VISIBILITY_PRESET default
  LINKER_LANGUAGE C
)

target_compile_options(boringssl_dart PRIVATE -O2 -fPIC)
