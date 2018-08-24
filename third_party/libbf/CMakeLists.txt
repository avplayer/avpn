# -- Project Setup ------------------------------------------------------------
cmake_minimum_required(VERSION 2.6)
project(libbf CXX)

#include(CTest)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Silence warning CMP0042
if (APPLE AND NOT DEFINED CMAKE_MACOSX_RPATH)
  set(CMAKE_MACOSX_RPATH true)
endif()

# -- Dependencies -------------------------------------------------------------

find_package(Threads)
if (NOT Threads_FOUND)
  message(FATAL_ERROR "Could not find system threading libraries")
endif ()

if (NOT MSVC)
	set(CMAKE_CXX_FLAGS                "-Wall -Wextra -std=c++11")
	set(CMAKE_CXX_FLAGS_DEBUG          "-O0 -g")
	set(CMAKE_CXX_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
	set(CMAKE_CXX_FLAGS_RELEASE        "-O3 -DNDEBUG")
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")
endif()

if (ENABLE_DEBUG)
  set(CMAKE_BUILD_TYPE Debug)
else ()
  set(CMAKE_BUILD_TYPE Release)
endif ()

# -- libbf -------------------------------------------------------------------

include_directories(${CMAKE_SOURCE_DIR})

set(libbf_headers
  bf/bloom_filter/basic.hpp
  bf/bloom_filter/bitwise.hpp
  bf/bloom_filter/counting.hpp
  bf/bloom_filter/stable.hpp
  bf/bloom_filter/a2.hpp
)
set(libbf_sources
  src/bitvector.cpp
  src/counter_vector.cpp
  src/hash.cpp
  src/bloom_filter/a2.cpp
  src/bloom_filter/basic.cpp
  src/bloom_filter/bitwise.cpp
  src/bloom_filter/counting.cpp
  src/bloom_filter/stable.cpp

  bf/hash.hpp
  bf/object.hpp
  bf/wrap.hpp
  bf/all.hpp
  bf/bitvector.hpp
  bf/bloom_filter.hpp
  bf/counter_vector.hpp
  bf/h3.hpp
)

source_group("Header Files\\bloom_filter" FILES ${libbf_headers})

add_library(libbf STATIC ${libbf_sources} ${libbf_headers})

target_include_directories(libbf PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(libbf PROPERTIES FOLDER "third_party")
set_target_properties(libbf PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(libbf PROPERTIES OUTPUT_NAME bf PREFIX "lib" CLEAN_DIRECT_OUTPUT 1)

set(LIBBF_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)
set(LIBBF_LIBRARIES libbf PARENT_SCOPE)
