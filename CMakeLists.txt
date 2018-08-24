cmake_minimum_required(VERSION 3.1)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
project(avpn)

include(CheckCXXCompilerFlag)
include(CheckLibraryExists)
include(TestBigEndian)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}/cmake")

if (WIN32)
	include(FindZip)
	message(STATUS ${ZIP_EXECUTABLE})

	add_definitions(-DAVPN_USE_WINAPI -DAVPN_WINDOWS)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	add_definitions(-DAVPN_LINUX)
elseif (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
	add_definitions(-DAVPN_FREEBSD)
endif()

option(ENABLE_JEMALLOC_STATIC "static link to Jemalloc" OFF)
option(ENABLE_TCMALLOC_STATIC "static link to Tcmalloc" OFF)
option(ENABLE_SYSTEM_OPENSSL "link to system openssl" OFF)
option(ENABLE_LOGGING "enable logging" ON)
option(ENABLE_USE_SYSTEMD_LOGGING "use systemd for logging" OFF)

if (USE_GIT)
	find_package(Git)
	gitGetVersion(${CMAKE_CURRENT_SOURCE_DIR} avpn)
	set(VERSION_GIT ${avpn_WC_REVISION_HASH})
	string(TIMESTAMP PVERSION "%Y%m%d-${VERSION_GIT}-${CMAKE_SYSTEM_NAME}")
endif()

if (MSVC)
	set(CompilerFlags
			CMAKE_CXX_FLAGS_DEBUG
			CMAKE_CXX_FLAGS_RELEASE
			CMAKE_CXX_FLAGS_MINSIZEREL
			CMAKE_CXX_FLAGS_RELWITHDEBINFO
			CMAKE_C_FLAGS_DEBUG
			CMAKE_C_FLAGS_RELEASE
			CMAKE_C_FLAGS_MINSIZEREL
			CMAKE_C_FLAGS_RELWITHDEBINFO
		)

	foreach(CompilerFlag ${CompilerFlags})
		string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
	endforeach()

	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
	add_definitions(-D_SCL_SECURE_NO_WARNINGS)
	add_definitions(-D_WIN32_WINNT=0x0600)
	add_definitions(-DBOOST_ALL_STATIC_LINK)
	add_definitions(-DBOOST_THREAD_USE_LIB)
	add_definitions(-DBOOST_FILESYSTEM_STATIC_LINK)
	add_definitions(-DWIN32_LEAN_AND_MEAN)
	add_definitions(-DNOMINMAX)

	if(ENABLE_LOGGING)
		set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DENABLE_LOGGER")
		set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DENABLE_LOGGER_THREAD_SAFE")
	endif()

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /bigobj")

else()
	if(ENABLE_LOGGING)
		set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DENABLE_LOGGER")
		set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DENABLE_LOGGER_THREAD_SAFE")
		set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DENABLE_LOGGER_THREAD_SAFE")
		set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DENABLE_LOGGER_THREAD_SAFE")
		if (ENABLE_USE_SYSTEMD_LOGGING)
			set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DUSE_SYSTEMD_LOGGING -DDISABLE_WRITE_LOGGING")
			set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DUSE_SYSTEMD_LOGGING -DDISABLE_WRITE_LOGGING")
		endif()
	endif()
endif()

CHECK_CXX_COMPILER_FLAG(-fvisibility-inlines-hidden COMPILER_HAS_VISIBILITY_INLINE_HIDDEN)
CHECK_CXX_COMPILER_FLAG(-fvisibility=hidden COMPILER_HAS_VISIBILITY_HIDDEN)
CHECK_CXX_COMPILER_FLAG(-std=c++14 LIBCXX_HAS_STDCXX14_FLAG)
#CHECK_CXX_COMPILER_FLAG(-std=c++17 LIBCXX_HAS_STDCXX17_FLAG)
#CHECK_CXX_COMPILER_FLAG(-std=c++20 LIBCXX_HAS_STDCXX20_FLAG)
CHECK_CXX_COMPILER_FLAG(-fdiagnostics-color=always COMPILER_HAS_COLOR)

#if (${COMPILER_HAS_VISIBILITY_INLINE_HIDDEN})
#	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility-inlines-hidden")
#endif()

#if (${COMPILER_HAS_VISIBILITY_HIDDEN})
#	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")
#endif()

#if (${COMPILER_HAS_COLOR})
#        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdiagnostics-color=always")
#endif()


if (NOT MSVC)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
	if (ANDROID)
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie")
	endif()
	if(LIBCXX_HAS_STDCXX20_FLAG)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20 -O3")
	elseif(LIBCXX_HAS_STDCXX17_FLAG)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -O3")
	elseif(LIBCXX_HAS_STDCXX14_FLAG)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -O3")
	else()
		CHECK_CXX_COMPILER_FLAG(-std=c++0x LIBCXX_HAS_STDCXX0X_FLAG)
		if(LIBCXX_HAS_STDCXX0X_FLAG)
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x -O3")
		else()
			if(NOT CMAKE_CXX_COMPILER MATCHES "icc")
				message(FATAL_ERROR "need at least gcc 4.4.7 or clang 3.2")
			endif(NOT CMAKE_CXX_COMPILER MATCHES "icc")
		endif()
	endif()
endif(NOT MSVC)

# 测试系统大小端.
test_big_endian(TEST_BIG_ENDIAN)

if (TEST_BIG_ENDIAN)
    add_definitions(-DAVPN_BIG_ENDIAN)
else ()
    add_definitions(-DAVPN_LITTLE_ENDIAN)
endif(TEST_BIG_ENDIAN)


set(Boost_USE_STATIC_LIBS		ON)
set(Boost_USE_STATIC_RUNTIME	ON)
add_definitions(-DBOOST_ALL_NO_LIB)

find_package(Threads)

link_libraries(${CMAKE_THREAD_LIBS_INIT})
if (ENABLE_TCMALLOC_STATIC)
	find_package(Tcmalloc)
	link_libraries(${Tcmalloc_LIBRARY})
endif()

if (ENABLE_JEMALLOC_STATIC)
	find_package(Jemalloc)
	link_libraries(${JEMALLOC_LIBRARIES})
endif()

set(BOOST_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost)

add_definitions(-DBOOST_COROUTINES_NO_DEPRECATION_WARNING)
add_subdirectory(third_party/boost)
include_directories(${BOOST_INCLUDE_DIRS})

add_subdirectory(third_party/zlib EXCLUDE_FROM_ALL)
set(ZLIB_LIBRARIES zlib)
set(ZLIB_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/zlib)
link_libraries(${ZLIB_LIBRARIES})

add_subdirectory(third_party/fmt)
set(LIBFMT_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/fmt)
include_directories(${LIBFMT_INCLUDE_DIRS})
set(LIBFMT_LIBRARIES fmt)
link_libraries(${LIBFMT_LIBRARIES})

add_subdirectory(third_party/libsodium)
link_libraries(${SODIUM_LIBRARIES})
include_directories(${SODIUM_INCLUDE_DIRS})

add_subdirectory(vpncore)

include_directories(
	${VPNCORE_INCLUDE_DIRS}
)

if (WIN32)
	link_libraries(Secur32.lib)
elseif(UNIX AND NOT APPLE)
	link_libraries(mnl netlink)
	if (ENABLE_USE_SYSTEMD_LOGGING)
		link_libraries(systemd)
	endif()
endif()

link_libraries(
	Boost::system Boost::thread Boost::chrono Boost::program_options Boost::locale Boost::random Boost::coroutine
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if (WIN32)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/debug)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/release)
endif()

add_subdirectory(avpn)

