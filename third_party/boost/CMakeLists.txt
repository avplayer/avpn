cmake_minimum_required(VERSION 3.2)
project(Boost)

option(Boost_USE_STATIC_LIBS "" ON)
option(DISABLE_BOOST_LOCALE "not build boost.locale" OFF)

find_path(LAMZ_INCLUDE_DIR lzma.h PATH /usr/include /usr/local/include )
find_library(LAMZ_LIBRARY NAMES lzma)

find_package(ZLIB)
find_package(Iconv)

if (ANDROID)
  set(LZMA_FOUND FALSE)
else()
if (LAMZ_INCLUDE_DIR AND LAMZ_LIBRARY)
  set(LZMA_FOUND TRUE)
else ()
  set(LZMA_FOUND FALSE)
endif ()
endif()


if(WIN32)
ENABLE_LANGUAGE(ASM_MASM)
else()
ENABLE_LANGUAGE(ASM)
endif()

find_package(Threads)

SET(BOOST_ATOMIC_SRC libs/atomic/src/lockpool.cpp)

set(BOOST_REGEX_SRC
	libs/regex/src/regex.cpp
	libs/regex/src/regex_traits_defaults.cpp
	libs/regex/src/wide_posix_api.cpp
	libs/regex/src/w32_regex_traits.cpp
	libs/regex/src/usinstances.cpp
	libs/regex/src/regex_debug.cpp
	libs/regex/src/instances.cpp
	libs/regex/src/fileiter.cpp
	libs/regex/src/cpp_regex_traits.cpp
	libs/regex/src/winstances.cpp
	libs/regex/src/wc_regex_traits.cpp
	libs/regex/src/posix_api.cpp
	libs/regex/src/regex_raw_buffer.cpp
	libs/regex/src/static_mutex.cpp
	libs/regex/src/internals.hpp
	libs/regex/src/c_regex_traits.cpp
	libs/regex/src/icu.cpp
	libs/regex/src/cregex.cpp
)

if(WIN32)
	set(BOOST_THREAD_SRC
		libs/thread/src/tss_null.cpp
		libs/thread/src/future.cpp
		libs/thread/src/win32/thread.cpp
		libs/thread/src/win32/tss_pe.cpp
		libs/thread/src/win32/tss_dll.cpp
		libs/thread/src/win32/thread_primitives.cpp
	)
else()
	set(BOOST_THREAD_SRC
		libs/thread/src/future.cpp
		libs/thread/src/pthread/thread.cpp
		libs/thread/src/pthread/once_atomic.cpp
	)
endif()

set(BOOST_CHRONO_SRC
	libs/chrono/src/chrono.cpp
	libs/chrono/src/thread_clock.cpp
	libs/chrono/src/process_cpu_clocks.cpp
)

set(BOOST_CONTEXT_SRC
	libs/context/src/execution_context.cpp
	libs/context/src/continuation.cpp
	libs/context/src/fiber.cpp
)

if(WIN32)
	list(APPEND BOOST_CONTEXT_SRC libs/context/src/windows/stack_traits.cpp)
	set(ASSEMBLER masm)
	set(ASM_FILE_EXT "asm")
	set(EXEUCTABLEFORMAT "pe")
	set(SYSABI "ms")

	if( CMAKE_SIZEOF_VOID_P EQUAL 8 )
		set(ARCH "x86_64")
	else()
		set(ARCH "i386")
	endif()

else()
	set(ASSEMBLER gas)
	set(ASM_FILE_EXT "S")
	if (APPLE)
	set(EXEUCTABLEFORMAT "macho")
	else()
	set(EXEUCTABLEFORMAT "elf")
	endif()

	list(APPEND BOOST_CONTEXT_SRC libs/context/src/posix/stack_traits.cpp)

	IF("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "x86")
		set(SYSABI "sysv")
		if( CMAKE_SIZEOF_VOID_P EQUAL 8 )
			set(ARCH "x86_64")
		else()
			set(ARCH "i386")
		endif()
	elseif("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "^arm")
		set(SYSABI "aapcs")
		if( CMAKE_SIZEOF_VOID_P EQUAL 8 )
			set(ARCH "arm64")
		else()
			set(ARCH "arm")
		endif()
	elseif ("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "aarch64")
		set(SYSABI "aapcs")
		set(ARCH "arm64")
	elseif ("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "i686")
		set(SYSABI "sysv")
		set(ARCH "i386")
	else()
		message(FATAL_ERROR "unsupported cpu: ${CMAKE_SYSTEM_PROCESSOR}" )
	endif()
endif()

list(APPEND BOOST_CONTEXT_SRC
	libs/context/src/asm/jump_${ARCH}_${SYSABI}_${EXEUCTABLEFORMAT}_${ASSEMBLER}.${ASM_FILE_EXT})
list(APPEND BOOST_CONTEXT_SRC
	libs/context/src/asm/make_${ARCH}_${SYSABI}_${EXEUCTABLEFORMAT}_${ASSEMBLER}.${ASM_FILE_EXT})

list(APPEND BOOST_CONTEXT_SRC
	libs/context/src/asm/ontop_${ARCH}_${SYSABI}_${EXEUCTABLEFORMAT}_${ASSEMBLER}.${ASM_FILE_EXT})

set(BOOST_COROUTINE_SRC
	libs/coroutine/src/detail/coroutine_context.cpp
	libs/coroutine/src/exceptions.cpp
)

if(WIN32)
	list(APPEND BOOST_COROUTINE_SRC libs/coroutine/src/windows/stack_traits.cpp)
else()
	list(APPEND BOOST_COROUTINE_SRC libs/coroutine/src/posix/stack_traits.cpp)
endif()

set(BOOST_FIBER_SRC
	libs/fiber/src/scheduler.cpp
	libs/fiber/src/fiber.cpp
	libs/fiber/src/properties.cpp
	libs/fiber/src/future.cpp
	libs/fiber/src/recursive_mutex.cpp
	libs/fiber/src/context.cpp
	libs/fiber/src/timed_mutex.cpp
	libs/fiber/src/condition_variable.cpp
	libs/fiber/src/algo/shared_work.cpp
	libs/fiber/src/algo/algorithm.cpp
	libs/fiber/src/algo/work_stealing.cpp
	libs/fiber/src/algo/round_robin.cpp
	libs/fiber/src/recursive_timed_mutex.cpp
	libs/fiber/src/mutex.cpp
	libs/fiber/src/barrier.cpp
	libs/fiber/src/numa/algo/work_stealing.cpp
	libs/fiber/src/numa/topology.cpp
)

if (WIN32)
list(APPEND BOOST_FIBER_SRC
	libs/fiber/src/numa/windows/topology.cpp
	libs/fiber/src/numa/windows/pin_thread.cpp
)
elseif(FREEBSD)
list(APPEND BOOST_FIBER_SRC
	libs/fiber/src/numa/freebsd/topology.cpp
	libs/fiber/src/numa/freebsd/pin_thread.cpp
)
else()
list(APPEND BOOST_FIBER_SRC
	libs/fiber/src/numa/linux/topology.cpp
	libs/fiber/src/numa/linux/pin_thread.cpp
)
endif()

set(BOOST_DATE_TIME_SRC

	libs/date_time/src/posix_time/posix_time_types.cpp
	libs/date_time/src/gregorian/greg_weekday.cpp
	libs/date_time/src/gregorian/gregorian_types.cpp
	libs/date_time/src/gregorian/greg_month.cpp
	libs/date_time/src/gregorian/date_generators.cpp
	libs/date_time/src/gregorian/greg_names.hpp
)

set(BOOST_EXCEPTION_SRC libs/exception/src/clone_current_exception_non_intrusive.cpp)

set(BOOST_FILESYSTEM_SRC
	libs/filesystem/src/path_traits.cpp
	libs/filesystem/src/operations.cpp
	libs/filesystem/src/unique_path.cpp
	libs/filesystem/src/utf8_codecvt_facet.cpp
	libs/filesystem/src/codecvt_error_category.cpp
	libs/filesystem/src/path.cpp
	libs/filesystem/src/portability.cpp
)

if (WIN32)
	list(APPEND BOOST_FILESYSTEM_SRC 	libs/filesystem/src/windows_file_codecvt.cpp)
endif()

set(BOOST_LOCALE_SRC
	libs/locale/src/encoding/codepage.cpp
	libs/locale/src/shared/date_time.cpp
	libs/locale/src/shared/generator.cpp
	libs/locale/src/shared/message.cpp
	libs/locale/src/shared/format.cpp
	libs/locale/src/shared/ids.cpp
	libs/locale/src/shared/mo_lambda.cpp
	libs/locale/src/shared/formatting.cpp
	libs/locale/src/shared/localization_backend.cpp
	libs/locale/src/std/collate.cpp
	libs/locale/src/std/numeric.cpp
	libs/locale/src/std/all_generator.hpp
	libs/locale/src/std/codecvt.cpp
	libs/locale/src/std/std_backend.cpp
	libs/locale/src/std/std_backend.hpp
	libs/locale/src/std/converter.cpp
	libs/locale/src/util/locale_data.cpp
	libs/locale/src/util/default_locale.cpp
	libs/locale/src/util/locale_data.hpp
	libs/locale/src/util/numeric.hpp
	libs/locale/src/util/info.cpp
	libs/locale/src/util/codecvt_converter.cpp
	libs/locale/src/util/timezone.hpp
	libs/locale/src/util/gregorian.hpp
	libs/locale/src/util/gregorian.cpp
	libs/locale/src/util/iconv.hpp
)

if (WIN32)
	list(APPEND BOOST_LOCALE_SRC
		libs/locale/src/win32/collate.cpp
		libs/locale/src/win32/lcid.cpp
		libs/locale/src/win32/win_backend.cpp
		libs/locale/src/win32/numeric.cpp
		libs/locale/src/win32/win_backend.hpp
		libs/locale/src/win32/api.hpp
		libs/locale/src/win32/all_generator.hpp
		libs/locale/src/win32/converter.cpp
		libs/locale/src/win32/lcid.hpp
	)
else()
	if (Iconv_FOUND)
		list(APPEND BOOST_LOCALE_SRC
			libs/locale/src/posix/all_generator.hpp
			libs/locale/src/posix/codecvt.hpp
			libs/locale/src/posix/posix_backend.cpp
			libs/locale/src/posix/converter.cpp
			libs/locale/src/posix/posix_backend.hpp
			libs/locale/src/posix/numeric.cpp
			libs/locale/src/posix/collate.cpp
			libs/locale/src/posix/codecvt.cpp
		)
	endif()
endif()

set(BOOST_PROGRAM_OPTIONS_SRC
	libs/program_options/src/winmain.cpp
	libs/program_options/src/value_semantic.cpp
	libs/program_options/src/convert.cpp
	libs/program_options/src/variables_map.cpp
	libs/program_options/src/parsers.cpp
	libs/program_options/src/options_description.cpp
	libs/program_options/src/utf8_codecvt_facet.cpp
	libs/program_options/src/split.cpp
	libs/program_options/src/positional_options.cpp
	libs/program_options/src/cmdline.cpp
	libs/program_options/src/config_file.cpp
)

set(BOOST_IOSTREAM_SRC
	libs/iostreams/src/mapped_file.cpp
	libs/iostreams/src/file_descriptor.cpp
)

if (LZMA_FOUND)
	list(APPEND BOOST_IOSTREAM_SRC
		libs/iostreams/src/lzma.cpp
	)
	message("boost iostreams enable lzma support")
endif()

if (ZLIB_FOUND)
	list(APPEND BOOST_IOSTREAM_SRC
		libs/iostreams/src/zlib.cpp
	)
	message("boost iostreams enable zip support")
endif()

set(BOOST_TIMER_SRC
	libs/timer/src/auto_timers_construction.cpp
	libs/timer/src/cpu_timer.cpp
)

set(BOOST_RANDOM_SRC libs/random/src/random_device.cpp)

add_library(boost_header INTERFACE)
add_library(Boost::boost ALIAS boost_header)
add_library(Boost::system ALIAS boost_header)

if(Boost_USE_STATIC_LIBS)
add_library(boost_atomic STATIC ${BOOST_ATOMIC_SRC})
add_library(Boost::atomic ALIAS boost_atomic)
else()
add_library(boost_atomic SHARED ${BOOST_ATOMIC_SRC})
add_library(Boost::atomic ALIAS boost_atomic)
endif()

if(Boost_USE_STATIC_LIBS)
add_library(boost_thread STATIC ${BOOST_THREAD_SRC})
add_library(Boost::thread ALIAS boost_thread)
else()
add_library(boost_thread SHARED ${BOOST_THREAD_SRC})
add_library(Boost::thread ALIAS boost_thread)
endif()

if(Boost_USE_STATIC_LIBS)
add_library(boost_context STATIC ${BOOST_CONTEXT_SRC})
add_library(Boost::context ALIAS boost_context)
else()
add_library(boost_context SHARED ${BOOST_CONTEXT_SRC})
add_library(Boost::context ALIAS boost_context)
endif()

add_library(boost_coroutine_static STATIC ${BOOST_COROUTINE_SRC})
add_library(Boost::coroutine ALIAS boost_coroutine_static)

if(Boost_USE_STATIC_LIBS)
add_library(boost_fiber STATIC ${BOOST_FIBER_SRC})
add_library(Boost::fiber ALIAS boost_fiber)
else()
add_library(boost_fiber SHARED ${BOOST_FIBER_SRC})
add_library(Boost::fiber ALIAS boost_fiber)
endif()

if(Boost_USE_STATIC_LIBS)
add_library(boost_chrono STATIC ${BOOST_CHRONO_SRC})
add_library(Boost::chrono ALIAS boost_chrono)
else()
add_library(boost_chrono SHARED ${BOOST_CHRONO_SRC})
add_library(Boost::chrono ALIAS boost_chrono)
endif()

if(Boost_USE_STATIC_LIBS)
add_library(boost_filesystem STATIC ${BOOST_FILESYSTEM_SRC})
add_library(Boost::filesystem ALIAS boost_filesystem)
else()
add_library(boost_filesystem SHARED ${BOOST_FILESYSTEM_SRC})
add_library(Boost::filesystem ALIAS boost_filesystem)
endif()

if (NOT DISABLE_BOOST_LOCALE)
	if(Boost_USE_STATIC_LIBS)
		add_library(boost_locale STATIC ${BOOST_LOCALE_SRC})
		add_library(Boost::locale ALIAS boost_locale)

		if (Iconv_FOUND)
			target_compile_definitions(boost_locale PRIVATE -DBOOST_LOCALE_WITH_ICONV)
			if (NOT Iconv_IS_BUILT_IN)
				target_link_libraries(boost_locale Iconv::Iconv)
				target_include_directories(boost_locale PRIVATE ${Iconv_INCLUDE_DIRS})
			endif()
		endif()

	else()
		add_library(boost_locale SHARED ${BOOST_LOCALE_SRC})
		add_library(Boost::locale ALIAS boost_locale)

		if (Iconv_FOUND)
			target_compile_definitions(boost_locale PRIVATE -DBOOST_LOCALE_WITH_ICONV)
			if (NOT Iconv_IS_BUILT_IN)
				target_link_libraries(boost_locale Iconv::Iconv)
				target_include_directories(boost_locale PRIVATE ${Iconv_INCLUDE_DIRS})
			endif()
		endif()

	endif()

endif()

if(Boost_USE_STATIC_LIBS)
add_library(boost_date_time STATIC ${BOOST_DATE_TIME_SRC})
add_library(Boost::date_time ALIAS boost_date_time)
else()
add_library(boost_date_time SHARED ${BOOST_DATE_TIME_SRC})
add_library(Boost::date_time ALIAS boost_date_time)
endif()

if(Boost_USE_STATIC_LIBS)
add_library(boost_regex STATIC ${BOOST_REGEX_SRC})
add_library(Boost::regex ALIAS boost_regex)
else()
add_library(boost_regex SHARED ${BOOST_REGEX_SRC})
add_library(Boost::regex ALIAS boost_regex)
endif()

if(Boost_USE_STATIC_LIBS)
add_library(boost_timer STATIC ${BOOST_TIMER_SRC})
add_library(Boost::timer ALIAS boost_timer)
else()
add_library(boost_timer SHARED ${BOOST_TIMER_SRC})
add_library(Boost::timer ALIAS boost_timer)
endif()

if(Boost_USE_STATIC_LIBS)
add_library(boost_iostreams STATIC ${BOOST_IOSTREAM_SRC})
add_library(Boost::iostreams ALIAS boost_iostreams)
else()
add_library(boost_iostreams SHARED ${BOOST_IOSTREAM_SRC})
add_library(Boost::iostreams ALIAS boost_iostreams)
endif()

if (LZMA_FOUND)
	target_link_libraries(boost_iostreams ${LAMZ_LIBRARY})
	target_include_directories(boost_iostreams PUBLIC ${LAMZ_INCLUDE_DIR})
endif()
if (ZLIB_FOUND)
	target_link_libraries(boost_iostreams ${ZLIB_LIBRARY})
	target_include_directories(boost_iostreams PUBLIC ${ZLIB_INCLUDE_DIRS})
endif()

if(Boost_USE_STATIC_LIBS)
add_library(boost_exception STATIC ${BOOST_EXCEPTION_SRC})
add_library(Boost::exception ALIAS boost_exception)
else()
add_library(boost_exception SHARED ${BOOST_EXCEPTION_SRC})
add_library(Boost::exception ALIAS boost_exception)
endif()

if(Boost_USE_STATIC_LIBS)
add_library(boost_random STATIC ${BOOST_RANDOM_SRC})
add_library(Boost::random ALIAS boost_random)
else()
add_library(boost_random SHARED ${BOOST_RANDOM_SRC})
add_library(Boost::random ALIAS boost_random)
endif()

if(Boost_USE_STATIC_LIBS)
add_library(boost_program_options STATIC ${BOOST_PROGRAM_OPTIONS_SRC} )
add_library(Boost::program_options ALIAS boost_program_options)
else()
add_library(boost_program_options SHARED ${BOOST_PROGRAM_OPTIONS_SRC})
add_library(Boost::program_options ALIAS boost_program_options)
endif()

target_include_directories(boost_header INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(boost_header INTERFACE -DBOOST_ALL_NO_LIB -DBOOST_ALL_STATIC_LINK -DBOOST_THREAD_USE_LIB -DBOOST_FILESYSTEM_STATIC_LINK)

if(Boost_USE_STATIC_LIBS)
target_compile_definitions(boost_thread PRIVATE -DBOOST_THREAD_BUILD_LIB)
else()
target_compile_definitions(boost_thread PRIVATE -DBOOST_THREAD_BUILD_DLL)
endif()

target_compile_definitions(boost_context PUBLIC -DBOOST_ALL_NO_LIB -DBOOST_ALL_STATIC_LINK)
target_compile_definitions(boost_context PRIVATE -DBOOST_CONTEXT_EXPORT)

target_link_libraries(boost_atomic boost_header)
target_link_libraries(boost_filesystem boost_header)
target_link_libraries(boost_thread boost_header Threads::Threads)
target_link_libraries(boost_context boost_header)
target_link_libraries(boost_fiber boost_context)
target_link_libraries(boost_chrono boost_header)

if(NOT DISABLE_BOOST_LOCALE)
target_link_libraries(boost_locale boost_header)
endif()

target_link_libraries(boost_date_time boost_chrono boost_header)
target_link_libraries(boost_regex boost_header)
target_link_libraries(boost_timer boost_chrono boost_header)
target_link_libraries(boost_iostreams boost_header)
target_link_libraries(boost_exception boost_header)
target_link_libraries(boost_random boost_header)
target_link_libraries(boost_program_options boost_filesystem boost_header)


if(WIN32)
	target_compile_definitions(boost_header INTERFACE -DWIN32_LEAN_AND_MEAN -DNOMINMAX)
	if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
		target_compile_definitions(boost_header INTERFACE -DBOOST_SP_USE_STD_ATOMIC -DBOOST_USE_WINDOWS_H)
		set_property(SOURCE libs/locale/src/shared/message.cpp APPEND PROPERTY CMAKE_CXX_FLAGS "-O0")
	endif()
	if(Boost_USE_STATIC_LIBS)
		target_compile_definitions(boost_context PUBLIC -DBOOST_USE_WINFIB)
	endif()
else()
	if(Boost_USE_STATIC_LIBS)
		target_compile_definitions(boost_context PRIVATE -DBOOST_USE_UCONTEXT)
	endif()

endif()

if (NOT DISABLE_BOOST_LOCALE)
set(BOOST_LIBRARIES
	Boost::boost
	Boost::atomic
	Boost::context
	Boost::chrono
	Boost::date_time
	Boost::regex
	Boost::timer
	Boost::exception
	Boost::filesystem
	Boost::thread
	Boost::random
	Boost::program_options
	Boost::locale
PARENT_SCOPE)
else()
set(BOOST_LIBRARIES
	Boost::boost
	Boost::atomic
	Boost::context
	Boost::chrono
	Boost::date_time
	Boost::regex
	Boost::timer
	Boost::exception
	Boost::filesystem
	Boost::thread
	Boost::random
	Boost::program_options
PARENT_SCOPE)
endif()

set_target_properties(boost_atomic PROPERTIES FOLDER "third_party/boost")
set_target_properties(boost_filesystem PROPERTIES FOLDER "third_party/boost")
set_target_properties(boost_thread PROPERTIES FOLDER "third_party/boost")
set_target_properties(boost_context PROPERTIES FOLDER "third_party/boost")
set_target_properties(boost_chrono PROPERTIES FOLDER "third_party/boost")
set_target_properties(boost_locale PROPERTIES FOLDER "third_party/boost")
set_target_properties(boost_date_time PROPERTIES FOLDER "third_party/boost")
set_target_properties(boost_regex PROPERTIES FOLDER "third_party/boost")
set_target_properties(boost_timer PROPERTIES FOLDER "third_party/boost")
set_target_properties(boost_exception PROPERTIES FOLDER "third_party/boost")
set_target_properties(boost_random PROPERTIES FOLDER "third_party/boost")
set_target_properties(boost_program_options PROPERTIES FOLDER "third_party/boost")
set_target_properties(boost_iostreams PROPERTIES FOLDER "third_party/boost")
