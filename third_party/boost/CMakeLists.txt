cmake_minimum_required(VERSION 3.2)
project(Boost)

if(WIN32)
	enable_language(ASM_MASM)
else()
	enable_language(ASM)
endif()

find_package(Threads)

set(BOOST_ATOMIC_SRC libs/atomic/src/lockpool.cpp)

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

set(BOOST_SYSTEM_SRC
	libs/system/src/error_code.cpp
)

if(WIN32)
	set(BOOST_THREAD_SRC
		libs/thread/src/tss_null.cpp
		libs/thread/src/future.cpp
		libs/thread/src/win32/tss_dll.cpp
		libs/thread/src/win32/thread.cpp
		libs/thread/src/win32/tss_pe.cpp
		libs/thread/src/win32/thread_primitives.cpp
	)
else()
	set(BOOST_THREAD_SRC
		libs/thread/src/tss_null.cpp
		libs/thread/src/future.cpp
		libs/thread/src/pthread/once.cpp
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
	endif()
endif()

list(APPEND BOOST_CONTEXT_SRC libs/context/src/asm/jump_${ARCH}_${SYSABI}_${EXEUCTABLEFORMAT}_${ASSEMBLER}.${ASM_FILE_EXT})
list(APPEND BOOST_CONTEXT_SRC libs/context/src/asm/make_${ARCH}_${SYSABI}_${EXEUCTABLEFORMAT}_${ASSEMBLER}.${ASM_FILE_EXT})
list(APPEND BOOST_CONTEXT_SRC libs/context/src/asm/ontop_${ARCH}_${SYSABI}_${EXEUCTABLEFORMAT}_${ASSEMBLER}.${ASM_FILE_EXT})

set(BOOST_COROUTINE_SRC
	libs/coroutine/src/detail/coroutine_context.cpp
	libs/coroutine/src/exceptions.cpp
)

if(WIN32)
	list(APPEND BOOST_COROUTINE_SRC libs/coroutine/src/windows/stack_traits.cpp)
else()
	list(APPEND BOOST_COROUTINE_SRC libs/coroutine/src/posix/stack_traits.cpp)
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
	libs/filesystem/src/windows_file_codecvt.hpp
	libs/filesystem/src/codecvt_error_category.cpp
	libs/filesystem/src/path.cpp
	libs/filesystem/src/windows_file_codecvt.cpp
	libs/filesystem/src/portability.cpp
)

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
	list(APPEND BOOST_LOCALE_SRC
		libs/locale/src/posix/collate.cpp
		libs/locale/src/posix/numeric.cpp
		libs/locale/src/posix/posix_backend.cpp
		libs/locale/src/posix/posix_backend.hpp
		libs/locale/src/posix/all_generator.hpp
		libs/locale/src/posix/codecvt.cpp
		libs/locale/src/posix/converter.cpp
		libs/locale/src/posix/codecvt.hpp
	)
endif()

if(CMAKE_COMPILER_IS_GNUCXX)
	add_definitions(-DBOOST_LOCALE_WITH_ICONV)
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

set(BOOST_TIMER_SRC
	libs/timer/src/auto_timers_construction.cpp
	libs/timer/src/cpu_timer.cpp
)

set(BOOST_RANDOM_SRC libs/random/src/random_device.cpp)

set(BOOST_SRCS ${BOOST_ATOMIC_SRC})

add_library(boost_header INTERFACE)
add_library(Boost::boost ALIAS boost_header)

if(Boost_USE_STATIC_LIBS)
	add_library(boost_atomic_static STATIC ${BOOST_ATOMIC_SRC})
	add_library(Boost::atomic ALIAS boost_atomic_static)
else()
	add_library(boost_atomic_dll SHARED ${BOOST_ATOMIC_SRC})
	add_library(Boost::atomic ALIAS boost_atomic_dll)
endif()

if(Boost_USE_STATIC_LIBS)
	add_library(boost_system_static STATIC ${BOOST_SYSTEM_SRC})
	add_library(Boost::system ALIAS boost_system_static)
else()
	add_library(boost_system_dll SHARED ${BOOST_SYSTEM_SRC})
	add_library(Boost::system ALIAS boost_system_dll)
endif()

if(Boost_USE_STATIC_LIBS)
	add_library(boost_thread_static STATIC ${BOOST_THREAD_SRC})
	add_library(Boost::thread ALIAS boost_thread_static)
else()
	add_library(boost_thread_dll SHARED ${BOOST_THREAD_SRC})
	add_library(Boost::thread ALIAS boost_thread_dll)
endif()

if(Boost_USE_STATIC_LIBS)
	add_library(boost_context_static STATIC ${BOOST_CONTEXT_SRC})
	add_library(Boost::context ALIAS boost_context_static)
else()
	add_library(boost_context_dll SHARED ${BOOST_CONTEXT_SRC})
	add_library(Boost::context ALIAS boost_context_dll)
endif()

if(Boost_USE_STATIC_LIBS)
	add_library(boost_coroutine_static STATIC ${BOOST_COROUTINE_SRC})
	add_library(Boost::coroutine ALIAS boost_coroutine_static)
else()
	add_library(boost_coroutine_dll SHARED ${BOOST_COROUTINE_SRC})
	add_library(Boost::coroutine ALIAS boost_coroutine_dll)
endif()

if(Boost_USE_STATIC_LIBS)
	add_library(boost_chrono_static STATIC ${BOOST_CHRONO_SRC})
	add_library(Boost::chrono ALIAS boost_chrono_static)
else()
	add_library(boost_chrono_dll SHARED ${BOOST_CHRONO_SRC})
	add_library(Boost::chrono ALIAS boost_chrono_dll)
endif()

if(Boost_USE_STATIC_LIBS)
	add_library(boost_filesystem_static STATIC ${BOOST_FILESYSTEM_SRC})
	add_library(Boost::filesystem ALIAS boost_filesystem_static)
else()
	add_library(boost_filesystem_dll SHARED ${BOOST_FILESYSTEM_SRC})
	add_library(Boost::filesystem ALIAS boost_filesystem_dll)
endif()

if(Boost_USE_STATIC_LIBS)
	add_library(boost_locale_static STATIC ${BOOST_LOCALE_SRC})
	add_library(Boost::locale ALIAS boost_locale_static)
	if(WIN32)
		target_compile_definitions(boost_locale_static PRIVATE -DBOOST_LOCALE_WITH_WCONV)
	else()
		target_compile_definitions(boost_locale_static PRIVATE -DBOOST_LOCALE_WITH_ICONV)
	endif()
else()
	add_library(boost_locale_dll SHARED ${BOOST_LOCALE_SRC})
	add_library(Boost::locale ALIAS boost_locale_dll)

	if(WIN32)
		target_compile_definitions(boost_locale_dll PRIVATE -DBOOST_LOCALE_WITH_WCONV)
	else()
		target_compile_definitions(boost_locale_dll PRIVATE -DBOOST_LOCALE_WITH_ICONV)
	endif()

endif()


if(Boost_USE_STATIC_LIBS)
	add_library(boost_date_time_static STATIC ${BOOST_DATE_TIME_SRC})
	add_library(Boost::date_time ALIAS boost_date_time_static)
else()
	add_library(boost_date_time_dll SHARED ${BOOST_DATE_TIME_SRC})
	add_library(Boost::date_time ALIAS boost_date_time_dll)
endif()

if(Boost_USE_STATIC_LIBS)
	add_library(boost_regex_static STATIC ${BOOST_REGEX_SRC})
	add_library(Boost::regex ALIAS boost_regex_static)
else()
	add_library(boost_regex_dll SHARED ${BOOST_REGEX_SRC})
	add_library(Boost::regex ALIAS boost_regex_dll)
endif()

if(Boost_USE_STATIC_LIBS)
	add_library(boost_timer_static STATIC ${BOOST_TIMER_SRC})
	add_library(Boost::timer ALIAS boost_timer_static)
else()
	add_library(boost_timer_dll SHARED ${BOOST_TIMER_SRC})
	add_library(Boost::timer ALIAS boost_timer_dll)
endif()

if(Boost_USE_STATIC_LIBS)
	add_library(boost_exception_static STATIC ${BOOST_EXCEPTION_SRC})
	add_library(Boost::exception ALIAS boost_exception_static)
else()
	add_library(boost_exception_dll SHARED ${BOOST_EXCEPTION_SRC})
	add_library(Boost::exception ALIAS boost_exception_dll)
endif()

if(Boost_USE_STATIC_LIBS)
	add_library(boost_random_static STATIC ${BOOST_RANDOM_SRC})
	add_library(Boost::random ALIAS boost_random_static)
else()
	add_library(boost_random_dll SHARED ${BOOST_RANDOM_SRC})
	add_library(Boost::random ALIAS boost_random_dll)
endif()

if(Boost_USE_STATIC_LIBS)
	add_library(boost_program_options_static STATIC ${BOOST_PROGRAM_OPTIONS_SRC} )
	add_library(Boost::program_options ALIAS boost_program_options_static)
else()
	add_library(boost_program_options_dll SHARED ${BOOST_PROGRAM_OPTIONS_SRC})
	add_library(Boost::program_options ALIAS boost_program_options_dll)
endif()

target_include_directories(boost_header INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(boost_system_static PUBLIC -DBOOST_ALL_NO_LIB -DBOOST_ALL_STATIC_LINK -DBOOST_THREAD_USE_LIB -DBOOST_FILESYSTEM_STATIC_LINK)
target_compile_definitions(boost_thread_static PRIVATE -DBOOST_THREAD_BUILD_LIB)
target_compile_definitions(boost_context_static PUBLIC -DBOOST_ALL_NO_LIB -DBOOST_ALL_STATIC_LINK)
target_compile_definitions(boost_context_static PRIVATE -DBOOST_CONTEXT_EXPORT)

if(Boost_USE_STATIC_LIBS)
	target_link_libraries(boost_system_static boost_header)
	target_link_libraries(boost_atomic_static boost_system_static boost_header)
	target_link_libraries(boost_filesystem_static boost_system_static boost_header)
	target_link_libraries(boost_thread_static boost_system_static boost_header Threads::Threads)
	target_link_libraries(boost_context_static boost_header)
	target_link_libraries(boost_coroutine_static boost_context_static boost_system_static boost_header)
	target_link_libraries(boost_chrono_static boost_system_static boost_header)
	target_link_libraries(boost_locale_static boost_system_static boost_header)
	target_link_libraries(boost_date_time_static boost_system_static boost_chrono_static boost_header)
	target_link_libraries(boost_regex_static boost_system_static boost_header)
	target_link_libraries(boost_timer_static boost_system_static boost_chrono_static boost_header)
	target_link_libraries(boost_exception_static boost_system_static boost_header)
	target_link_libraries(boost_random_static boost_system_static boost_header)
	target_link_libraries(boost_program_options_static boost_filesystem_static boost_system_static boost_header)
else()
	target_link_libraries(boost_system_dll boost_header)
	target_link_libraries(boost_atomic_dll boost_system_static boost_header)
	target_link_libraries(boost_filesystem_dll boost_system_static boost_header)
	target_link_libraries(boost_thread_dll boost_system_static boost_header Threads::Threads)
	target_link_libraries(boost_context_dll boost_header)
	target_link_libraries(boost_coroutine_dll boost_context_static boost_system_static boost_header)
	target_link_libraries(boost_chrono_dll boost_system_static boost_header)
	target_link_libraries(boost_locale_dll boost_system_static boost_header)
	target_link_libraries(boost_date_time_dll boost_system_static boost_chrono_static boost_header)
	target_link_libraries(boost_regex_dll boost_system_static boost_header)
	target_link_libraries(boost_timer_dll boost_system_static boost_chrono_static boost_header)
	target_link_libraries(boost_exception_dll boost_system_static boost_header)
	target_link_libraries(boost_random_dll boost_system_static boost_header)
	target_link_libraries(boost_program_options_dll boost_filesystem_static boost_system_static boost_header)
endif()

if(WIN32)
	target_compile_definitions(boost_header INTERFACE -DWIN32_LEAN_AND_MEAN -DNOMINMAX)
	if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
		target_compile_definitions(boost_header INTERFACE -DBOOST_SP_USE_STD_ATOMIC -DBOOST_USE_WINDOWS_H)
		set_property(SOURCE libs/locale/src/shared/message.cpp APPEND PROPERTY CMAKE_CXX_FLAGS "-O0")
	endif()
	target_compile_definitions(boost_context_static PUBLIC -DBOOST_USE_WINFIB)
else()
	target_compile_definitions(boost_context_static PRIVATE -DBOOST_USE_UCONTEXT)
endif()

set(BOOST_LIBRARIES
	Boost::boost
	Boost::atomic
	Boost::context
	Boost::system
	Boost::coroutine
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

if(Boost_USE_STATIC_LIBS)
	set_target_properties(boost_system_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_atomic_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_filesystem_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_thread_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_context_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_coroutine_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_chrono_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_locale_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_date_time_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_regex_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_timer_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_exception_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_random_static PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_program_options_static PROPERTIES FOLDER "third_party/boost")
else()
	set_target_properties(boost_system_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_atomic_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_filesystem_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_thread_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_context_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_coroutine_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_chrono_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_locale_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_date_time_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_regex_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_timer_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_exception_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_random_dll PROPERTIES FOLDER "third_party/boost")
	set_target_properties(boost_program_options_dll PROPERTIES FOLDER "third_party/boost")
endif()
