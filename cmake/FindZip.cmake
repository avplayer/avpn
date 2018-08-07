# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

macro(create_zip ARCHIVE FILELIST)

	get_target_property(OUTVAR ENABLE_LOGGER COMPILE_DEFINITIONS)
	message(STATUS "${OUTVAR}")

	find_program(WIN_ZIP_EXECUTABLE wzzip PATHS "$ENV{ProgramFiles}/WinZip")
	if (NOT WIN_ZIP_EXECUTABLE)
		find_program(WIN_ZIP_EXECUTABLE wzzip PATHS "$ENV{ProgramW6432}/WinZip")
		if (NOT WIN_ZIP_EXECUTABLE)
			find_program(WIN_ZIP_EXECUTABLE 7z PATHS "$ENV{ProgramFiles}/7-Zip")
			if (NOT WIN_ZIP_EXECUTABLE)
				find_program(WIN_ZIP_EXECUTABLE 7z PATHS "$ENV{ProgramW6432}/7-Zip")
				if (NOT WIN_ZIP_EXECUTABLE)
					find_package(Cygwin)
					find_program(WIN_ZIP_EXECUTABLE zip PATHS "${CYGWIN_INSTALL_PATH}/bin")
					if (WIN_ZIP_EXECUTABLE)
						message(STATUS "${CYGWIN_INSTALL_PATH}/bin")
						add_custom_command(TARGET ${ARCHIVE} POST_BUILD
							COMMAND ${WIN_ZIP_EXECUTABLE} -r ${ARCHIVE}.zip . -i ${FILELIST}
							DEPENDS ${ARCHIVE} WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
							COMMENT "Generating ${ARCHIVE}.zip for distribute to customers" USES_TERMINAL)
						#set(ZIP_COMMAND "\"${WIN_ZIP_EXECUTABLE}\" -r \"${ARCHIVE}\".zip . -i ${FILELIST}")
					endif()
				else()
					message(STATUS "$ENV{ProgramW6432}/7-Zip")
					add_custom_command(TARGET ${ARCHIVE} POST_BUILD
						COMMAND ${WIN_ZIP_EXECUTABLE} a ${ARCHIVE}.7z ${FILELIST}
						DEPENDS ${ARCHIVE} WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
						COMMENT "Generating ${ARCHIVE}.7z for distribute to customers" USES_TERMINAL)
					#set(ZIP_COMMAND "\"${WIN_ZIP_EXECUTABLE}\" a -tzip \"${ARCHIVE}\".7z ${FILELIST}")
				endif()
			else()
				message(STATUS "$ENV{ProgramFiles}/7-Zip")
				add_custom_command(TARGET ${ARCHIVE} POST_BUILD
					COMMAND ${WIN_ZIP_EXECUTABLE} a ${ARCHIVE}.7z ${FILELIST}
					DEPENDS ${ARCHIVE} WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
					COMMENT "Generating ${ARCHIVE}.7z for distribute to customers" USES_TERMINAL)
				#set(ZIP_COMMAND "\"${WIN_ZIP_EXECUTABLE}\" a -tzip \"${ARCHIVE}\".7z ${FILELIST}")
			endif()
		else()
			message(STATUS "$ENV{ProgramW6432}/WinZip")
			add_custom_command(TARGET ${ARCHIVE} POST_BUILD
				COMMAND ${WIN_ZIP_EXECUTABLE} -P ${ARCHIVE}.zip -i ${FILELIST}
				DEPENDS ${ARCHIVE} WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
				COMMENT "Generating ${ARCHIVE}.zip for distribute to customers" USES_TERMINAL)
			#set(ZIP_COMMAND "\"${WIN_ZIP_EXECUTABLE}\" -P \"${ARCHIVE}\".zip ${FILELIST}")
		endif()
	else()
		add_custom_command(TARGET ${ARCHIVE} POST_BUILD
			COMMAND ${WIN_ZIP_EXECUTABLE} -P ${ARCHIVE}.zip -i ${FILELIST}
			DEPENDS ${ARCHIVE} WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
			COMMENT "Generating ${ARCHIVE}.zip for distribute to customers" USES_TERMINAL)
		#set(ZIP_COMMAND "\"${WIN_ZIP_EXECUTABLE}\" -P \"${ARCHIVE}\".zip ${FILELIST}")
	endif()
endmacro()
