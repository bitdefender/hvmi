cmake_minimum_required(VERSION 3.13)

include(FindPkgConfig)

project(hvmid
	VERSION 0.0
	DESCRIPTION "Hypervisor Memory Introspection Daemon"
	LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_definitions(
	_REENTRANT
	SUPRESS_INTRO_ACTION_LOG
	)

add_compile_options(
	-W
	-Wall
	-Wwrite-strings
	-Wformat-security
	-Wno-unused-result
	-Wno-deprecated-declarations
	-fno-strict-aliasing
	-fvisibility-inlines-hidden
	-fvisibility=hidden
	-ffunction-sections
	-fdata-sections
	)

if (DEBUG)
	add_compile_options( -ggdb )
endif()

find_package(PkgConfig REQUIRED)

pkg_check_modules(BDVMI REQUIRED libbdvmi)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

pkg_check_modules(INTROCORE REQUIRED libintrocore)
pkg_get_variable(INTROCORE_DATADIR libintrocore pkgdatadir)

add_executable(${CMAKE_PROJECT_NAME})

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
	${PROJECT_SOURCE_DIR}/include
	${${CMAKE_PROJECT_NAME}_BINARY_DIR}
	${BDVMI_INCLUDE_DIRS}
	${INTROCORE_INCLUDE_DIRS}
	${JSONCPP_INCLUDE_DIRS}
	)

target_sources(${CMAKE_PROJECT_NAME}
	PRIVATE
	src/hvmidomainhandler.cpp
	src/hvmieventhandler.cpp
	src/hvmisettings.cpp
	src/hvmitooltask.cpp
	src/introcoremanager.cpp
	src/main.cpp
	)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
	${BDVMI_LIBRARIES}
	${INTROCORE_LIBRARIES}
	${JSONCPP_LIBRARIES}
	pthread
	stdc++fs
	dl
	)

target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE
	${BDVMI_LIBRARY_DIRS}
	${INTROCORE_LIBRARY_DIRS}
	${JSONCPP_LIBRARY_DIRS}
	)

configure_file(${${CMAKE_PROJECT_NAME}_SOURCE_DIR}/settings.json.in
	${${CMAKE_PROJECT_NAME}_BINARY_DIR}/settings.json)
configure_file(${${CMAKE_PROJECT_NAME}_SOURCE_DIR}/config.h.in
	${${CMAKE_PROJECT_NAME}_BINARY_DIR}/config.h)

install(FILES ${${CMAKE_PROJECT_NAME}_SOURCE_DIR}/default.json DESTINATION etc/${CMAKE_PROJECT_NAME}/policies/)
install(FILES ${${CMAKE_PROJECT_NAME}_BINARY_DIR}/settings.json DESTINATION etc/${CMAKE_PROJECT_NAME}/)

install(TARGETS ${CMAKE_PROJECT_NAME}
	RUNTIME	DESTINATION bin
	)
