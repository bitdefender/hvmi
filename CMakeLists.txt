cmake_minimum_required (VERSION 3.13)

find_program(CTAGS_EXE
  NAMES "ctags"
  DOC "Path to ctags executable"
  )

find_program(CLANG_TIDY_EXE
  NAMES "clang-tidy"
  DOC "Path to clang-tidy executable"
  )

find_program(CPPCHECK_EXE
  NAMES "cppcheck"
  DOC "Path to cppcheck executable"
  )

find_program(DOXYGEN_EXE
  NAMES "doxygen"
  DOC "Path to doxygen executable"
  )

find_program(PYTHON_EXE
  NAMES "python3"
  DOC "Path to python executable"
  )

find_package(Git)

if ("$ENV{HVMI_BUILDNUMBER}" STREQUAL "")
  execute_process(
    COMMAND ${GIT_EXECUTABLE} rev-list --count HEAD
    OUTPUT_VARIABLE project_buildnumber
    RESULT_VARIABLE git_success)
    if (${git_success})
      message(FATAL_ERROR "Could not run git to find the count!")
    endif()
else()
  set(project_buildnumber "$ENV{HVMI_BUILDNUMBER}")
endif()

execute_process(
  COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
  OUTPUT_VARIABLE project_changeset
  RESULT_VARIABLE git_success)

if (${git_success})
  message(FATAL_ERROR "Could not run git to find the changeset!")
endif()

execute_process(
  COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
  OUTPUT_VARIABLE project_branch
  RESULT_VARIABLE git_success)

if (${git_success})
  message(FATAL_ERROR "Could not run git to find the branch name!")
endif()

# We need this since the output will contain the final \n
string(REGEX REPLACE "\n$" "" project_buildnumber "${project_buildnumber}")
string(REGEX REPLACE "\n$" "" project_changeset "${project_changeset}")
string(REGEX REPLACE "\n$" "" project_branch "${project_branch}")

######################################

include("${CMAKE_CURRENT_LIST_DIR}/project-meta-info.in")

project(introcore
  VERSION ${project_version}
  DESCRIPTION ${project_description}
  LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_SKIP_BUILD_RPATH TRUE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

get_filename_component(DISASM_DIRECTORY "${PROJECT_SOURCE_DIR}/bddisasm" ABSOLUTE)

if ("${CMAKE_MAKE_PROGRAM}" MATCHES "make$")
  # We need to resolve symlinks, since the Makefile will do too
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__='\"$(notdir $(abspath $<))\"'")
  # get_filename_component(REAL_PROJECT_SOURCE_DIR ${CMAKE_SOURCE_DIR} REALPATH)
  # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__='\"$(subst ${REAL_PROJECT_SOURCE_DIR}/introcore/src/,,$(abspath $<))\"'")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__=__FILE__")
endif()

message(STATUS "Build system used: ${CMAKE_MAKE_PROGRAM}")

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type given. Will use 'Debug'!")
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Source per-user config file
cmake_host_system_information(RESULT machine QUERY HOSTNAME)
string(TOLOWER ${machine} machine_lower)

if (EXISTS "${PROJECT_SOURCE_DIR}/build-config/${machine_lower}.cmake")
  include("${PROJECT_SOURCE_DIR}/build-config/${machine_lower}.cmake")
endif()

if (MSVC)
  message(FATAL_ERROR "For now cmake only builds on linux!")
endif()

if (OPTIONAL_CFLAGS)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPTIONAL_CFLAGS}")
endif()

if (NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
  get_filename_component(CMAKE_LIBRARY_OUTPUT_BASE_DIRECTORY "${PROJECT_SOURCE_DIR}/bin/x64" REALPATH)
  get_filename_component(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_BASE_DIRECTORY}/${CMAKE_BUILD_TYPE}" REALPATH)
else()
  get_filename_component(CMAKE_LIBRARY_OUTPUT_BASE_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} REALPATH)
  get_filename_component(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_BASE_DIRECTORY}/${CMAKE_BUILD_TYPE}" REALPATH)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")

if (CMAKE_C_FLAGS)
  message(STATUS "Passed CFLAGS: ${CMAKE_C_FLAGS}")
endif()

if (("${CMAKE_BUILD_TYPE}" STREQUAL "Debug") AND (CMAKE_C_FLAGS_DEBUG))
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O2")
  message(STATUS "Passed CFLAGS_DEBUG: ${CMAKE_C_FLAGS_DEBUG}")
endif()

if (("${CMAKE_BUILD_TYPE}" STREQUAL "Release") AND (CMAKE_C_FLAGS_RELEASE))
  message(STATUS "Passed CFLAGS_RELEASE: ${CMAKE_C_FLAGS_RELEASE}")
endif()

include_directories(
  ${DISASM_DIRECTORY}/inc
  ${DISASM_DIRECTORY}/inc/bdshemu
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/introcore/agents
  ${PROJECT_SOURCE_DIR}/introcore/src/guests/linux/detours
  ${PROJECT_SOURCE_DIR}/include/public
  ${PROJECT_SOURCE_DIR}/introcore
  ${PROJECT_SOURCE_DIR}/introcore/include
  )

add_compile_options(
  "$<$<CONFIG:Release>:-U_FORTIFY_SOURCE>"
  "$<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2>"
  -Wall
  -Wextra
  -Wshadow
  -Wformat-security
  -Wstrict-overflow=2
  -Wno-unused-function
  -Wno-multichar
  -Wno-incompatible-pointer-types
  -Werror=format-security
  -Werror=implicit-function-declaration
  -pipe
  -fpic
  -fwrapv
  -fno-strict-aliasing
  -fstack-protector-strong
  -fno-omit-frame-pointer
  -ffunction-sections
  -fdata-sections
  -g3
  -gdwarf-4
  -grecord-gcc-switches
  -march=nehalem
  -Wcast-qual
  )

if (NOT "${CMAKE_TOOLCHAIN_FILE}")
  add_compile_options(-fdiagnostics-color)
endif()

add_compile_definitions(
  "$<$<CONFIG:Debug>:DEBUG>"
  _LIB
  USER_MODE
  _GNU_SOURCE
  INTRO_VERSION_BUILDNUMBER=${project_buildnumber}
  INTRO_VERSION_CHANGESET="${project_changeset}"
  INTRO_VERSION_BRANCH="${project_branch}"
  INTRO_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
  INTRO_VERSION_MINOR=${PROJECT_VERSION_MINOR}
  INTRO_VERSION_REVISION=${PROJECT_VERSION_PATCH}
  CFG_DISABLE_HIRES_COUNTERS=1
)

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} \
-shared \
-fpic \
-Wl,-fpic \
-Wl,--fatal-warnings \
-Wl,--warn-common \
-Wl,--no-undefined \
-Wl,-version-script=\"${PROJECT_SOURCE_DIR}/introcore/version\" \
-Wl,-z,noexecstack \
-Wl,-z,relro \
-Wl,-z,now \
-Wl,--build-id")

set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} -Wl,-O1")

# We could use $<> generators, but it gets too complicated
if (CMAKE_COMPILER_IS_GNUCC)
  if (CMAKE_C_COMPILER_VERSION VERSION_LESS 7.0)
    message(FATAL_ERROR "GCC 7.0 or bigger required!")
  endif()

  add_compile_options(
    -Wshift-overflow=2
    -Wnull-dereference
    -Wduplicated-cond
    -Wlogical-op
    -Wvla
    )

  if ((CMAKE_C_COMPILER_VERSION VERSION_EQUAL 8.0)
      OR (CMAKE_C_COMPILER_VERSION VERSION_GREATER 8.0))
    add_compile_options(
      -Wdangling-else
      -Wshadow=global
      -Walloc-zero
      )
  endif()

  if ((CMAKE_C_COMPILER_VERSION VERSION_EQUAL 9.0)
      OR (CMAKE_C_COMPILER_VERSION VERSION_GREATER 9.0))
    add_compile_options(
      -Wmultistatement-macros
      -Warray-bounds=2
      -Wformat-overflow=2
      -Wformat-truncation=1
      -Wstringop-truncation
      -Wpointer-arith
      -Wdouble-promotion
      -Wmissing-include-dirs
      -Wuninitialized
      -Wmissing-noreturn
      -Wsuggest-attribute=noreturn
      -Walloca
      -Wtrampolines
      -Wcast-qual
      -Wcast-align
      -Wparentheses
      -Wjump-misses-init
      -Wfloat-conversion
      -Wstrict-prototypes
      # -Wmissing-prototypes
      # -Wunused-function
      -Wredundant-decls
      -Wdisabled-optimization
      -Woverlength-strings
      -fstack-clash-protection
      )
  endif()
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
  add_compile_options(
    -Wno-missing-braces
    -Wno-incompatible-pointer-types
    )

  if ((CMAKE_C_COMPILER_VERSION VERSION_EQUAL 8.0)
      OR (CMAKE_C_COMPILER_VERSION VERSION_GREATER 8.0))
    add_compile_options(
      -Wextra-semi-stmt
      )
  endif()

  if ((CMAKE_C_COMPILER_VERSION VERSION_EQUAL 7.0)
      OR (CMAKE_C_COMPILER_VERSION VERSION_GREATER 7.0))
    add_compile_options(
      -Wself-assign
      -Wself-assign-field
      )
  endif()

  if ((CMAKE_C_COMPILER_VERSION VERSION_EQUAL 6.0)
      OR (CMAKE_C_COMPILER_VERSION VERSION_GREATER 6.0))
    add_compile_options(
      -Wshift-overflow
      -Wnull-dereference
      -Wvla
      -Wdangling-else
      -Wshadow-all
      -Wpragma-pack
      -Wtautological-compare
      -Wnull-pointer-arithmetic
      -Wzero-as-null-pointer-constant
      )
  endif()

  if ((CMAKE_C_COMPILER_VERSION VERSION_EQUAL 5.0)
      OR (CMAKE_C_COMPILER_VERSION VERSION_GREATER 5.0))
    add_compile_options(
      -Wstrict-prototypes
      )
  endif()
else()
  message(FATAL_ERROR "Unspported compiler: ${CMAKE_C_COMPILER_ID}")
endif()

add_custom_target(
  disasm_target
  COMMAND $(MAKE)
  WORKING_DIRECTORY "${DISASM_DIRECTORY}"
  COMMENT "Building bddisasm library"
  )

add_library(${CMAKE_PROJECT_NAME} SHARED)

include(introcore/sources.cmake)

get_property(src_files TARGET ${CMAKE_PROJECT_NAME} PROPERTY SOURCES)

set_target_properties(${CMAKE_PROJECT_NAME}
  PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  C_STANDARD 11
  C_STANDARD_REQUIRED ON
  C_EXTENSIONS ON
  )

target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE "${DISASM_DIRECTORY}/bin/x64/${CMAKE_BUILD_TYPE}")

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE bddisasm bdshemu ${OPTIONAL_LIBRARIES})

add_dependencies(${CMAKE_PROJECT_NAME} disasm_target)

get_target_property(myname ${CMAKE_PROJECT_NAME} LIBRARY_OUTPUT_NAME)

add_custom_command(
  TARGET ${CMAKE_PROJECT_NAME}
  POST_BUILD
  COMMAND cp $<TARGET_FILE:${CMAKE_PROJECT_NAME}> ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Copying library to the build directory"
  )

get_filename_component(PROJECT_PUBLIC_HEADER_PATH "${PROJECT_SOURCE_DIR}/include/public" REALPATH)
file(GLOB_RECURSE PROJECT_PUBLIC_HEADERS "${PROJECT_PUBLIC_HEADER_PATH}/*.h")

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${PROJECT_PUBLIC_HEADERS}")

get_filename_component(PROJECT_SDK_PATH "${PROJECT_SOURCE_DIR}/tmp" REALPATH)

set(PROJECT_SDK_NAME ${PROJECT_SOURCE_DIR}/hvmi.${project_version}.${project_buildnumber}.${project_changeset}.zip)

set_target_properties(${CMAKE_PROJECT_NAME}
  PROPERTIES
    VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

set(DEST_DIR "${CMAKE_INSTALL_PREFIX}")
set(LIB_DIR "${CMAKE_INSTALL_LIBDIR}")
set(INC_DIR "${CMAKE_INSTALL_INCLUDEDIR}")
set(PRIVATE_LIBS "-l${CMAKE_PROJECT_NAME}")
set(DATA_DIR "${CMAKE_INSTALL_DATADIR}")

CONFIGURE_FILE("${CMAKE_SHARED_LIBRARY_PREFIX}${CMAKE_PROJECT_NAME}.pc.in"
               "${PROJECT_SOURCE_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}${CMAKE_PROJECT_NAME}.pc"
               @ONLY)

INSTALL(TARGETS ${CMAKE_PROJECT_NAME}
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}/hvmi"
)

INSTALL(FILES "${PROJECT_SOURCE_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}${CMAKE_PROJECT_NAME}.pc" DESTINATION "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# In case we want to build with ASAN, then some things are needed
if (USE_ASAN)
  message(STATUS "ASAN BUILD *************************************************")

  add_compile_options(
    -fsanitize=address,undefined,shift-base,shift-exponent,integer-divide-by-zero,unreachable,null,signed-integer-overflow,bounds,bounds-strict,alignment,object-size,nonnull-attribute,returns-nonnull-attribute,bool,enum,pointer-overflow,builtin,pointer-compare,pointer-subtract
    -fsanitize-address-use-after-scope
    -static-liblsan
    -static-libasan
    -static-libubsan
    )

  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} \
-static-libasan \
-static-liblsan \
-static-libubsan")

  target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC asan lsan ubsan)
endif()

set_source_files_properties(tags PROPERTIES GENERATED true)

if (CTAGS_EXE)
  execute_process(COMMAND ${CTAGS_EXE} --version OUTPUT_VARIABLE ctags_version)

  if ("${ctags_version}" MATCHES "Universal")
    set(tags_arguments --fields=*-f-l-Z-E --c-kinds=defgmpstuvxL --c++-kinds=defgmpstuvxLcn --extras=+p+r+f --sort=no --tag-relative=never -D _In_ -D _In_opt_ -D _In_z_ -D _Inout_ -D _Inout_opt_ -D _In_opt_z_ -D "'_In_reads_z_(Size)='" -D "'_In_reads_opt_z_(Size)='" -D "'_Inout_updates_(Size)='" -D "'_In_reads_(Size)='" -D "'_In_reads_or_z_(Size)='" -D "'_In_reads_bytes_(Bytes)='" -D "'_In_bytecount_(Bytes)='" -D _Out_ -D _Out_opt_ -D _Out_z_  -D _Out_opt_z -D _Outptr_ -D "'_Outptr_result_bytebuffer_(Size)='" -D "'_Out_writes_z_(Size)='" -D "'_Out_writes_opt_z_(Size)='" -D "'_Out_writes_or_z_(Size)='" -D "'_Out_writes_(Size)='" -D "'_Out_writes_bytes_(Bytes)='" -D "'_When_(Cond,Spec)='" -D "'_Function_class_(Class)='" -D _Cx_In_ -D _Cx_In_opt_ -D _Cx_In_z_ -D _Cx_Inout_ -D _Cx_Inout_opt_ -D _Cx_In_opt_z_ -D "'_Cx_In_reads_(Bytes)='" -D "'_Cx_In_reads_z_(Size)='" -D "'_Cx_In_reads_or_z_(count)='" -D "'_Cx_In_reads_bytes_(Bytes)='" -D "'_Cx_In_bytecount_(Length)='" -D _Cx_Out_ -D _Cx_Out_opt_ -D _Cx_Out_z_ -D _Cx_Out_opt_z -D _Cx_Outptr_ -D "'_Cx_Outptr_result_bytebuffer_(Size)='" -D "'_Cx_Out_writes_z_(Size)='" -D "'_Cx_Out_writes_opt_z_(Size)='" -D "'_Cx_Out_writes_or_z_(Size)='" -D "'_Cx_Out_writes_(Bytes)='" -D "'_Cx_Out_writes_bytes_(Bytes)='" -D "'_Cx_When_(Cond,Spec)='" -D "'_Cx_Function_class_(Class)='")
  endif()

  add_custom_target(tags
    COMMAND ${CTAGS_EXE} ${tags_arguments} ${src_files}
    COMMAND ${CTAGS_EXE} ${tags_arguments} -R --append introcore/include
    COMMAND ${CTAGS_EXE} ${tags_arguments} -R --append include
    COMMAND ${CTAGS_EXE} ${tags_arguments} -R --append ${DISASM_DIRECTORY}/inc
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
endif()

add_custom_target(package
    COMMAND ${CMAKE_COMMAND} -E echo "Packing..."
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_SDK_PATH}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_SDK_PATH}/include
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_SDK_PATH}/Bin/Introspection/X64/Debug
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_SDK_PATH}/Bin/Introspection/X64/Release
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_PUBLIC_HEADERS} ${PROJECT_SDK_PATH}/include
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_LIBRARY_OUTPUT_BASE_DIRECTORY}/Debug/libintrocore.so ${PROJECT_SDK_PATH}/Bin/Introspection/X64/Debug/libintrocore.so
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_LIBRARY_OUTPUT_BASE_DIRECTORY}/Release/libintrocore.so ${PROJECT_SDK_PATH}/Bin/Introspection/X64/Release/libintrocore.so
    )

if (EXISTS "${PROJECT_SOURCE_DIR}/dep-versions.txt")
    add_custom_command(TARGET package
        COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/dep-versions.txt ${PROJECT_SDK_PATH}
    )
endif()

add_custom_command(TARGET package
  COMMAND zip -r ${PROJECT_SDK_NAME} . WORKING_DIRECTORY ${PROJECT_SDK_PATH}
  COMMAND rm -rf ${PROJECT_SDK_PATH}
  )

if (CLANG_TIDY_EXE)
  add_custom_target(tidy
    COMMAND clang-tidy -p ${CMAKE_CURRENT_BINARY_DIR} ${src_files}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()

if (DOXYGEN_EXE)
  add_custom_target(doxy
    COMMAND doxygen Doxygen/Doxyfile
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMENT Building doxygen documentation
  )
endif()

if (PYTHON_EXE)
    get_filename_component(PROJECT_EXCEPTION_PATH "${PROJECT_SOURCE_DIR}/exceptions" REALPATH)
    add_custom_target(exceptions ALL
        COMMAND python3 exceptions.py --build=${project_exceptions_build} --verbose=2 jsons --output "${${CMAKE_PROJECT_NAME}_BINARY_DIR}/exceptions.bin"
        WORKING_DIRECTORY ${PROJECT_EXCEPTION_PATH})
    INSTALL(FILES "${${CMAKE_PROJECT_NAME}_BINARY_DIR}/exceptions.bin" DESTINATION "${CMAKE_INSTALL_FULL_DATADIR}/${CMAKE_PROJECT_NAME}")
endif()

if (PYTHON_EXE)
    get_filename_component(PROJECT_CAMI_PATH "${PROJECT_SOURCE_DIR}/cami" REALPATH)
    add_custom_target(cami ALL
        COMMAND python3 scripts/main.py --major ${project_cami_major} --minor ${project_cami_minor} --buildnumber ${project_cami_build} --output "${${CMAKE_PROJECT_NAME}_BINARY_DIR}/intro_live_update.bin"
        WORKING_DIRECTORY ${PROJECT_CAMI_PATH})
    INSTALL(FILES "${${CMAKE_PROJECT_NAME}_BINARY_DIR}/intro_live_update.bin" DESTINATION "${CMAKE_INSTALL_FULL_DATADIR}/${CMAKE_PROJECT_NAME}")
endif()
