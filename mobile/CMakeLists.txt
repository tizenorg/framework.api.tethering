CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(fw_name "capi-network-tethering")

PROJECT(${fw_name})

SET(CMAKE_INSTALL_PREFIX /usr)
SET(PREFIX ${CMAKE_INSTALL_PREFIX})

SET(INC_DIR include)
INCLUDE_DIRECTORIES(${INC_DIR})

SET(dependents "dlog glib-2.0 capi-base-common dbus-glib-1 vconf")

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")

INCLUDE(FindPkgConfig)
pkg_check_modules(${fw_name} REQUIRED ${dependents})
FOREACH(flag ${${fw_name}_CFLAGS})
    SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIC -Wall -Werror -fvisibility=hidden")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")

IF("${ARCH}" STREQUAL "arm")
    ADD_DEFINITIONS("-DTARGET")
ENDIF("${ARCH}" STREQUAL "arm")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DTIZEN_DEBUG")

SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--as-needed -Wl,--rpath=%{_libdir}")

FIND_PROGRAM(MARSHALTOOL NAMES glib-genmarshal)
EXEC_PROGRAM("${MARSHALTOOL}" ARGS "--prefix=marshal ${INC_DIR}/marshal.list --header > ${INC_DIR}/marshal.h")
EXEC_PROGRAM("${MARSHALTOOL}" ARGS "--prefix=marshal ${INC_DIR}/marshal.list --body > src/marshal.c")

FIND_PROGRAM(DBUS_BINDING_TOOL NAMES dbus-binding-tool)
EXEC_PROGRAM("${DBUS_BINDING_TOOL}" ARGS "--prefix=tethering ${INC_DIR}/tethering.xml --mode=glib-client --output=${INC_DIR}/tethering-client-stub.h")

aux_source_directory(src SOURCES)
ADD_LIBRARY(${fw_name} SHARED ${SOURCES})

TARGET_LINK_LIBRARIES(${fw_name} ${${fw_name}_LDFLAGS})

SET_TARGET_PROPERTIES(${fw_name} PROPERTIES SOVERSION 0.1.0)

INSTALL(TARGETS ${fw_name} DESTINATION ${LIB_INSTALL_DIR})
INSTALL(
        DIRECTORY ${INC_DIR}/ DESTINATION include/network
        FILES_MATCHING
        PATTERN "*_private.h" EXCLUDE
        PATTERN "marshal.h" EXCLUDE
        PATTERN "tethering-client-stub.h" EXCLUDE
        PATTERN "${INC_DIR}/*.h"
        )

SET(PC_NAME ${fw_name})
SET(PC_REQUIRED ${dependents})
SET(PC_LDFLAGS -l${fw_name})
SET(PC_CFLAGS -I\${includedir}/network)

CONFIGURE_FILE(
    capi-network-tethering.pc.in
    ${CMAKE_CURRENT_SOURCE_DIR}/${fw_name}.pc
    @ONLY
)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${fw_name}.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
MESSAGE("Arch ${ARCH}")
IF(NOT "${ARCH}" STREQUAL "emul")
	INSTALL(FILES "${CMAKE_CURRENT_SOURCE_DIR}/sysinfo-tethering.xml" DESTINATION "/etc/config/connectivity")
ENDIF(NOT "${ARCH}" STREQUAL "emul")

ADD_SUBDIRECTORY(test)

IF(UNIX)

ADD_CUSTOM_TARGET (distclean @echo cleaning for source distribution)
ADD_CUSTOM_COMMAND(
        DEPENDS clean
        COMMENT "distribution clean"
        COMMAND find
        ARGS    .
        -not -name config.cmake -and \(
        -name tester.c -or
        -name Testing -or
        -name CMakeFiles -or
        -name cmake.depends -or
        -name cmake.check_depends -or
        -name CMakeCache.txt -or
        -name cmake.check_cache -or
        -name *.cmake -or
        -name Makefile -or
        -name core -or
        -name core.* -or
        -name gmon.out -or
        -name install_manifest.txt -or
        -name *.pc -or
        -name *~ \)
        | grep -v TC | xargs rm -rf
        TARGET  distclean
        VERBATIM
)

ENDIF(UNIX)

