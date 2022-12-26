cmake_minimum_required(VERSION 3.13)

PROJECT(uwsd C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -ffunction-sections -fwrapv -D_GNU_SOURCE)

IF(CMAKE_C_COMPILER_VERSION VERSION_GREATER 6)
	ADD_DEFINITIONS(-Wextra -Werror=implicit-function-declaration)
	ADD_DEFINITIONS(-Wformat -Werror=format-security -Werror=format-nonliteral)
ENDIF()
ADD_DEFINITIONS(-Wmissing-declarations -Wno-error=unused-variable -Wno-unused-parameter)

INCLUDE_DIRECTORIES(include)

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3 -O0)
ELSE()
  ADD_DEFINITIONS(-DNDEBUG)
ENDIF()

SET(UWSD_SOURCES main.c teeny-sha1.c util.c listen.c http.c client.c ws.c file.c state.c script.c ssl.c config.c auth.c)
ADD_EXECUTABLE(uwsd ${UWSD_SOURCES})

FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(ucode NAMES ucode)
FIND_LIBRARY(jsonc NAMES json-c)
FIND_LIBRARY(crypto NAMES crypto)
FIND_LIBRARY(ssl NAMES ssl)

FIND_LIBRARY(crypt NAMES crypt)
IF(crypt STREQUAL "crypt-NOTFOUND")
  SET(crypt "")
ENDIF()

TARGET_LINK_LIBRARIES(uwsd ${ubox} ${ucode} ${jsonc} ${ssl} ${crypto} ${crypt})
