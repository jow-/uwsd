cmake_minimum_required(VERSION 3.13)
include(CheckCSourceCompiles)
include(CheckSymbolExists)

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

CHECK_C_SOURCE_COMPILES(
	"#include <sys/mman.h>\nint main() { return memfd_create(\"test\", 0); }"
	HAVE_MEMFD_CREATE)

CHECK_C_SOURCE_COMPILES(
	"#define _GNU_SOURCE\n#include <fcntl.h>\nint main() { return O_TMPFILE; }"
	HAVE_O_TMPFILE)

IF(HAVE_MEMFD_CREATE)
	ADD_DEFINITIONS(-DHAVE_MEMFD_CREATE)
ENDIF()

IF(HAVE_O_TMPFILE)
	ADD_DEFINITIONS(-DHAVE_O_TMPFILE)
ENDIF()

IF(USE_MBEDTLS)
	FIND_LIBRARY(mbedtls NAMES mbedtls)
	FIND_LIBRARY(mbedx509 NAMES mbedx509)
	FIND_LIBRARY(mbedcrypto NAMES mbedcrypto)
	SET(UWSD_SSL_SOURCES ssl-mbedtls.c)
	SET(UWSD_SSL_LIBRARIES ${mbedtls} ${mbedx509} ${mbedcrypto})
ELSE()
	FIND_LIBRARY(ssl NAMES ssl)
	FIND_LIBRARY(crypto NAMES crypto)
	SET(UWSD_SSL_SOURCES ssl-openssl.c)
	SET(UWSD_SSL_LIBRARIES ${ssl} ${crypto})

	SET(CMAKE_REQUIRED_LIBRARIES ${ssl})
	CHECK_SYMBOL_EXISTS(SSL_get0_peer_certificate openssl/ssl.h HAVE_SSL_GET0_PEER_CERTIFICATE)

	IF(HAVE_SSL_GET0_PEER_CERTIFICATE)
		ADD_DEFINITIONS(-DHAVE_SSL_GET0_PEER_CERTIFICATE)
	ENDIF()
ENDIF()

SET(UWSD_SOURCES main.c teeny-sha1.c util.c listen.c http.c client.c ws.c file.c state.c script.c config.c auth.c log.c ${UWSD_SSL_SOURCES})
ADD_EXECUTABLE(uwsd ${UWSD_SOURCES})

FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(ucode NAMES ucode)
FIND_LIBRARY(jsonc NAMES json-c)

FIND_LIBRARY(crypt NAMES crypt)
IF(crypt STREQUAL "crypt-NOTFOUND")
  SET(crypt "")
ENDIF()

TARGET_LINK_LIBRARIES(uwsd ${ubox} ${ucode} ${jsonc} ${crypt} ${UWSD_SSL_LIBRARIES})
