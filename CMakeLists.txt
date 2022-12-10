cmake_minimum_required(VERSION 3.15)
set(PROJECT_NAME amiitool)
project(${PROJECT_NAME} VERSION 0.2.0 LANGUAGES C)

if("${CMAKE_BUILD_TYPE}" STREQUAL "")
	set(CMAKE_BUILD_TYPE "Release")
endif()

message(STATUS "Build Mode: ${CMAKE_BUILD_TYPE}")

###########################
### Create gitversion.h ###

execute_process(COMMAND cmd /C "git rev-parse HEAD" OUTPUT_VARIABLE COMMIT_ID)
execute_process(COMMAND cmd /C "git rev-list --count --all" OUTPUT_VARIABLE COMMIT_CNT)
string(REGEX REPLACE "\n$" "" COMMIT_ID "${COMMIT_ID}")
string(REGEX REPLACE "\n$" "" COMMIT_CNT "${COMMIT_CNT}")
string(SUBSTRING "${COMMIT_ID}" 0 8 COMMIT_ID)
set(COMMIT_ID "0x${COMMIT_ID}")

message(STATUS "COMMIT_ID:  ${COMMIT_ID}")
message(STATUS "COMMIT_CNT: ${COMMIT_CNT}")

configure_file(gitversion.h.in ${CMAKE_CURRENT_SOURCE_DIR}/gitversion.h)

### Create gitversion.h ###
###########################

####################################
### Copy Generated MbedTLS files ###

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_gen/error.c ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/error.c COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_gen/psa_crypto_driver_wrappers.c ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/psa_crypto_driver_wrappers.c COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_gen/ssl_debug_helpers_generated.c ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/ssl_debug_helpers_generated.c COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_gen/version_features.c ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/version_features.c COPYONLY)

### Copy Generated MbedTLS files ###
####################################

option(ENABLE_PROGRAMS "" OFF)
add_subdirectory(mbedtls)

include_directories(include)

file(GLOB src "*.c")
file(GLOB src_bin "src_bin/*.c")
file(GLOB src_lib "src_lib/*.c")

add_executable(${PROJECT_NAME}-bin ${src_bin} ${src})
target_link_libraries(${PROJECT_NAME}-bin PUBLIC MbedTLS::mbedcrypto)
set_target_properties(${PROJECT_NAME}-bin PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

add_library(${PROJECT_NAME} STATIC ${src_lib} ${src})
set_target_properties(${PROJECT_NAME} PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(${PROJECT_NAME} PUBLIC MbedTLS::mbedcrypto)
