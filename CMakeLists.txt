cmake_minimum_required(VERSION 3.17)
project(libcoap-server)

set(CMAKE_C_STANDARD 11)

find_package(PkgConfig REQUIRED)
pkg_check_modules(libcoap-3 REQUIRED IMPORTED_TARGET libcoap-3)
pkg_check_modules(libcbor REQUIRED IMPORTED_TARGET libcbor)

add_executable(server server.c shared.c shared.h heatshrink_decoder.c heatshrink_decoder.h cbor_callback1.c cbor_callback1.h)

target_link_libraries(server PUBLIC PkgConfig::libcoap-3 PkgConfig::libcbor)
