cmake_minimum_required(VERSION 3.10)
project(PacketScope CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PACKETSCOPE_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(PACKETSCOPE_COVERAGE "Build with gcov coverage instrumentation" OFF)
option(PACKETSCOPE_WERROR "Treat compiler warnings as errors" OFF)

find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY)
  message(FATAL_ERROR "libpcap not found (install libpcap-dev on Linux; it ships with macOS)")
endif()

set(PS_FLAGS -Wall -Wextra -Wpedantic)
if(PACKETSCOPE_WERROR)
  list(APPEND PS_FLAGS -Werror)
endif()
if(PACKETSCOPE_SANITIZE)
  list(APPEND PS_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all -g)
  set(PS_LINK_FLAGS -fsanitize=address,undefined)
endif()
if(PACKETSCOPE_COVERAGE)
  list(APPEND PS_FLAGS --coverage -O0)
  list(APPEND PS_LINK_FLAGS --coverage)
endif()

add_library(packetscope_core STATIC
  src/parser.cpp
  src/stats.cpp
  src/display.cpp
  src/capture.cpp)
target_include_directories(packetscope_core PUBLIC include)
target_compile_options(packetscope_core PRIVATE ${PS_FLAGS})
target_link_libraries(packetscope_core PUBLIC ${PCAP_LIBRARY} ${PS_LINK_FLAGS})

add_executable(packetscope src/main.cpp)
target_compile_options(packetscope PRIVATE ${PS_FLAGS})
target_link_libraries(packetscope PRIVATE packetscope_core)

enable_testing()
add_executable(packetscope_tests tests/test_packetscope.cpp)
target_compile_options(packetscope_tests PRIVATE ${PS_FLAGS})
target_link_libraries(packetscope_tests PRIVATE packetscope_core)
add_test(NAME packetscope_tests COMMAND packetscope_tests)
