cmake_minimum_required(VERSION 3.10)
project(PacketScope)

set(CMAKE_CXX_STANDARD 17)

find_library(PCAP_LIBRARY pcap)

add_executable(packetscope src/main.cpp)

target_link_libraries(packetscope ${PCAP_LIBRARY})