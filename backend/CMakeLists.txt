cmake_minimum_required(VERSION 3.16)
project(DPIEngine VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(Threads REQUIRED)

include_directories(
    ${PROJECT_SOURCE_DIR}/include
)

set(SRC_FILES
    src/dpi_engine.cpp
    src/load_balancer.cpp
    src/connection_tracker.cpp
    src/fast_path.cpp
    src/packet_parser.cpp
    src/pcap_reader.cpp
    src/rule_manager.cpp
    src/sni_extractor.cpp
    src/types.cpp
    src/main_dpi.cpp
)

find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found")
endif()

add_executable(dpi_engine ${SRC_FILES})

# Unit tests for the extractors and the app classifier. Deliberately a separate
# target from the engine: it links the same sources minus main_dpi.cpp, so the
# tests exercise the code the engine actually runs rather than a copy.
set(TEST_SRC_FILES ${SRC_FILES})
list(REMOVE_ITEM TEST_SRC_FILES src/main_dpi.cpp)

add_executable(dpi_tests
    tests/test_extractors.cpp
    ${TEST_SRC_FILES}
)
target_link_libraries(dpi_tests
    Threads::Threads
    ${PCAP_LIBRARY}
)

# Link libraries
target_link_libraries(dpi_engine
    Threads::Threads
    ${PCAP_LIBRARY}
)