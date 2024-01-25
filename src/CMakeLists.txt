cmake_minimum_required(VERSION 3.12)
project(stream_classifier)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -pedantic-errors)

find_package(PcapPlusPlus REQUIRED)

add_executable(${PROJECT_NAME}
                main.cc
                ArgumentsParser/arguments_parser.cc)
target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)
