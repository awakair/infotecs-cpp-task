cmake_minimum_required(VERSION 3.12)
project(connection_classifier)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror -pedantic-errors)

find_package(PcapPlusPlus REQUIRED)

add_subdirectory(libs/ArgumentsParser)
add_subdirectory(bin)
