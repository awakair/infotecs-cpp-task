cmake_minimum_required(VERSION 3.12)
project(stream_classifier)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror -pedantic-errors)

find_package(PcapPlusPlus REQUIRED)

add_executable(${PROJECT_NAME}
                main.cc
                ArgumentsParser/arguments_parser.cc
                StreamClassifier/stream_classifier.cc
                SourceHandler/source_handler.cc
                TableFileWriter/table_file_writer.cc
                TableFileWriter/dsv_writer.cc)
target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)
