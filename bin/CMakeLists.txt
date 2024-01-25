add_executable(${PROJECT_NAME} main.cc)

target_link_libraries(${PROJECT_NAME} PRIVATE arguments_parser)
target_link_libraries(${PROJECT_NAME} PUBLIC PcapPlusPlus::Pcap++)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR})
