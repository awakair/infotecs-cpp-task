#include <iostream>
#include "ArgumentsParser/arguments_parser.h"
#include "StreamClassifier/stream_classifier.h"
#include "SourceHandler/source_handler.h"

void PrintUsage() {
  std::cout << "Test task for infotecs. Program № 1" << std::endl;
  std::cout << "Usage:" << std::endl;
  std::cout << "\t--source-name <name>\tName of source file or interface" << std::endl;
  std::cout << "\t--source-type <pcap-file/interface>\tpcap-file if you want to process pcap-file"
               "or interface if you want to listen interface" << std::endl;
  std::cout << "\t--output-file <name>\tOutput .csv file. In will be created or rewritten" << std::endl;
  std::cout << "\t--timeout\tTimeout to listen interface (seconds). Ingored for pcap-file option" << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "\tstream-classifier --source-name captured.pcap --source-type pcap-file --output-file stats.csv" << std::endl;
  std::cout << "\tstream-classifier --source-name eth0 --source-type interface --output-file stats.csv --timeout 500" << std::endl;
}

int main(int argc, char** argv) {
  ArgumentsParser::Parser parser(argc, argv);
  if (!parser.Parse()) {
    PrintUsage();
    return EXIT_FAILURE;
  }
  auto arguments = parser.GetParsedArguments();

  StreamClassifier::StreamStats stream_stats;
  switch(arguments.source_type) {
    case ArgumentsParser::SourceType::kPcapFile:
      stream_stats = SourceHandler::HandlePcap(std::string(arguments.source_name));
      break;
    case ArgumentsParser::SourceType::kInterface:
      stream_stats = SourceHandler::HandleInterface(std::string(arguments.source_name), arguments.timeout);
      break;
    case ArgumentsParser::SourceType::kUndefined:
      return EXIT_FAILURE;
  }

  for (auto& [stream, stats]: stream_stats) {
    std::cout << pcpp::IPv4Address(stream.src_ip).toString() << ":" << stream.src_port << " -> " << pcpp::IPv4Address(stream.dst_ip).toString() << ":" << stream.dst_port << "\t" << stats.packets_count << " " << stats.bytes_count << std::endl;
  }

  return EXIT_SUCCESS;
}
