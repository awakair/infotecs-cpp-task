#include <iostream>
#include "PcapFileDevice.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "ArgumentsParser/arguments_parser.h"
#include "StreamClassifier/stream_classifier.h"

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

bool OnPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* _, void* cookie) {
  auto& streams_stats = *reinterpret_cast<StreamClassifier::StreamStats*>(cookie);
  pcpp::Packet parsed_packet(packet);
  ClassifyToStream(parsed_packet, streams_stats);

  return false;
}

int main(int argc, char** argv) {
  auto arguments = ArgumentsParser::Parse(argc, argv);

  if (!arguments.has_value()) {
    PrintUsage();
    return EXIT_FAILURE;
  }

  pcpp::IPcapDevice* source;
  switch(arguments->source_type) {
    case ArgumentsParser::SourceType::kPcapFile:
      source = new pcpp::PcapFileReaderDevice(std::string(arguments->source_name));
      break;
    case ArgumentsParser::SourceType::kInterface:
      source = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(std::string(arguments->source_name));
      break;
    case ArgumentsParser::SourceType::kUndefined:
      return EXIT_FAILURE;
  }

  if (!source->open()) {
    std::cerr << "Cannot open file for reading" << std::endl;
    return EXIT_FAILURE;
  }

  if (!source->setFilter("ip proto \\tcp || ip proto \\udp")) {
    std::cerr << "Cannot set filter for file source" << std::endl;
    return EXIT_FAILURE;
  }

  StreamClassifier::StreamStats stream_stats;
  pcpp::RawPacket packet;
  switch(arguments->source_type) {
    case ArgumentsParser::SourceType::kPcapFile:
      while (dynamic_cast<pcpp::PcapFileReaderDevice*>(source)->getNextPacket(packet)) {
        pcpp::Packet parsed_packet(&packet);
        StreamClassifier::ClassifyToStream(parsed_packet, stream_stats);
      }
      break;
    case ArgumentsParser::SourceType::kInterface:
      dynamic_cast<pcpp::PcapLiveDevice*>(source)->startCaptureBlockingMode(OnPacketArrives, &stream_stats, arguments->timeout);
      break;
    case ArgumentsParser::SourceType::kUndefined:
      return EXIT_FAILURE;
  }

  source->close();

  for (auto& [stream, stats]: stream_stats) {
    std::cout << pcpp::IPv4Address(stream.src_ip).toString() << ":" << stream.src_port << " -> " << pcpp::IPv4Address(stream.dst_ip).toString() << ":" << stream.dst_port << "\t" << stats.packets_count << " " << stats.bytes_count << std::endl;
  }

  return EXIT_SUCCESS;
}
