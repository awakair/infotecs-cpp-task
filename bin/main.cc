#include <iostream>
#include "Packet.h"
#include "PcapFileDevice.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "ProtocolType.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

#include "libs/ArgumentsParser/arguments_parser.h"

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

struct Stream {
  uint32_t src_ip;
  uint16_t src_port;
  uint32_t dst_ip;
  uint16_t dst_port;

  bool operator==(const Stream& other) const noexcept = default;
};

template <>
struct std::hash<Stream> {
  std::size_t operator()(const Stream& s) const noexcept {
    // bitshifts to avoid hash to be zero
    return ((std::hash<uint32_t>{}(s.src_ip) ^ (std::hash<uint16_t>{}(s.src_port) >> 1)) << 1)
    ^ (std::hash<uint32_t>{}(s.dst_ip) << 1) ^ std::hash<uint16_t>{}(s.dst_port);
  }
};

struct Stats {
  size_t packets_count = 0;
  size_t bytes_count = 0;
};

void ClassifyToStream(pcpp::Packet& packet, std::unordered_map<Stream, Stats>& stream_stats) {
  Stream current_stream;

  auto ip_layer = packet.getLayerOfType<pcpp::IPv4Layer>();

  current_stream.src_ip = ip_layer->getSrcIPAddress().getIPv4().toInt();
  current_stream.dst_ip = ip_layer->getDstIPAddress().getIPv4().toInt();


  if (packet.isPacketOfType(pcpp::UDP)) {
    auto udp_layer = packet.getLayerOfType<pcpp::UdpLayer>();
    current_stream.src_port = udp_layer->getSrcPort();
    current_stream.dst_port = udp_layer->getDstPort();
  } else {
    auto tcp_layer = packet.getLayerOfType<pcpp::TcpLayer>();
    current_stream.src_port = tcp_layer->getSrcPort();
    current_stream.dst_port = tcp_layer->getDstPort();
  }

  ++stream_stats[current_stream].packets_count;
  stream_stats[current_stream].bytes_count += packet.getFirstLayer()->getDataLen();
}

bool OnPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* _, void* cookie) {
  auto& streams_stats = *reinterpret_cast<std::unordered_map<Stream, Stats>*>(cookie);
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

  std::unordered_map<Stream, Stats> stream_stats;
  pcpp::RawPacket packet;
  switch(arguments->source_type) {
    case ArgumentsParser::SourceType::kPcapFile:
      while (dynamic_cast<pcpp::PcapFileReaderDevice*>(source)->getNextPacket(packet)) {
        pcpp::Packet parsed_packet(&packet);
        ClassifyToStream(parsed_packet, stream_stats);
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
