#include "source_handler.h"

namespace SourceHandler {

bool OnPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* _, void* cookie) {
  auto& streams_stats = *reinterpret_cast<StreamClassifier::StreamStats*>(cookie);
  pcpp::Packet parsed_packet(packet);
  StreamClassifier::ClassifyToStream(parsed_packet, streams_stats);

  return false;
}

StreamClassifier::StreamStats HandlePcap(const std::string& pcap_name) {
  auto source = new pcpp::PcapFileReaderDevice(pcap_name);

  if (!source->open()) {
    throw std::runtime_error("Cannot open file");
  }

  if (!source->setFilter(BPF)) {
    throw std::runtime_error("Cannot set filter for pcap file");
  }

  StreamClassifier::StreamStats stream_stats;
  pcpp::RawPacket packet;
  while (source->getNextPacket(packet)) {
    pcpp::Packet parsed_packet(&packet);
    StreamClassifier::ClassifyToStream(parsed_packet, stream_stats);
  }

  source->close();

  return stream_stats;
}

StreamClassifier::StreamStats HandleInterface(const std::string& interface_name, int timeout) {
  auto source = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_name);

  if (source == nullptr || !source->open()) {
    throw std::runtime_error("Cannot find or open device");
  }

  if (!source->setFilter(BPF)) {
    throw std::runtime_error("Cannot set filter for interface");
  }

  StreamClassifier::StreamStats stream_stats;
  pcpp::RawPacket packet;
  source->startCaptureBlockingMode(OnPacketArrives, &stream_stats, timeout);

  source->close();

  return stream_stats;
}

}  // namespace SourceHandler
