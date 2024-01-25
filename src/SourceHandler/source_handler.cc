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
    throw "Cannot open file";
  }

  source->setFilter("ip proto \\tcp || ip proto \\udp");

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
    throw "Cannot find or open device";
  }

  source->setFilter("ip proto \\tcp || ip proto \\udp");

  StreamClassifier::StreamStats stream_stats;
  pcpp::RawPacket packet;
  source->startCaptureBlockingMode(OnPacketArrives, &stream_stats, timeout);

  source->close();

  return stream_stats;
}

}  // namespace SourceHandler
