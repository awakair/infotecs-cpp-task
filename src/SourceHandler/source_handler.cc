#include "source_handler.h"

namespace SourceHandler {

bool SourceHandler::OnPacketArrives(pcpp::RawPacket* packet, [[maybe_unused]]	pcpp::PcapLiveDevice* _, void* cookie)
  noexcept {
  auto& stream_classifier = *reinterpret_cast<StreamClassifier::StreamClassifier*>(cookie);
  pcpp::Packet parsed_packet(packet);
  stream_classifier.AddToStreamStats(parsed_packet);

  return false;
}

StreamClassifier::StreamStats SourceHandler::HandlePcap(const std::string& pcap_name) {
  pcpp::PcapFileReaderDevice source(pcap_name);

  if (!source.open()) {
    throw BadSourceError("Cannot open file");
  }

  if (!source.setFilter(kBPF)) {
    throw BadSourceError("Cannot set filter for pcap file");
  }

  StreamClassifier::StreamClassifier stream_classifier;
  pcpp::RawPacket packet;
  while (source.getNextPacket(packet)) {
    pcpp::Packet parsed_packet(&packet);
    stream_classifier.AddToStreamStats(parsed_packet);
  }

  source.close();

  return stream_classifier.GetStreamStats();
}

StreamClassifier::StreamStats SourceHandler::HandleInterface(const std::string& interface_name, int timeout) {
  auto source = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_name);

  if (source == nullptr || !source->open()) {
    throw BadSourceError("Cannot find or open interface");
  }

  if (!source->setFilter(kBPF)) {
    throw BadSourceError("Cannot set filter for interface");
  }

  StreamClassifier::StreamClassifier stream_classifier;
  pcpp::RawPacket packet;
  source->startCaptureBlockingMode(OnPacketArrives, &stream_classifier, timeout);

  source->close();

  return stream_classifier.GetStreamStats();
}

}  // namespace SourceHandler
