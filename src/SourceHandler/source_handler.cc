#include "source_handler.h"

namespace SourceHandler {

bool SourceHandler::OnPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* _, void* cookie) {
  auto& stream_classifier = *reinterpret_cast<StreamClassifier::StreamClassifier*>(cookie);
  pcpp::Packet parsed_packet(packet);
  stream_classifier.AddToStreamStats(parsed_packet);

  return false;
}

StreamClassifier::StreamStats SourceHandler::HandlePcap(const std::string& pcap_name) {
  auto source = new pcpp::PcapFileReaderDevice(pcap_name);

  if (!source->open()) {
    throw std::runtime_error("Cannot open file");
  }

  if (!source->setFilter(kBPF)) {
    throw std::runtime_error("Cannot set filter for pcap file");
  }

  StreamClassifier::StreamClassifier stream_classifier;
  pcpp::RawPacket packet;
  while (source->getNextPacket(packet)) {
    pcpp::Packet parsed_packet(&packet);
    stream_classifier.AddToStreamStats(parsed_packet);
  }

  source->close();

  return stream_classifier.GetStreamStats();
}

StreamClassifier::StreamStats SourceHandler::HandleInterface(const std::string& interface_name, int timeout) {
  auto source = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_name);

  if (source == nullptr || !source->open()) {
    throw std::runtime_error("Cannot find or open device");
  }

  if (!source->setFilter(kBPF)) {
    throw std::runtime_error("Cannot set filter for interface");
  }

  StreamClassifier::StreamClassifier stream_classifier;
  pcpp::RawPacket packet;
  source->startCaptureBlockingMode(OnPacketArrives, &stream_classifier, timeout);

  source->close();

  return stream_classifier.GetStreamStats();
}

}  // namespace SourceHandler
