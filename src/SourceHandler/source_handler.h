#pragma once

#include <string>
#include <stdexcept>
#include "PcapFileDevice.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "../StreamClassifier/stream_classifier.h"

namespace SourceHandler {
class BadSourceError: public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class SourceHandler {
 public:
  static constexpr auto kBPF = "ip proto \\tcp || ip proto \\udp";

  static StreamClassifier::StreamStats HandlePcap(const std::string& pcap_name);
  static StreamClassifier::StreamStats HandleInterface(const std::string& interface_name, int timeout);

 private:
  static bool OnPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* _, void* cookie) noexcept;
};

}  // namespace SourceHandler
