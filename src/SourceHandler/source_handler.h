#pragma once

#include <string>
#include <stdexcept>
#include "PcapFileDevice.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "../StreamClassifier/stream_classifier.h"

namespace SourceHandler {

const char* BPF = "ip proto \\tcp || ip proto \\udp";

StreamClassifier::StreamStats HandlePcap(const std::string& pcap_name);
StreamClassifier::StreamStats HandleInterface(const std::string& interface_name, int timeout);

}  // namespace SourceHandler
