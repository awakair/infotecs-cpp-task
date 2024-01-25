#pragma once

#include <string>
#include "PcapFileDevice.h"
#include "PcapLiveDevice.h"
#include "PcapLiveDeviceList.h"
#include "../StreamClassifier/stream_classifier.h"

namespace SourceHandler {

StreamClassifier::StreamStats HandlePcap(const std::string& pcap_name);
StreamClassifier::StreamStats HandleInterface(const std::string& interface_name, int timeout);

}  // namespace SourceHandler
