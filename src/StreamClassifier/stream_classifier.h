#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>
#include "Packet.h"
#include "ProtocolType.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

namespace StreamClassifier {

struct Stream {
  uint32_t src_ip;
  uint16_t src_port;
  uint32_t dst_ip;
  uint16_t dst_port;

  bool operator==(const Stream& other) const noexcept = default;
};

struct StreamHash {
  std::size_t operator()(const Stream& s) const noexcept;
};

struct Stats {
  size_t packets_count = 0;
  size_t bytes_count = 0;
};

using StreamStats = std::unordered_map<Stream, Stats, StreamHash>;

class StreamClassifier {
 public:
  void AddToStreamStats(const pcpp::Packet& packet);
  StreamStats& GetStreamStats() noexcept;
 private:
  StreamStats stream_stats_;
};

}  // namespace StreamClassifier
