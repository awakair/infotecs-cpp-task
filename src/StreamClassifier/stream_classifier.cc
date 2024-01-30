#include "stream_classifier.h"

namespace StreamClassifier {

std::size_t StreamHash::operator()(const Stream& s) const noexcept {
  // bitshifts to avoid hash to be zero
  return ((std::hash<uint32_t>{}(s.src_ip) ^ (std::hash<uint16_t>{}(s.src_port) >> 1)) << 1)
    ^ (std::hash<uint32_t>{}(s.dst_ip) << 1) ^ std::hash<uint16_t>{}(s.dst_port);
}

void StreamClassifier::AddToStreamStats(const pcpp::Packet& packet) {
  Stream current_stream;

  auto ip_layer = packet.getLayerOfType<pcpp::IPv4Layer>();

  if (ip_layer == nullptr) {
    return;
  }

  current_stream.src_ip = ip_layer->getSrcIPAddress().getIPv4().toInt();
  current_stream.dst_ip = ip_layer->getDstIPAddress().getIPv4().toInt();

  if (packet.isPacketOfType(pcpp::UDP)) {
    auto udp_layer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (udp_layer == nullptr) {
      return;
    }
    current_stream.src_port = udp_layer->getSrcPort();
    current_stream.dst_port = udp_layer->getDstPort();
  } else {
    auto tcp_layer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (tcp_layer == nullptr) {
      return;
    }
    current_stream.src_port = tcp_layer->getSrcPort();
    current_stream.dst_port = tcp_layer->getDstPort();
  }

  ++stream_stats_[current_stream].packets_count;
  stream_stats_[current_stream].bytes_count += packet.getFirstLayer()->getDataLen();
}

StreamStats& StreamClassifier::GetStreamStats() noexcept {
  return stream_stats_;
}

}  // namespace StreamClassifier
