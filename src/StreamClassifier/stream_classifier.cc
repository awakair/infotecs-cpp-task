#include "stream_classifier.h"

namespace StreamClassifier {

std::size_t StreamHash::operator()(const Stream& s) const noexcept {
  // bitshifts to avoid hash to be zero
  return ((std::hash<uint32_t>{}(s.src_ip) ^ (std::hash<uint16_t>{}(s.src_port) >> 1)) << 1)
    ^ (std::hash<uint32_t>{}(s.dst_ip) << 1) ^ std::hash<uint16_t>{}(s.dst_port);
}

void ClassifyToStream(pcpp::Packet& packet, StreamStats& stream_stats) {
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

}  // namespace StreamClassifier
