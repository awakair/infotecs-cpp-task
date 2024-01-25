#include "arguments_parser.h"

namespace ArgumentsParser {

constexpr std::string_view argument_prefix = "--";
constexpr std::string_view source_type_argument = "source-type";
constexpr std::string_view pcap_file_type = "pcap-file";
constexpr std::string_view interface_type = "interface";
constexpr std::string_view source_name_argument = "source-name";
constexpr std::string_view output_file_argument = "output-file";
constexpr std::string_view timeout_argument = "timeout";

std::optional<Arguments> Parse(int argc, char** argv) noexcept {
  Arguments arguments;
  if (argc == 1) {
    return std::nullopt;
  }

  for (int i = 1; i + 1 < argc; i += 2) {
    std::string_view current_argument = argv[i];

    if (!current_argument.starts_with(argument_prefix)) {
      return std::nullopt;
    }
    current_argument.remove_prefix(argument_prefix.length());

    if (current_argument == source_name_argument) {
      arguments.source_name = argv[i + 1];
      continue;
    }

    if (current_argument == source_type_argument) {
      std::string_view type = argv[i + 1];
      if (type == pcap_file_type) {
        arguments.source_type = SourceType::kPcapFile;
      }
      if (type == interface_type) {
        arguments.source_type = SourceType::kInterface;
      }
      continue;
    }

    if (current_argument == output_file_argument) {
      arguments.output_file_name = argv[i + 1];
      continue;
    }

    if (current_argument == timeout_argument) {
      arguments.timeout = static_cast<int>(std::strtol(argv[i + 1], nullptr, 10));
      continue;
    }
  }

  bool arguments_are_unfilled = (arguments.source_type == SourceType::kUndefined) || (arguments.output_file_name.empty()) ||
    (arguments.source_name.empty()) || (arguments.source_type == SourceType::kInterface && arguments.timeout == 0);
  if (arguments_are_unfilled) {
    return std::nullopt;
  }

  return arguments;
}

}  // namespace ArgumentsParser
