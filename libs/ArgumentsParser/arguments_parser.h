#pragma once

#include <string_view>
#include <optional>

namespace ArgumentsParser {

enum class SourceType {
  kUndefined,
  kPcapFile,
  kInterface
};

struct Arguments {
  SourceType source_type = SourceType::kUndefined;
  std::string_view source_name = "";
  std::string_view output_file_name = "";
  int timeout = 0;
};

[[nodiscard]] std::optional<Arguments> Parse(int argc, char** argv);

}  // namespace ArgumentsParser
