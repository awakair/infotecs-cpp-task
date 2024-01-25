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
  std::string_view source_name;
  std::string_view output_file_name;
  int timeout = 0;
};

class Parser {
 public:
  static constexpr std::string_view kArgumentPrefix = "--";
  static constexpr std::string_view kSourceTypeArgument = "source-type";
  static constexpr std::string_view kPcapFileType = "pcap-file";
  static constexpr std::string_view kInterfaceType = "interface";
  static constexpr std::string_view kSourceNameArgument = "source-name";
  static constexpr std::string_view kOutputFileArgument = "output-file";
  static constexpr std::string_view kTimeoutArgument = "timeout";
  Parser(int argc, char** argv) noexcept;
  bool Parse() noexcept;
  bool IsCorrectlyParsed() noexcept;
  const Arguments& GetParsedArguments();

 private:
  int argc_;
  char** argv_;
  Arguments parsed_arguments_;
  bool is_correctly_parsed_ = false;
};

}  // namespace ArgumentsParser
