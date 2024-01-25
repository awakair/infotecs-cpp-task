#include "arguments_parser.h"

namespace ArgumentsParser {

Parser::Parser(int argc, char** argv) noexcept: argc_(argc), argv_(argv) {}

bool Parser::Parse() noexcept {
  if (is_correctly_parsed_) {
    return true;
  }

  if (argc_ == 1) {
    return is_correctly_parsed_ = false;
  }

  for (int i = 1; i + 1 < argc_; i += 2) {
    std::string_view current_argument = argv_[i];

    if (!current_argument.starts_with(kArgumentPrefix)) {
      return is_correctly_parsed_ = false;
    }
    current_argument.remove_prefix(kArgumentPrefix.length());

    if (current_argument == kSourceNameArgument) {
      parsed_arguments_.source_name = argv_[i + 1];
      continue;
    }

    if (current_argument == kSourceTypeArgument) {
      std::string_view type = argv_[i + 1];
      if (type == kPcapFileType) {
        parsed_arguments_.source_type = SourceType::kPcapFile;
      }
      if (type == kInterfaceType) {
        parsed_arguments_.source_type = SourceType::kInterface;
      }
      continue;
    }

    if (current_argument == kOutputFileArgument) {
      parsed_arguments_.output_file_name = argv_[i + 1];
      continue;
    }

    if (current_argument == kTimeoutArgument) {
      parsed_arguments_.timeout = static_cast<int>(std::strtol(argv_[i + 1], nullptr, 10));
      continue;
    }
  }

  bool arguments_are_unfilled = (parsed_arguments_.source_type == SourceType::kUndefined) || (parsed_arguments_.output_file_name.empty()) ||
    (parsed_arguments_.source_name.empty()) || (parsed_arguments_.source_type == SourceType::kInterface && parsed_arguments_.timeout == 0);

  return is_correctly_parsed_ = !arguments_are_unfilled;
}

bool Parser::IsCorrectlyParsed() noexcept {
  return is_correctly_parsed_;
}

const Arguments& Parser::GetParsedArguments() {
  if (!is_correctly_parsed_) {
    throw std::logic_error("Expression is not parsed");
  }

  return parsed_arguments_;
}

}  // namespace ArgumentsParser
