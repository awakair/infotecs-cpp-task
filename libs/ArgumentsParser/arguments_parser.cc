#include "arguments_parser.h"

namespace ArgumentsParser {

constexpr std::string_view argument_prefix = "--";
constexpr std::string_view source_type_argument = "source-type";
constexpr std::string_view source_name_argument = "source-name";
constexpr std::string_view output_file_argument = "output-file";
constexpr std::string_view timeout_argument = "timeout";

std::optional<Arguments> Parse(int argc, char** argv) {
  Arguments arguments;
  if (argc == 1) {
    return std::nullopt;
  }

  for (int i = 1; i < argc; ++i) {
    std::string_view current_argument = argv[i];

    if (!current_argument.starts_with(argument_prefix)) {
      return std::nullopt;
    }
    current_argument.remove_prefix(argument_prefix.length());

    if (current_argument.starts_with(source_name_argument) && current_argument.length()) {

    }
  }

  bool arguments_are_unfilled = (arguments.source_type == SourceType::kUndefined) || (arguments.output_file_name.empty()) ||
    (arguments.source_name.empty()) || (arguments.timeout == 0);
  if (arguments_are_unfilled) {
    return std::nullopt;
  }

  return arguments;
}

}  // namespace ArgumentsParser
