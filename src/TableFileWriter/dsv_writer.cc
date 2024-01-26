#include "dsv_writer.h"

namespace TableFileWriter {

DSVWriter::DSVWriter(char delimiter, std::size_t columns, const std::string& filename):
  TableFileWriter(columns, filename), delimiter_(delimiter) {}

void DSVWriter::WriteRow(const std::vector<std::string>& row) {
  assert(row.size() == columns_);

  for (std::size_t i = 0; i != row.size() - 1; ++i) {
    file_ << row[i] << delimiter_;
  }

  file_ << row[row.size() - 1] << std::endl;
}

}  // namespace TableFileWriter
