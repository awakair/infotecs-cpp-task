#include "table_file_writer.h"

namespace TableFileWriter {

TableFileWriter::TableFileWriter(std::size_t columns, const std::string& filename):
  columns_(columns), file_(filename) {
  assert(columns != 0);
}

std::size_t TableFileWriter::GetColumns() {
  return columns_;
}

std::ofstream& TableFileWriter::GetFile() {
  return file_;
}

}  // namespace TableFileWriter
