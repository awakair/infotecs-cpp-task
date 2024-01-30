#pragma once

#include <cassert>
#include <string>
#include <vector>
#include "table_file_writer.h"

namespace TableFileWriter {

class DSVWriter : public TableFileWriter {
 public:
  DSVWriter(char delimiter, std::size_t columns, const std::string& filename);
  void WriteRow(const std::vector<std::string>& row) override;
 private:
  const char delimiter_;
};

}  // namespace TableFileWriter
