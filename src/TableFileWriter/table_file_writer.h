#pragma once

#include <vector>
#include <string>
#include <cassert>
#include <fstream>

namespace TableFileWriter {

class TableFileWriter {
 public:
  TableFileWriter(std::size_t columns, const std::string& filename);
  virtual void WriteRow(const std::vector<std::string>& row) = 0;
  virtual ~TableFileWriter() = default;
  std::size_t GetColumns();
  std::ofstream& GetFile();
 protected:
  const std::size_t columns_;
  std::ofstream file_;
};

}  // namespace TableFileWriter
