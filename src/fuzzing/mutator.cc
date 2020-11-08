#include "src/fuzzing/mutator.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <random>

#include "glog/logging.h"

namespace fido2_tests {
namespace {

constexpr int kMutationOperations = 3;

uint8_t RandomByte() { return static_cast<uint8_t>(std::rand() % 256); }

}  // namespace

Mutator::Mutator(int max_mutation_degree, int seed)
    : max_mutation_degree_(max_mutation_degree) {
  srand(seed);
}

bool Mutator::EraseByte(std::vector<uint8_t> &data, size_t max_size) {
  if (data.size() <= 1) return false;
  int index = std::rand() % data.size();
  data.erase(data.begin() + index);
  return true;
}

bool Mutator::InsertByte(std::vector<uint8_t> &data, size_t max_size) {
  if (data.size() >= max_size) return false;
  int index = std::rand() % data.size();
  uint8_t elem = RandomByte();
  data.insert(data.begin() + index, elem);
  return true;
}

bool Mutator::ShuffleBytes(std::vector<uint8_t> &data, size_t max_size) {
  if (data.size() > max_size || data.size() <= 1) return false;
  int shuffle_count = std::rand() % data.size();
  int shuffle_offset = std::rand() % (data.size() - shuffle_count);
  std::shuffle(data.begin() + shuffle_offset,
               data.begin() + shuffle_offset + shuffle_count,
               std::default_random_engine());
  return true;
}

bool Mutator::Mutate(std::vector<uint8_t> &data, size_t max_size) {
  int mutation_degree = std::rand() % max_mutation_degree_;
  while (mutation_degree--) {
    int op = std::rand() % kMutationOperations;
    bool ok = true;
    switch (static_cast<MutationOperation>(op)) {
      case kEraseByte:
        ok = EraseByte(data, max_size);
        break;
      case kInsertByte:
        ok = InsertByte(data, max_size);
        break;
      case kShuffleBytes:
        ok = ShuffleBytes(data, max_size);
        break;
      default:
        CHECK(false) << "unreachable default - TEST SUITE BUG";
    }
    // If the mutation operation failed (e.g. max_size exceeded),
    // retry in next iteration.
    if (!ok) {
      ++mutation_degree;
    }
  }
  return true;
}

}  // namespace fido2_tests

