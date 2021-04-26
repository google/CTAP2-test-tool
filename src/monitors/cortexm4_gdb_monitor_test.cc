// Copyright 2020-2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "src/monitors/cortexm4_gdb_monitor.h"

#include <iostream>

#include "gtest/gtest.h"

namespace fido2_tests {
namespace {

TEST(Cortexm4GdbMonitor, TestPrintOneRegister) {
  Cortexm4GdbMonitor monitor(0);
  std::string register_packet = "00000000";
  std::string expected_output =
      "R0                                      0x00000000\n";
  testing::internal::CaptureStdout();
  monitor.PrintOneRegister(register_packet, "R0", 0);
  std::string output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  register_packet =
      "00000000000000000000000000000000000000000000000120003c5020000f8000000000"
      "0000072ee000e20020003f5c0000000020000d7800012bc100012bcc0000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000061000000";
  expected_output = "R10                                     0xe000e200\n";
  testing::internal::CaptureStdout();
  monitor.PrintOneRegister(register_packet, "R10", 10);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);
  expected_output = "R23                                     0x00000000\n";
  testing::internal::CaptureStdout();
  monitor.PrintOneRegister(register_packet, "R23", 23);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  register_packet =
      "00000000000000000000000000120003c5020000f80000000000000072ee000e20020003"
      "f5c0000000020000d7800012bc100012bcc00000000000000000000061000000";
  expected_output = "PSR                                     0x61000000\n";
  testing::internal::CaptureStdout();
  monitor.PrintOneRegister(register_packet, "PSR", 16);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);
}

TEST(Cortexm4GdbMonitor, TestPrintGeneralRegisters) {
  Cortexm4GdbMonitor monitor(0);
  std::string register_packet = "00000000";
  std::string expected_output =
      "Error reading general registers. Got unexpected response: 00000000\n";
  testing::internal::CaptureStdout();
  monitor.PrintGeneralRegisters(register_packet);
  std::string output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  register_packet =
      "00000000000000000000000000000000000000000000000120003c5020000f8000000000"
      "0000072ee000e20020003f5c0000000020000d7800012bc100012bcc0000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000061000000";
  expected_output =
      "Error reading general registers. Got unexpected response: "
      "00000000000000000000000000000000000000000000000120003c5020000f8000000000"
      "0000072ee000e20020003f5c0000000020000d7800012bc100012bcc0000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000061000000\n";
  testing::internal::CaptureStdout();
  monitor.PrintGeneralRegisters(register_packet);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  register_packet =
      "00000000000000000000000000120003c5020000f80000000000000072ee000e20020003"
      "f5c0000000020000d7800012bc100012bcc00000000000000000000061000000";
  expected_output =
      "R0                                      0x00000000\n"
      "R1                                      0x00000000\n"
      "R2                                      0x00000000\n"
      "R3                                      0x00120003\n"
      "R4                                      0xc5020000\n"
      "R5                                      0xf8000000\n"
      "R6                                      0x00000000\n"
      "R7                                      0x72ee000e\n"
      "R8                                      0x20020003\n"
      "R9                                      0xf5c00000\n"
      "R10                                     0x00020000\n"
      "R11                                     0xd7800012\n"
      "R12                                     0xbc100012\n"
      "SP                                      0xbcc00000\n"
      "LR                                      0x00000000\n"
      "PC                                      0x00000000\n"
      "PSR                                     0x61000000\n";
  testing::internal::CaptureStdout();
  monitor.PrintGeneralRegisters(register_packet);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);
}

TEST(Cortexm4GdbMonitor, TestPrintOneFlag) {
  Cortexm4GdbMonitor monitor(0);
  uint32_t register_value = 0;
  register_value |= 1 << 5;
  register_value |= 1 << 27;  // bit 5, 27 set, rest unset
  std::string expected_output =
      "Flag 5                                  true\n";
  testing::internal::CaptureStdout();
  monitor.PrintOneFlag(register_value, "Flag 5", 5);
  std::string output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  expected_output = "Flag 27                                 true\n";
  testing::internal::CaptureStdout();
  monitor.PrintOneFlag(register_value, "Flag 27", 27);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  expected_output = "Flag 0                                  false\n";
  testing::internal::CaptureStdout();
  monitor.PrintOneFlag(register_value, "Flag 0", 0);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  expected_output = "Flag 31                                 false\n";
  testing::internal::CaptureStdout();
  monitor.PrintOneFlag(register_value, "Flag 31", 31);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);
}

TEST(Cortexm4GdbMonitor, TestPrintCfsrRegister) {
  Cortexm4GdbMonitor monitor(0);
  uint32_t register_value = 0;  // all bits unset
  std::string expected_output =
      "Instruction Access Violation:           false\n"
      "Data Access Violation:                  false\n"
      "Memory Management Unstacking Fault:     false\n"
      "Memory Management Stacking Fault:       false\n"
      "Memory Management Lazy FP Fault:        false\n"
      "Valid Memory Fault Address:             false\n"
      "Instruction Bus Error:                  false\n"
      "Precise Data Bus Error:                 false\n"
      "Imprecise Data Bus Error:               false\n"
      "Bus Unstacking Fault:                   false\n"
      "Bus Stacking Fault:                     false\n"
      "Bus Lazy FP Fault:                      false\n"
      "Valid Bus Fault Address:                false\n"
      "Undefined Instruction Usage Fault:      false\n"
      "Invalid State Usage Fault:              false\n"
      "Invalid PC Load Usage Fault:            false\n"
      "No Coprocessor Usage Fault:             false\n"
      "Unaligned Access Usage Fault:           false\n"
      "Divide By Zero:                         false\n";
  testing::internal::CaptureStdout();
  monitor.PrintCfsrRegister(register_value);
  std::string output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  register_value = ~0;  // all bits set
  expected_output =
      "Instruction Access Violation:           true\n"
      "Data Access Violation:                  true\n"
      "Memory Management Unstacking Fault:     true\n"
      "Memory Management Stacking Fault:       true\n"
      "Memory Management Lazy FP Fault:        true\n"
      "Valid Memory Fault Address:             true\n"
      "Instruction Bus Error:                  true\n"
      "Precise Data Bus Error:                 true\n"
      "Imprecise Data Bus Error:               true\n"
      "Bus Unstacking Fault:                   true\n"
      "Bus Stacking Fault:                     true\n"
      "Bus Lazy FP Fault:                      true\n"
      "Valid Bus Fault Address:                true\n"
      "Undefined Instruction Usage Fault:      true\n"
      "Invalid State Usage Fault:              true\n"
      "Invalid PC Load Usage Fault:            true\n"
      "No Coprocessor Usage Fault:             true\n"
      "Unaligned Access Usage Fault:           true\n"
      "Divide By Zero:                         true\n";
  testing::internal::CaptureStdout();
  monitor.PrintCfsrRegister(register_value);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  register_value = 0;
  register_value |= 1 << 5;
  register_value |= 1 << 27;  // bit 5, 27 set, rest unset
  expected_output =
      "Instruction Access Violation:           false\n"
      "Data Access Violation:                  false\n"
      "Memory Management Unstacking Fault:     false\n"
      "Memory Management Stacking Fault:       false\n"
      "Memory Management Lazy FP Fault:        true\n"
      "Valid Memory Fault Address:             false\n"
      "Instruction Bus Error:                  false\n"
      "Precise Data Bus Error:                 false\n"
      "Imprecise Data Bus Error:               false\n"
      "Bus Unstacking Fault:                   false\n"
      "Bus Stacking Fault:                     false\n"
      "Bus Lazy FP Fault:                      false\n"
      "Valid Bus Fault Address:                false\n"
      "Undefined Instruction Usage Fault:      false\n"
      "Invalid State Usage Fault:              false\n"
      "Invalid PC Load Usage Fault:            false\n"
      "No Coprocessor Usage Fault:             false\n"
      "Unaligned Access Usage Fault:           false\n"
      "Divide By Zero:                         false\n";
  testing::internal::CaptureStdout();
  monitor.PrintCfsrRegister(register_value);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  register_value = 0;
  register_value |= 1 << 1;
  register_value |= 1 << 4;
  register_value |= 1 << 12;  // bit 1, 4, 12 set, rest unset
  expected_output =
      "Instruction Access Violation:           false\n"
      "Data Access Violation:                  true\n"
      "Memory Management Unstacking Fault:     false\n"
      "Memory Management Stacking Fault:       true\n"
      "Memory Management Lazy FP Fault:        false\n"
      "Valid Memory Fault Address:             false\n"
      "Instruction Bus Error:                  false\n"
      "Precise Data Bus Error:                 false\n"
      "Imprecise Data Bus Error:               false\n"
      "Bus Unstacking Fault:                   false\n"
      "Bus Stacking Fault:                     true\n"
      "Bus Lazy FP Fault:                      false\n"
      "Valid Bus Fault Address:                false\n"
      "Undefined Instruction Usage Fault:      false\n"
      "Invalid State Usage Fault:              false\n"
      "Invalid PC Load Usage Fault:            false\n"
      "No Coprocessor Usage Fault:             false\n"
      "Unaligned Access Usage Fault:           false\n"
      "Divide By Zero:                         false\n";
  testing::internal::CaptureStdout();
  monitor.PrintCfsrRegister(register_value);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);
}

TEST(Cortexm4GdbMonitor, TestPrintHfsrRegister) {
  Cortexm4GdbMonitor monitor(0);
  uint32_t register_value = 0;  // all bits unset
  std::string expected_output =
      "Bus Fault on Vector Table Read:         false\n"
      "Forced Hard Fault:                      false\n";
  testing::internal::CaptureStdout();
  monitor.PrintHfsrRegister(register_value);
  std::string output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  register_value = 0;
  register_value |= 1 << 1;
  register_value |= 1 << 2;
  register_value |= 1 << 4;
  register_value |= 1 << 12;  // bit 1, 2, 4, 12 set, rest unset
  expected_output =
      "Bus Fault on Vector Table Read:         true\n"
      "Forced Hard Fault:                      false\n";
  testing::internal::CaptureStdout();
  monitor.PrintHfsrRegister(register_value);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  register_value = ~0;  // all bits set
  expected_output =
      "Bus Fault on Vector Table Read:         true\n"
      "Forced Hard Fault:                      true\n";
  testing::internal::CaptureStdout();
  monitor.PrintHfsrRegister(register_value);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);
}

}  // namespace
}  // namespace fido2_tests

