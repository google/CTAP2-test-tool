// Copyright 2020 Google LLC
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

#include "corpus_tests/monitor/cortexm4_gdb_monitor.h"

#include <iostream>

#include "gtest/gtest.h"

namespace corpus_tests {
namespace {

TEST(Cortexm4GdbMonitor, TestPrintOneRegister) {
  Cortexm4GdbMonitor monitor(nullptr, 0);
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
  Cortexm4GdbMonitor monitor(nullptr, 0);
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
      "R0                                      0x00000000\nR1                  "
      "                    0x00000000\nR2                                      "
      "0x00000000\nR3                                      0x00120003\nR4      "
      "                                0xc5020000\nR5                          "
      "            0xf8000000\nR6                                      "
      "0x00000000\nR7                                      0x72ee000e\nR8      "
      "                                0x20020003\nR9                          "
      "            0xf5c00000\nR10                                     "
      "0x00020000\nR11                                     0xd7800012\nR12     "
      "                                0xbc100012\nSP                          "
      "            0xbcc00000\nLR                                      "
      "0x00000000\nPC                                      0x00000000\nPSR     "
      "                                0x61000000\n";
  testing::internal::CaptureStdout();
  monitor.PrintGeneralRegisters(register_packet);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);
}

TEST(Cortexm4GdbMonitor, TestPrintOneFlag) {
  Cortexm4GdbMonitor monitor(nullptr, 0);
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
  Cortexm4GdbMonitor monitor(nullptr, 0);
  uint32_t register_value = 0;  // all bits unset
  std::string expected_output =
      "Instruction Access Violation:           false\nData Access Violation:   "
      "               false\nMemory Management Unstacking Fault:     "
      "false\nMemory Management Stacking Fault:       false\nMemory Management "
      "Lazy FP Fault:        false\nValid Memory Fault Address:             "
      "false\nInstruction Bus Error:                  false\nPrecise Data Bus "
      "Error:                 false\nImprecise Data Bus Error:               "
      "false\nBus Unstacking Fault:                   false\nBus Stacking "
      "Fault:                     false\nBus Lazy FP Fault:                    "
      "  false\nValid Bus Fault Address:                false\nUndefined "
      "Instruction Usage Fault:      false\nInvalid State Usage Fault:         "
      "     false\nInvalid PC Load Usage Fault:            false\nNo "
      "Coprocessor Usage Fault:             false\nUnaligned Access Usage "
      "Fault:           false\nDivide By Zero:                         false\n";
  testing::internal::CaptureStdout();
  monitor.PrintCfsrRegister(register_value);
  std::string output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  register_value = 0;
  register_value |= 1 << 5;
  register_value |= 1 << 27;  // bit 5, 27 set, rest unset
  expected_output =
      "Instruction Access Violation:           false\nData Access Violation:   "
      "               false\nMemory Management Unstacking Fault:     "
      "false\nMemory Management Stacking Fault:       false\nMemory Management "
      "Lazy FP Fault:        true\nValid Memory Fault Address:             "
      "false\nInstruction Bus Error:                  false\nPrecise Data Bus "
      "Error:                 false\nImprecise Data Bus Error:               "
      "false\nBus Unstacking Fault:                   false\nBus Stacking "
      "Fault:                     false\nBus Lazy FP Fault:                    "
      "  false\nValid Bus Fault Address:                false\nUndefined "
      "Instruction Usage Fault:      false\nInvalid State Usage Fault:         "
      "     false\nInvalid PC Load Usage Fault:            false\nNo "
      "Coprocessor Usage Fault:             false\nUnaligned Access Usage "
      "Fault:           false\nDivide By Zero:                         false\n";
  testing::internal::CaptureStdout();
  monitor.PrintCfsrRegister(register_value);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  register_value = 0;
  register_value |= 1 << 1;
  register_value |= 1 << 4;
  register_value |= 1 << 12;  // bit 1, 4, 12 set, rest unset
  expected_output =
      "Instruction Access Violation:           false\nData Access Violation:   "
      "               true\nMemory Management Unstacking Fault:     "
      "false\nMemory Management Stacking Fault:       true\nMemory Management "
      "Lazy FP Fault:        false\nValid Memory Fault Address:             "
      "false\nInstruction Bus Error:                  false\nPrecise Data Bus "
      "Error:                 false\nImprecise Data Bus Error:               "
      "false\nBus Unstacking Fault:                   false\nBus Stacking "
      "Fault:                     true\nBus Lazy FP Fault:                    "
      "  false\nValid Bus Fault Address:                false\nUndefined "
      "Instruction Usage Fault:      false\nInvalid State Usage Fault:         "
      "     false\nInvalid PC Load Usage Fault:            false\nNo "
      "Coprocessor Usage Fault:             false\nUnaligned Access Usage "
      "Fault:           false\nDivide By Zero:                         false\n";
  testing::internal::CaptureStdout();
  monitor.PrintCfsrRegister(register_value);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);
}

TEST(Cortexm4GdbMonitor, TestPrintHfsrRegister) {
  Cortexm4GdbMonitor monitor(nullptr, 0);
  uint32_t register_value = 0;  // all bits unset
  std::string expected_output =
      "Bus Fault on Vector Table Read:         false\nForced Hard Fault:       "
      "               false\n";
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
      "Bus Fault on Vector Table Read:         true\nForced Hard Fault:        "
      "              false\n";
  testing::internal::CaptureStdout();
  monitor.PrintHfsrRegister(register_value);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);

  register_value = ~0;  // all bits set
  expected_output =
      "Bus Fault on Vector Table Read:         true\nForced Hard Fault:        "
      "              true\n";
  testing::internal::CaptureStdout();
  monitor.PrintHfsrRegister(register_value);
  output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, expected_output);
}

}  // namespace
}  // namespace corpus_tests