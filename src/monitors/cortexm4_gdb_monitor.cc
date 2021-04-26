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

#include <arpa/inet.h>

#include <iomanip>
#include <iostream>

#include "absl/strings/str_cat.h"

namespace fido2_tests {

// Memory addresses of the status registers for fault exceptions.
constexpr std::string_view kConfigurableFaultStatusRegister = "e000ed28";
constexpr std::string_view kHardFaultStatusRegister = "e000ed2c";
constexpr std::string_view kBusFaultAddressRegister = "e000ed38";
constexpr std::string_view kMemManageFaultAddressRegister = "e000ed34";
// Architecture specific register related information.
constexpr int kRegisterLength = 4;
constexpr int kRegisterHexLength = 2 * kRegisterLength;
constexpr int kNumTotalRegisters = 17;
constexpr int kNumNumberedRegisters = 13;
// Default number of retries.
constexpr int kRetries = 10;
// Default field width used for printing registers.
constexpr int kFieldWidth = 40;

Cortexm4GdbMonitor::Cortexm4GdbMonitor(int port)
    : GdbMonitor(port), rsp_client_(GdbMonitor::GetRspClient()) {}

void Cortexm4GdbMonitor::PrintOneRegister(
    const std::string_view& register_packet,
    const std::string_view& register_name, int register_number) {
  std::cout << std::left << std::setw(kFieldWidth) << register_name << "0x"
            << register_packet.substr(register_number * kRegisterHexLength,
                                      kRegisterHexLength)
            << std::endl;
}

void Cortexm4GdbMonitor::PrintGeneralRegisters(
    const std::string_view& register_packet) {
  if (register_packet.length() != kNumTotalRegisters * kRegisterHexLength) {
    std::cout << "Error reading general registers. Got unexpected response: "
              << register_packet << std::endl;
    return;
  }
  for (int i = 0; i < kNumNumberedRegisters; ++i) {
    PrintOneRegister(register_packet, absl::StrCat("R", i), i);
  }
  PrintOneRegister(register_packet, "SP", 13);
  PrintOneRegister(register_packet, "LR", 14);
  PrintOneRegister(register_packet, "PC", 15);
  PrintOneRegister(register_packet, "PSR", 16);
}

void Cortexm4GdbMonitor::PrintOneFlag(uint32_t register_value,
                                      const std::string_view& flag_info,
                                      int flag_bit) {
  std::cout << std::left << std::setw(kFieldWidth) << flag_info
            << std::boolalpha
            << static_cast<bool>(register_value & (1 << flag_bit)) << std::endl;
}

void Cortexm4GdbMonitor::PrintCfsrRegister(uint32_t register_value) {
  // Memory Management Status Register
  // IACCVIOL: Instruction access violation flag
  PrintOneFlag(register_value, "Instruction Access Violation:", 0);
  // DACCVIOL: Data access violation flag
  PrintOneFlag(register_value, "Data Access Violation:", 1);
  // MUNSTKERR: MemManage fault on unstacking for a return from exception
  PrintOneFlag(register_value, "Memory Management Unstacking Fault:", 3);
  // MSTKERR: MemManage fault on stacking for exception entry
  PrintOneFlag(register_value, "Memory Management Stacking Fault:", 4);
  // MLSPERR: MemManage fault during floating point lazy state preservation
  // (only Cortex-M4 with FPU)
  PrintOneFlag(register_value, "Memory Management Lazy FP Fault:", 5);
  // MMARVALID: MemManage Fault Address Register (MMFAR) valid flag
  PrintOneFlag(register_value, "Valid Memory Fault Address:", 7);

  // Bus Fault Status Register
  // IBUSERR: Instruction bus error
  PrintOneFlag(register_value, "Instruction Bus Error:", 8);
  // PRECISERR: Precise data bus error
  PrintOneFlag(register_value, "Precise Data Bus Error:", 9);
  // IMPRECISERR: Imprecise data bus error
  PrintOneFlag(register_value, "Imprecise Data Bus Error:", 10);
  // UNSTKERR: BusFault on unstacking for a return from exception
  PrintOneFlag(register_value, "Bus Unstacking Fault:", 11);
  // STKERR: BusFault on stacking for exception entry
  PrintOneFlag(register_value, "Bus Stacking Fault:", 12);
  // LSPERR: BusFault during floating point lazy state preservation (only when
  // FPU present)
  PrintOneFlag(register_value, "Bus Lazy FP Fault:", 13);
  // BFARVALID: BusFault Address Register (BFAR) valid flag
  PrintOneFlag(register_value, "Valid Bus Fault Address:", 15);

  // Usage Fault Status Register
  // UNDEFINSTR: Undefined instruction
  PrintOneFlag(register_value, "Undefined Instruction Usage Fault:", 16);
  // INVSTATE: Invalid state
  PrintOneFlag(register_value, "Invalid State Usage Fault:", 17);
  // INVPC: Invalid PC load UsageFault
  PrintOneFlag(register_value, "Invalid PC Load Usage Fault:", 18);
  // NOCP: No coprocessor
  PrintOneFlag(register_value, "No Coprocessor Usage Fault:", 19);
  // UNALIGNED: Unaligned access UsageFault
  PrintOneFlag(register_value, "Unaligned Access Usage Fault:", 24);
  // DIVBYZERO: Divide by zero UsageFault
  PrintOneFlag(register_value, "Divide By Zero:", 25);
}

void Cortexm4GdbMonitor::PrintHfsrRegister(uint32_t register_value) {
  // VECTTBL: Indicates a Bus Fault on a vector table read during exception
  // processing
  PrintOneFlag(register_value, "Bus Fault on Vector Table Read:", 1);
  // FORCED: Indicates a forced Hard Fault
  PrintOneFlag(register_value, "Forced Hard Fault:", 30);
}

void Cortexm4GdbMonitor::PrintCrashReport() {
  GdbMonitor::PrintCrashReport();
  std::optional<std::string> response;

  std::cout << "----| General registers |----" << std::endl;
  response = rsp_client_.SendRecvPacket(rsp::RspPacket::ReadGeneralRegisters,
                                        kRetries);
  if (response.has_value()) {
    PrintGeneralRegisters(response.value());
  } else {
    std::cout << "Error reading general registers." << std::endl;
  }

  std::cout << "----| Kernel Fault Status |----" << std::endl;
  // Print CFSR register.
  response = rsp_client_.SendRecvPacket(
      rsp::RspPacket(rsp::RspPacket::ReadFromMemory,
                     kConfigurableFaultStatusRegister, kRegisterLength),
      kRetries);
  if (response.has_value()) {
    uint32_t register_value =
        static_cast<uint32_t>(stoul(response.value(), 0, 16));
    // Register value is in host order in memory.
    register_value = htonl(register_value);
    PrintCfsrRegister(register_value);
  } else {
    std::cout << "Error reading Configurable Fault Status Register."
              << std::endl;
  }
  // Print HFSR register.
  response = rsp_client_.SendRecvPacket(
      rsp::RspPacket(rsp::RspPacket::ReadFromMemory, kHardFaultStatusRegister,
                     kRegisterLength),
      kRetries);
  if (response.has_value()) {
    uint32_t register_value =
        static_cast<uint32_t>(stoul(response.value(), 0, 16));
    // Register value is in host order in memory.
    register_value = htonl(register_value);
    PrintHfsrRegister(register_value);
  } else {
    std::cout << "Error reading Hard Fault Status Register." << std::endl;
  }
  // Print memory fault and bus fault addresses.
  response = rsp_client_.SendRecvPacket(
      rsp::RspPacket(rsp::RspPacket::ReadFromMemory,
                     kMemManageFaultAddressRegister, kRegisterLength),
      kRetries);
  if (response.has_value()) {
    uint32_t register_value =
        static_cast<uint32_t>(stoul(response.value(), 0, 16));
    // Register value is in host order in memory.
    register_value = htonl(register_value);
    std::cout << std::left << std::setw(40) << "Memory Fault Address:"
              << "0x"
              << absl::StrCat(absl::Hex(register_value, absl::kZeroPad8))
              << std::endl;
  } else {
    std::cout << "Error reading Memory Fault Address." << std::endl;
  }
  response = rsp_client_.SendRecvPacket(
      rsp::RspPacket(rsp::RspPacket::ReadFromMemory, kBusFaultAddressRegister,
                     kRegisterLength),
      kRetries);
  if (response.has_value()) {
    uint32_t register_value =
        static_cast<uint32_t>(stoul(response.value(), 0, 16));
    // Register value is in host order in memory.
    register_value = htonl(register_value);
    std::cout << std::left << std::setw(40) << "Bus Fault Address:"
              << "0x"
              << absl::StrCat(absl::Hex(register_value, absl::kZeroPad8))
              << std::endl;
  } else {
    std::cout << "Error reading Bus Fault Address." << std::endl;
  }
}

}  // namespace fido2_tests

