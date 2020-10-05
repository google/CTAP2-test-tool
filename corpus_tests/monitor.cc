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

#include "corpus_tests/monitor.h"

#include <arpa/inet.h>

#include <iomanip>
#include <iostream>

#include "absl/strings/str_cat.h"

namespace corpus_tests {

namespace {

// Memory addresses of the status registers for fault exceptions.
constexpr std::string_view kConfigurableFaultStatusRegister = "e000ed28";
constexpr std::string_view kHardFaultStatusRegister = "e000ed2c";
constexpr std::string_view kBusFaultAddressRegister = "e000ed38";
constexpr std::string_view kMemManageFaultAddressRegister = "e000ed34";
// Architecture specific register length in bytes.
constexpr int kRegisterLength = 4;
// Default number of retries.
constexpr int kRetries = 10;

// Prints the details of the stop reply according to
// https://sourceware.org/gdb/current/onlinedocs/gdb/Stop-Reply-Packets.html#Stop-Reply-Packets
void PrintStopReply(std::string_view response) {
  if (response[0] == 'N') {
    std::cout << "There are no resumed threads left in the target."
              << std::endl;
    return;
  }
  if (response[0] == 'S' || response[0] == 'T') {
    std::cout << "The program received signal: " << response.substr(1, 2);
    if (response[0] == 'T') {
      std::cout << ", " << response.substr(3);
    }
    std::cout << std::endl;
    return;
  }
  if (response[0] == 'W') {
    std::cout << "The process exited with exit status: "
              << response.substr(1, 2);
    if (response.size() > 3) {
      std::cout << ", " << response.substr(4) << std::endl;
    }
    return;
  }
  if (response[0] == 'X') {
    std::cout << "The process terminated with signal: "
              << response.substr(1, 2);
    if (response.size() > 3) {
      std::cout << ", " << response.substr(4) << std::endl;
    }
    return;
  }
}

// Prints all general registers of the architecture.
// Processor general registers summary can be found in:
// https://developer.arm.com/documentation/ddi0439/b/Programmers-Model/Processor-core-register-summary
void PrintGeneralRegisters(std::string_view register_packet) {
  if (register_packet.length() != 17 * 2 * kRegisterLength) {
    std::cout << "Error reading general registers. Got unexpected response: "
              << register_packet << std::endl;
    return;
  }
  for (int i = 0; i < 13; ++i) {
    std::cout << std::left << std::setw(10) << "R" + std::to_string(i) << "0x"
              << register_packet.substr(i * 2 * kRegisterLength,
                                        2 * kRegisterLength)
              << std::endl;
  }
  std::cout << std::left << std::setw(10) << "SP"
            << "0x"
            << register_packet.substr(13 * 2 * kRegisterLength,
                                      2 * kRegisterLength)
            << std::endl;
  std::cout << std::left << std::setw(10) << "LR"
            << "0x"
            << register_packet.substr(14 * 2 * kRegisterLength,
                                      2 * kRegisterLength)
            << std::endl;
  std::cout << std::left << std::setw(10) << "PC"
            << "0x"
            << register_packet.substr(15 * 2 * kRegisterLength,
                                      2 * kRegisterLength)
            << std::endl;
  std::cout << std::left << std::setw(10) << "PRS"
            << "0x"
            << register_packet.substr(16 * 2 * kRegisterLength,
                                      2 * kRegisterLength)
            << std::endl;
}

// Prints the information contained in the configurable fault status register.
// Details can be found at https://www.keil.com/appnotes/files/apnt209.pdf
// page 8.
void PrintCfsrRegister(uint32_t register_value) {
  // Memory Management Status Register
  // IACCVIOL: Instruction access violation flag
  std::cout << std::left << std::setw(40)
            << "Instruction Access Violation:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 0)) << std::endl;
  // DACCVIOL: Data access violation flag
  std::cout << std::left << std::setw(40)
            << "Data Access Violation:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 1)) << std::endl;
  // MUNSTKERR: MemManage fault on unstacking for a return from exception
  std::cout << std::left << std::setw(40)
            << "Memory Management Unstacking Fault:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 3)) << std::endl;
  // MSTKERR: MemManage fault on stacking for exception entry
  std::cout << std::left << std::setw(40)
            << "Memory Management Stacking Fault:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 4)) << std::endl;
  // MLSPERR: MemManage fault during floating point lazy state preservation
  // (only Cortex-M4 with FPU)
  std::cout << std::left << std::setw(40)
            << "Memory Management Lazy FP Fault:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 5)) << std::endl;
  // MMARVALID: MemManage Fault Address Register (MMFAR) valid flag
  std::cout << std::left << std::setw(40)
            << "Valid Memory Fault Address:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 7)) << std::endl;

  // Bus Fault Status Register
  // IBUSERR: Instruction bus error
  std::cout << std::left << std::setw(40)
            << "Instruction Bus Error:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 8)) << std::endl;
  // PRECISERR: Precise data bus error
  std::cout << std::left << std::setw(40)
            << "Precise Data Bus Error:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 9)) << std::endl;
  // IMPRECISERR: Imprecise data bus error
  std::cout << std::left << std::setw(40)
            << "Imprecise Data Bus Error:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 10)) << std::endl;
  // UNSTKERR: BusFault on unstacking for a return from exception
  std::cout << std::left << std::setw(40)
            << "Bus Unstacking Fault:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 11)) << std::endl;
  // STKERR: BusFault on stacking for exception entry
  std::cout << std::left << std::setw(40)
            << "Bus Stacking Fault:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 12)) << std::endl;
  // LSPERR: BusFault during floating point lazy state preservation (only when
  // FPU present)
  std::cout << std::left << std::setw(40)
            << "Bus Lazy FP Fault:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 13)) << std::endl;
  // BFARVALID: BusFault Address Register (BFAR) valid flag
  std::cout << std::left << std::setw(40)
            << "Valid Bus Fault Address:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 15)) << std::endl;

  // Usage Fault Status Register
  // UNDEFINSTR: Undefined instruction
  std::cout << std::left << std::setw(40)
            << "Undefined Instruction Usage Fault:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 16)) << std::endl;
  // INVSTATE: Invalid state
  std::cout << std::left << std::setw(40)
            << "Invalid State Usage Fault:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 17)) << std::endl;
  // INVPC: Invalid PC load UsageFault
  std::cout << std::left << std::setw(40)
            << "Invalid PC Load Usage Fault:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 18)) << std::endl;
  // NOCP: No coprocessor
  std::cout << std::left << std::setw(40)
            << "No Coprocessor Usage Fault:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 19)) << std::endl;
  // UNALIGNED: Unaligned access UsageFault
  std::cout << std::left << std::setw(40)
            << "Unaligned Access Usage Fault:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 24)) << std::endl;
  // DIVBYZERO: Divide by zero UsageFault
  std::cout << std::left << std::setw(40) << "Divide By Zero:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 25)) << std::endl;
}

// Prints the information contained in the hard fault status register.
// Details can be found at https://www.keil.com/appnotes/files/apnt209.pdf
// page 7.
void PrintHfsrRegister(uint32_t register_value) {
  // VECTTBL: Indicates a Bus Fault on a vector table read during exception
  // processing
  std::cout << std::left << std::setw(40)
            << "Bus Fault on Vector Table Read:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 1)) << std::endl;
  // FORCED: Indicates a forced Hard Fault
  std::cout << std::left << std::setw(40)
            << "Forced Hard Fault:" << std::boolalpha
            << static_cast<bool>(register_value & (1 << 30)) << std::endl;
}

}  // namespace

bool Monitor::Attach(fido2_tests::DeviceInterface* device, int port) {
  device_ = device;
  if (!rsp_client_.Initialize()) {
    return false;
  }
  return rsp_client_.Connect(port);
}

bool Monitor::Start() {
  return rsp_client_.SendPacket(rsp::RspPacket(rsp::RspPacket::Continue));
}

bool Monitor::DeviceCrashed() {
  bool ok;
  std::tie(ok, stop_message_) = rsp_client_.ReceivePacket();
  return ok;
}

void Monitor::PrintCrashReport() {
  PrintStopReply(stop_message_);
  bool ok;
  std::string response;

  std::cout << "----| General registers |----" << std::endl;
  std::tie(ok, response) = rsp_client_.SendRecvPacket(
      rsp::RspPacket::ReadGeneralRegisters, kRetries);
  if (ok) {
    PrintGeneralRegisters(response);
  } else {
    std::cout << "Error reading general registers." << std::endl;
  }

  std::cout << "----| Kernal Fault Status |----" << std::endl;
  // Print CFSR register.
  std::tie(ok, response) = rsp_client_.SendRecvPacket(
      rsp::RspPacket(rsp::RspPacket::ReadFromMemory,
                     kConfigurableFaultStatusRegister, kRegisterLength),
      kRetries);
  if (ok) {
    uint32_t register_value = static_cast<uint32_t>(stoul(response, 0, 16));
    // Register value is in host order in memory.
    register_value = htonl(register_value);
    PrintCfsrRegister(register_value);
  } else {
    std::cout << "Error reading Configurable Fault Status Register."
              << std::endl;
  }
  // Print HFSR register.
  std::tie(ok, response) = rsp_client_.SendRecvPacket(
      rsp::RspPacket(rsp::RspPacket::ReadFromMemory, kHardFaultStatusRegister,
                     kRegisterLength),
      kRetries);
  if (ok) {
    uint32_t register_value = static_cast<uint32_t>(stoul(response, 0, 16));
    // Register value is in host order in memory.
    register_value = htonl(register_value);
    PrintHfsrRegister(register_value);
  } else {
    std::cout << "Error reading Hard Fault Status Register." << std::endl;
  }
  // Print memory fault and bus fault addresses.
  std::tie(ok, response) = rsp_client_.SendRecvPacket(
      rsp::RspPacket(rsp::RspPacket::ReadFromMemory,
                     kMemManageFaultAddressRegister, kRegisterLength),
      kRetries);
  if (ok) {
    uint32_t register_value = static_cast<uint32_t>(stoul(response, 0, 16));
    // Register value is in host order in memory.
    register_value = htonl(register_value);
    std::cout << std::left << std::setw(40) << "Memory Fault Address:"
              << "0x"
              << absl::StrCat(absl::Hex(register_value, absl::kZeroPad8))
              << std::endl;
  } else {
    std::cout << "Error reading Memory Fault Address." << std::endl;
  }
  std::tie(ok, response) = rsp_client_.SendRecvPacket(
      rsp::RspPacket(rsp::RspPacket::ReadFromMemory, kBusFaultAddressRegister,
                     kRegisterLength),
      kRetries);
  if (ok) {
    uint32_t register_value = static_cast<uint32_t>(stoul(response, 0, 16));
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

}  // namespace corpus_tests