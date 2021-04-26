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

#ifndef CORTEXM4_GDB_MONITOR_H_
#define CORTEXM4_GDB_MONITOR_H_

#include "src/monitors/gdb_monitor.h"

namespace fido2_tests {

// A GdbMonitor specific to the Cortex m4 architecture, capable of
// a more detailed crash report.
class Cortexm4GdbMonitor : public GdbMonitor {
 public:
  Cortexm4GdbMonitor(int port);
  // Prints the general registers and fault status of the
  // cortex m4 architecture.
  void PrintCrashReport() override;
  // Prints a singular register from the given register packet.
  void PrintOneRegister(const std::string_view& register_packet,
                        const std::string_view& register_name,
                        int register_number);
  // Prints all general registers of the architecture.
  // Processor general registers summary can be found in:
  // https://developer.arm.com/documentation/ddi0439/b/Programmers-Model/Processor-core-register-summary.
  void PrintGeneralRegisters(const std::string_view& register_packet);
  // Prints a singular flag information from the given register value.
  void PrintOneFlag(uint32_t register_value, const std::string_view& flag_info,
                    int flag_bit);
  // Prints the information contained in the configurable fault status register.
  // Details can be found at https://www.keil.com/appnotes/files/apnt209.pdf
  // page 8.
  void PrintCfsrRegister(uint32_t register_value);
  // Prints the information contained in the hard fault status register.
  // Details can be found at https://www.keil.com/appnotes/files/apnt209.pdf
  // page 7.
  void PrintHfsrRegister(uint32_t register_value);

 private:
  rsp::RemoteSerialProtocol& rsp_client_;
};

}  // namespace fido2_tests

#endif  // CORTEXM4_GDB_MONITOR_H_

