// Copyright 2019 Google LLC
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

#include <iostream>

#include "gflags/gflags.h"
#include "glog/logging.h"
#include "src/constants.h"
#include "src/device_tracker.h"
#include "src/hid/hid_device.h"
#include "src/parameter_check.h"
#include "src/test_series.h"

DEFINE_string(
    token_path, "",
    "The path to the device on your operating system, usually /dev/hidraw*.");

DEFINE_string(commit_hash, "",
              "The reported commit hash, logged in the JSON output.");

DEFINE_bool(verbose, false, "Printing debug logs, i.e. transmitted packets.");

DEFINE_int32(num_credentials, 50,
             "Maximum number of created credentials to test the key store.");

// Calling this function first connects to the device and then executes all test
// series listed.
//
// Usage example:
//   ./fido2_conformance --token_path=/dev/hidraw4 --verbose
int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  if (FLAGS_token_path.empty()) {
    std::cout << "Please add the --token_path flag for one of these devices:"
              << std::endl;
    fido2_tests::hid::PrintFidoDevices();
    exit(0);
  }

  if (FLAGS_token_path == "_") {
    // This magic value is used by the run script for comfort.
    FLAGS_token_path = fido2_tests::hid::FindFidoDevicePath();
    std::cout << "Testing device at path: " << FLAGS_token_path << std::endl;
  }

  if (FLAGS_commit_hash.empty()) {
    std::cout << "No commit hash passed, please add the --commit_hash flag or "
              << "manually add the commit to your report." << std::endl;
  }

  fido2_tests::DeviceTracker tracker;
  std::unique_ptr<fido2_tests::DeviceInterface> device =
      absl::make_unique<fido2_tests::hid::HidDevice>(&tracker, FLAGS_token_path,
                                                     FLAGS_verbose);
  CHECK(fido2_tests::Status::kErrNone == device->Init())
      << "CTAPHID initialization failed";
  device->Wink();

  fido2_tests::InputParameterTestSeries input_parameter_test_series =
      fido2_tests::InputParameterTestSeries(device.get(), &tracker);
  fido2_tests::SpecificationProcedure specification_procedure_test_series =
      fido2_tests::SpecificationProcedure(device.get(), &tracker);

  specification_procedure_test_series.Reset();
  bool is_fido_2_1_compliant =
      specification_procedure_test_series.GetInfoIs2Point1Compliant();

  input_parameter_test_series.MakeCredentialBadParameterTypesTest();
  input_parameter_test_series.MakeCredentialMissingParameterTest();
  input_parameter_test_series.MakeCredentialRelyingPartyEntityTest();
  input_parameter_test_series.MakeCredentialUserEntityTest();
  input_parameter_test_series.MakeCredentialExcludeListTest();
  input_parameter_test_series.MakeCredentialExtensionsTest();
  input_parameter_test_series.GetAssertionBadParameterTypesTest();
  input_parameter_test_series.GetAssertionMissingParameterTest();
  input_parameter_test_series.GetAssertionAllowListTest();
  input_parameter_test_series.GetAssertionExtensionsTest();
  input_parameter_test_series.ClientPinGetPinRetriesTest();
  input_parameter_test_series.ClientPinGetKeyAgreementTest();
  input_parameter_test_series.ClientPinSetPinTest();
  input_parameter_test_series.ClientPinChangePinTest();
  input_parameter_test_series.ClientPinGetPinUvAuthTokenUsingPinTest();
  if (is_fido_2_1_compliant) {
    input_parameter_test_series.ClientPinGetPinUvAuthTokenUsingUvTest();
    input_parameter_test_series.ClientPinGetUVRetriesTest();
  }

  specification_procedure_test_series.ResetDeletionTest();
  specification_procedure_test_series.ResetPhysicalPresenceTest();
  specification_procedure_test_series.PersistenceTest();

  specification_procedure_test_series.MakeCredentialExcludeListTest();
  specification_procedure_test_series.MakeCredentialCoseAlgorithmTest();
  specification_procedure_test_series.MakeCredentialOptionsTest();
  specification_procedure_test_series.MakeCredentialPinAuthTest(
      is_fido_2_1_compliant);
  specification_procedure_test_series.MakeCredentialMultipleKeysTest(
      FLAGS_num_credentials);
  specification_procedure_test_series.MakeCredentialPhysicalPresenceTest();
  specification_procedure_test_series.MakeCredentialDisplayNameEncodingTest();

  specification_procedure_test_series.GetAssertionOptionsTest();
  specification_procedure_test_series.GetAssertionResidentialKeyTest();
  specification_procedure_test_series.GetAssertionPinAuthTest(
      is_fido_2_1_compliant);
  specification_procedure_test_series.GetAssertionPhysicalPresenceTest();

  specification_procedure_test_series.GetInfoTest();
  specification_procedure_test_series.ClientPinRequirementsTest();
  specification_procedure_test_series.ClientPinRetriesTest();
  if (specification_procedure_test_series.GetInfoIsHmacSecretSupported()) {
    specification_procedure_test_series.MakeCredentialHmacSecretTest();
  }

  std::cout << "\nRESULTS" << std::endl;
  tracker.ReportFindings();
  tracker.SaveResultsToFile(FLAGS_commit_hash);
}
