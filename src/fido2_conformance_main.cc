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
#include "src/tests/test_series.h"

DEFINE_string(
    token_path, "",
    "The path to the device on your operating system, usually /dev/hidraw*.");

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

  fido2_tests::DeviceTracker tracker;
  std::unique_ptr<fido2_tests::DeviceInterface> device =
      absl::make_unique<fido2_tests::hid::HidDevice>(&tracker, FLAGS_token_path,
                                                     FLAGS_verbose);
  CHECK(fido2_tests::Status::kErrNone == device->Init())
      << "CTAPHID initialization failed";
  device->Wink();

  fido2_tests::TestSeries test_series =
      fido2_tests::TestSeries(device.get(), &tracker);

  test_series.Reset();
  // You need to execute GetInfo first to initialize the tracker.
  test_series.GetInfoTest();

  test_series.MakeCredentialBadParameterTypesTest();
  test_series.MakeCredentialMissingParameterTest();
  test_series.MakeCredentialRelyingPartyEntityTest();
  test_series.MakeCredentialUserEntityTest();
  test_series.MakeCredentialExcludeListCredentialDescriptorTest();
  test_series.MakeCredentialExtensionsTest();
  test_series.GetAssertionBadParameterTypesTest();
  test_series.GetAssertionMissingParameterTest();
  test_series.GetAssertionAllowListCredentialDescriptorTest();
  test_series.GetAssertionExtensionsTest();
  test_series.ClientPinGetPinRetriesTest();
  test_series.ClientPinGetKeyAgreementTest();
  test_series.ClientPinSetPinTest();
  test_series.ClientPinChangePinTest();
  test_series.ClientPinGetPinUvAuthTokenUsingPinTest();
  test_series.ClientPinGetPinUvAuthTokenUsingUvTest();
  test_series.ClientPinGetUVRetriesTest();

  test_series.ResetDeletionTest();
  test_series.ResetPhysicalPresenceTest();
  test_series.PersistenceTest();

  test_series.MakeCredentialExcludeListTest();
  test_series.MakeCredentialCoseAlgorithmTest();
  test_series.MakeCredentialOptionsTest();
  test_series.MakeCredentialPinAuthTest();
  test_series.MakeCredentialMultipleKeysTest(FLAGS_num_credentials);
  test_series.MakeCredentialPhysicalPresenceTest();
  test_series.MakeCredentialDisplayNameEncodingTest();

  test_series.GetAssertionOptionsTest();
  test_series.GetAssertionResidentialKeyTest();
  test_series.GetAssertionPinAuthTest();
  test_series.GetAssertionPhysicalPresenceTest();

  test_series.ClientPinRequirementsTest();
  test_series.ClientPinRequirements2Point1Test();
  test_series.ClientPinRetriesTest();
  test_series.MakeCredentialHmacSecretTest();

  std::cout << "\nRESULTS" << std::endl;
  tracker.ReportFindings();
  tracker.SaveResultsToFile();
}
