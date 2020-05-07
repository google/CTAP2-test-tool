# The chromium CBOR parser.
# The fuzzer is removed, trusting upstream to execute it.

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "cbor",
    srcs = [
        "reader.cc",
        "values.cc",
        "writer.cc",
    ],
    hdrs = [
        "cbor_export.h",
        "constants.h",
        "reader.h",
        "values.h",
        "writer.h",
    ],
    deps = [
        "@com_google_glog//:glog",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
        "//third_party/chromium_base_numerics:numerics",
    ],
)

cc_test(
    name = "reader_test",
    srcs = ["reader_unittest.cc"],
    deps = [
        "cbor",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "values_test",
    srcs = ["values_unittest.cc"],
    deps = [
        "cbor",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "writer_test",
    srcs = ["writer_unittest.cc"],
    deps = [
        "cbor",
        "@com_google_googletest//:gtest_main",
        "@com_google_absl//absl/base:core_headers",
    ],
)
