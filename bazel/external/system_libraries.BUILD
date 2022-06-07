# Copyright 2021 The Magma Authors.

# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@bazel_skylib//rules:native_binary.bzl", "native_binary")
load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

# This configuration is used for building inside the Magma VM
# The default configuration applies for building inside the bazel build Docker container
config_setting(
    name = "use_folly_so",
    values = {"define": "folly_so=1"},
)

cc_library(
    name = "folly",
    srcs = select({
        ":use_folly_so": ["usr/local/lib/libfolly.so"],
        "//conditions:default": [
            "usr/local/lib/libfolly.a",
            "usr/local/lib/libfmt.a",
        ],
    }),
    linkopts = select({
        ":use_folly_so": [
            "-ldl",
            "-levent",
            "-ldouble-conversion",
            "-lgflags",
        ],
        "//conditions:default": [
            "-ldl",
            "-levent",
            "-ldouble-conversion",
            "-lgflags",
            "-liberty",
        ],
    }),
)

cc_library(
    name = "libmnl",
    linkopts = ["-lmnl"],
)

cc_library(
    name = "grpc_plus_plus",
    srcs = ["usr/local/lib/libgrpc++.so.1.15.0"],
    linkopts = [
        "-lpthread",
        "-lm",
        "-lstdc++",
    ],
)

cc_library(
    name = "proto_source",
    srcs = glob(include = [
        "usr/include/google/protobuf/**/*.c",
        "usr/include/google/protobuf/**/*.cpp",
        "usr/include/google/protobuf/**/*.h",
        "usr/include/google/protobuf/**/*.hpp",
    ]),
)

cc_library(
    name = "glog",
    srcs = ["usr/lib/x86_64-linux-gnu/libglog.so.0.0.0"],
    linkopts = [
        "-lpthread",
        "-lm",
        "-lstdc++",
    ],
)

cc_library(
    name = "proto_static",
    srcs = [
        # "tmp/libdescriptor_proto.upb.so",
        # "usr/lib/x86_64-linux-gnu/libprotobuf.a",
        # "usr/lib/x86_64-linux-gnu/libprotobuf-lite.a",
        "usr/lib/x86_64-linux-gnu/libprotobuf.so.17.0.0",
        "usr/lib/x86_64-linux-gnu/libprotoc.so.17.0.0",
        "usr/lib/x86_64-linux-gnu/libprotobuf-lite.so.17.0.0",
    ],
    linkopts = [
        "-lpthread",
        "-lm",
        "-lstdc++",
    ],
)

cc_library(
    name = "libpcap",
    linkopts = ["-lpcap"],
)

cc_library(
    name = "libuuid",
    linkopts = ["-luuid"],
)

cc_library(
    name = "sctp",
    linkopts = ["-lsctp"],
)

cc_library(
    name = "czmq",
    linkopts = ["-lczmq"],
)

cc_library(
    name = "libconfig",
    linkopts = ["-lconfig"],
)

cc_library(
    name = "libfd",
    srcs = [
        "usr/local/lib/libfdcore.so",
        "usr/local/lib/libfdproto.so",
    ],
    linkopts = [
        "-lfdcore",
        "-lfdproto",
    ],
)

cc_library(
    name = "libnettle",
    srcs = ["usr/lib/libnettle.so"],
    linkopts = ["-lnettle"],
)

cc_library(
    name = "libgnutls",
    srcs = ["usr/lib/libgnutls.so"],
    linkopts = ["-lgnutls"],
)

# TODO(GH9710): Generate asn1c with Bazel
native_binary(
    name = "asn1c",
    src = "usr/local/bin/asn1c",
    out = "asn1c",
)
