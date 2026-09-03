// minimosq — library version.
//
// The version exists in two places that must agree: project(minimosq
// VERSION ...) in CMakeLists.txt, which is what find_package() and the
// installed package version file report, and the macros below, which are
// all a vendored copy of include/ carries. The release tarball ships the
// headers on their own, so without this a vendored copy is
// unidentifiable — nothing in the tree says which version it is.
//
// Neither may drift, so CMake reads this header at configure time and
// fails the build if the two disagree.
//
//     #include <minimosq/version.hpp>
//     static_assert(MINIMOSQ_VERSION_AT_LEAST(1, 0, 0), "minimosq too old");
//
// Macros rather than constants alone, because a version check has to work
// in the preprocessor; the constexpr values below mirror them for code
// that would rather not use macros.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_VERSION_HPP
#define MINIMOSQ_VERSION_HPP

#define MINIMOSQ_VERSION_MAJOR 1
#define MINIMOSQ_VERSION_MINOR 0
#define MINIMOSQ_VERSION_PATCH 0

// One comparable integer, three digits per component: 1.0.0 -> 1000000.
// Minor and patch are therefore bounded by 999, which is ample and keeps
// a later version from ever comparing below an earlier one.
#define MINIMOSQ_VERSION_NUMBER(major, minor, patch) ((major) * 1000000 + (minor) * 1000 + (patch))

#define MINIMOSQ_VERSION                                                                           \
    MINIMOSQ_VERSION_NUMBER(MINIMOSQ_VERSION_MAJOR, MINIMOSQ_VERSION_MINOR, MINIMOSQ_VERSION_PATCH)

#define MINIMOSQ_VERSION_AT_LEAST(major, minor, patch)                                             \
    (MINIMOSQ_VERSION >= MINIMOSQ_VERSION_NUMBER(major, minor, patch))

// Built from the three numbers above so there is no fourth place to
// update, and no way for the string to disagree with them.
#define MINIMOSQ_VERSION_STRINGIFY_(x) #x
#define MINIMOSQ_VERSION_STRINGIFY(x) MINIMOSQ_VERSION_STRINGIFY_(x)
#define MINIMOSQ_VERSION_STRING                                                                    \
    MINIMOSQ_VERSION_STRINGIFY(MINIMOSQ_VERSION_MAJOR)                                             \
    "." MINIMOSQ_VERSION_STRINGIFY(MINIMOSQ_VERSION_MINOR) "." MINIMOSQ_VERSION_STRINGIFY(         \
        MINIMOSQ_VERSION_PATCH)

namespace minimosq {

inline constexpr int version_major = MINIMOSQ_VERSION_MAJOR;
inline constexpr int version_minor = MINIMOSQ_VERSION_MINOR;
inline constexpr int version_patch = MINIMOSQ_VERSION_PATCH;
inline constexpr const char* version_string = MINIMOSQ_VERSION_STRING;

}  // namespace minimosq

#endif  // MINIMOSQ_VERSION_HPP
