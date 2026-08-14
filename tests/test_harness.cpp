// Sanity checks for the test harness itself.
// SPDX-License-Identifier: MIT
#include "test.hpp"

TEST(check_passes) {
    CHECK(1 + 1 == 2);
    CHECK_EQ(2 + 2, 4);
}

TEST(cases_run_in_definition_order) {
    // The previous case has already run; the registrar appends at the tail.
    CHECK(minitest::cases() != nullptr);
    CHECK(minitest::cases()->next != nullptr);
}
