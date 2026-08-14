// Unit tests for topic validation and wildcard matching, following the
// examples in [MQTT-4.7].
// SPDX-License-Identifier: MIT
#include "test.hpp"

#include <minimosq/topic.hpp>

using namespace minimosq;

TEST(topic_name_validation) {
    CHECK(topic_name_valid("a"));
    CHECK(topic_name_valid("a/b/c"));
    CHECK(topic_name_valid("/"));       // two empty levels: allowed
    CHECK(topic_name_valid("a//b"));    // empty middle level: allowed
    CHECK(topic_name_valid("$SYS/x"));

    CHECK(!topic_name_valid(""));
    CHECK(!topic_name_valid("a/+/b"));  // wildcards forbidden in names
    CHECK(!topic_name_valid("a/#"));
    CHECK(!topic_name_valid(StrView("a\0b", 3)));  // embedded NUL
}

TEST(topic_filter_validation) {
    CHECK(topic_filter_valid("#"));
    CHECK(topic_filter_valid("+"));
    CHECK(topic_filter_valid("sport/#"));
    CHECK(topic_filter_valid("+/tennis/#"));
    CHECK(topic_filter_valid("sport/+/player1"));
    CHECK(topic_filter_valid("/"));

    CHECK(!topic_filter_valid(""));
    CHECK(!topic_filter_valid("sport/tennis#"));    // '#' must be a whole level
    CHECK(!topic_filter_valid("sport/#/ranking"));  // '#' must be last
    CHECK(!topic_filter_valid("sport+"));           // '+' must be a whole level
    CHECK(!topic_filter_valid("+sport"));
    CHECK(!topic_filter_valid("a/+b"));
    CHECK(!topic_filter_valid(StrView("a\0", 2)));
}

TEST(multi_level_wildcard_matching) {
    // Spec examples for "sport/tennis/player1/#".
    CHECK(topic_matches("sport/tennis/player1/#", "sport/tennis/player1"));
    CHECK(topic_matches("sport/tennis/player1/#", "sport/tennis/player1/ranking"));
    CHECK(topic_matches("sport/tennis/player1/#", "sport/tennis/player1/score/wimbledon"));
    CHECK(!topic_matches("sport/tennis/player1/#", "sport/tennis/player2"));

    CHECK(topic_matches("sport/#", "sport"));  // '#' includes the parent
    CHECK(topic_matches("#", "a"));
    CHECK(topic_matches("#", "a/b/c"));
    CHECK(topic_matches("sport/#", "sport/"));
}

TEST(single_level_wildcard_matching) {
    // Spec examples for "sport/tennis/+".
    CHECK(topic_matches("sport/tennis/+", "sport/tennis/player1"));
    CHECK(topic_matches("sport/tennis/+", "sport/tennis/player2"));
    CHECK(!topic_matches("sport/tennis/+", "sport/tennis/player1/ranking"));

    CHECK(topic_matches("sport/+", "sport/"));  // '+' matches an empty level
    CHECK(!topic_matches("sport/+", "sport"));
    CHECK(topic_matches("+/+", "/finance"));
    CHECK(topic_matches("/+", "/finance"));
    CHECK(!topic_matches("+", "/finance"));
    CHECK(topic_matches("+", "finance"));
}

TEST(exact_matching) {
    CHECK(topic_matches("a/b", "a/b"));
    CHECK(!topic_matches("a/b", "a/b/c"));
    CHECK(!topic_matches("a/b/c", "a/b"));
    CHECK(!topic_matches("a/b", "a/c"));
    CHECK(topic_matches("/", "/"));
    CHECK(topic_matches("a//b", "a//b"));
}

TEST(dollar_topics_not_matched_by_leading_wildcards) {
    CHECK(!topic_matches("#", "$SYS/broker/clients"));
    CHECK(!topic_matches("+/broker/clients", "$SYS/broker/clients"));
    CHECK(topic_matches("$SYS/#", "$SYS/broker/clients"));
    CHECK(topic_matches("$SYS/broker/+", "$SYS/broker/clients"));
    // '$' only special in the first level.
    CHECK(topic_matches("a/#", "a/$weird"));
}
