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

TEST(filter_subsumption) {
    // cover covers filter: every topic the filter matches, the cover
    // matches too.
    CHECK(topic_filter_covers("#", "a/b"));
    CHECK(topic_filter_covers("#", "#"));
    CHECK(topic_filter_covers("#", "+/+"));
    CHECK(topic_filter_covers("home/#", "home/+/temp"));
    CHECK(topic_filter_covers("home/#", "home"));       // '#' covers the parent
    CHECK(topic_filter_covers("home/+", "home/kitchen"));
    CHECK(topic_filter_covers("+", "kitchen"));
    CHECK(topic_filter_covers("+/+", "home/+"));
    CHECK(topic_filter_covers("a/b/c", "a/b/c"));

    CHECK(!topic_filter_covers("home/+", "home/#"));    // '#' reaches deeper
    CHECK(!topic_filter_covers("home/kitchen", "home/+"));
    CHECK(!topic_filter_covers("home/#", "#"));
    CHECK(!topic_filter_covers("a/b", "a"));
    CHECK(!topic_filter_covers("a", "a/b"));
    CHECK(!topic_filter_covers("+", "#"));
    CHECK(!topic_filter_covers("a/#", "b/#"));

    // Wildcard covers never reach $-topics.
    CHECK(!topic_filter_covers("#", "$SYS/#"));
    CHECK(!topic_filter_covers("+/x", "$SYS/x"));
    CHECK(topic_filter_covers("$SYS/#", "$SYS/broker/+"));
}

TEST(utf8_validation) {
    CHECK(utf8_valid("plain ascii"));
    CHECK(utf8_valid("caf\xC3\xA9"));                  // é
    CHECK(utf8_valid("\xE2\x82\xAC"));                 // €
    CHECK(utf8_valid("\xF0\x9F\x99\x82"));             // U+1F642

    CHECK(!utf8_valid(StrView("a\0b", 3)));            // U+0000 forbidden
    CHECK(!utf8_valid("\xC3"));                        // truncated sequence
    CHECK(!utf8_valid("\x80"));                        // stray continuation
    CHECK(!utf8_valid("\xC0\xAF"));                    // overlong '/'
    CHECK(!utf8_valid("\xE0\x80\xAF"));                // overlong, 3 bytes
    CHECK(!utf8_valid("\xED\xA0\x80"));                // UTF-16 surrogate D800
    CHECK(!utf8_valid("\xF4\x90\x80\x80"));            // above U+10FFFF
    CHECK(!utf8_valid("\xFF\xFE"));                    // invalid lead bytes
}

TEST(ill_formed_utf8_invalidates_topics_and_filters) {
    CHECK(!topic_name_valid("\xFF\xFE"));
    CHECK(!topic_name_valid("a/\xC0\xAF"));
    CHECK(!topic_filter_valid("\xED\xA0\x80/#"));
    CHECK(topic_name_valid("caf\xC3\xA9/temp"));
    CHECK(topic_filter_valid("caf\xC3\xA9/+"));
}

TEST(dollar_topics_not_matched_by_leading_wildcards) {
    CHECK(!topic_matches("#", "$SYS/broker/clients"));
    CHECK(!topic_matches("+/broker/clients", "$SYS/broker/clients"));
    CHECK(topic_matches("$SYS/#", "$SYS/broker/clients"));
    CHECK(topic_matches("$SYS/broker/+", "$SYS/broker/clients"));
    // '$' only special in the first level.
    CHECK(topic_matches("a/#", "a/$weird"));
}
