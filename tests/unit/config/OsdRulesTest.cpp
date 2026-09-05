#include "camera_firmware/config/OsdRules.hpp"

#include <string>

#include <gtest/gtest.h>

namespace {

using camera_firmware::config::IsAllowedOsdPosition;
using camera_firmware::config::IsAllowedOsdType;
using camera_firmware::config::IsPrintableOsdText;
using camera_firmware::config::IsValidOsdItem;
using camera_firmware::config::kMaxOsdItems;
using camera_firmware::config::kMaxOsdTextBytes;

TEST(OsdRulesTest, PublishesTheContractBounds) {
  EXPECT_EQ(kMaxOsdItems, 8U);
  EXPECT_EQ(kMaxOsdTextBytes, 64U);
}

TEST(OsdRulesTest, AcceptsExactlyTheThreeTypesAndFourPositions) {
  for (const char* type : {"timestamp", "camera_name", "custom_text"}) {
    EXPECT_TRUE(IsAllowedOsdType(type)) << type;
  }
  EXPECT_FALSE(IsAllowedOsdType("clock"));
  EXPECT_FALSE(IsAllowedOsdType(""));
  for (const char* position :
       {"top_left", "top_right", "bottom_left", "bottom_right"}) {
    EXPECT_TRUE(IsAllowedOsdPosition(position)) << position;
  }
  EXPECT_FALSE(IsAllowedOsdPosition("center"));
}

TEST(OsdRulesTest, PrintableTextIsBoundedInUtf8BytesAndFreeOfControlCharacters) {
  EXPECT_TRUE(IsPrintableOsdText(""));
  EXPECT_TRUE(IsPrintableOsdText(std::string(64, 'x')));
  EXPECT_FALSE(IsPrintableOsdText(std::string(65, 'x')));
  // 21 Hangul syllables = 63 bytes, 22 = 66 bytes.
  std::string hangul21;
  for (int i = 0; i < 21; ++i) hangul21 += "\xea\xb0\x80";  // 가
  EXPECT_TRUE(IsPrintableOsdText(hangul21));
  EXPECT_FALSE(IsPrintableOsdText(hangul21 + "\xea\xb0\x80"));
  EXPECT_FALSE(IsPrintableOsdText("a\tb"));
  EXPECT_FALSE(IsPrintableOsdText(std::string("a\x7f")));
}

TEST(OsdRulesTest, ValidItemRequiresNonEmptyCustomTextOnly) {
  EXPECT_TRUE(IsValidOsdItem("timestamp", "", "top_left"));
  EXPECT_TRUE(IsValidOsdItem("camera_name", "", "bottom_right"));
  EXPECT_TRUE(IsValidOsdItem("custom_text", "Front door", "top_right"));
  EXPECT_FALSE(IsValidOsdItem("custom_text", "", "top_right"));
  EXPECT_FALSE(IsValidOsdItem("clock", "x", "top_left"));
  EXPECT_FALSE(IsValidOsdItem("custom_text", "x", "middle"));
  EXPECT_FALSE(IsValidOsdItem("custom_text", "a\nb", "top_left"));
}

}  // namespace
