#include "camera_firmware/common/Result.hpp"

#include <gtest/gtest.h>

using camera_firmware::common::Error;
using camera_firmware::common::Result;

TEST(ResultTest, CarriesValue) {
  auto result = Result<int>::Ok(7);
  ASSERT_TRUE(result.ok());
  EXPECT_EQ(result.value(), 7);
}

TEST(ResultTest, CarriesError) {
  auto result = Result<int>::Err({"E_TEST", "failure"});
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_TEST");
}
