#include "camera_firmware/common/Result.hpp"

#include <utility>

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

TEST(ResultTest, CopiesAndMovesOwningErrors) {
  auto original = Result<int>::Err({"E_OWNED", "owned failure"});
  auto copied = original;
  auto moved = std::move(copied);

  ASSERT_FALSE(original.ok());
  ASSERT_FALSE(moved.ok());
  EXPECT_EQ(original.error().code, "E_OWNED");
  EXPECT_EQ(moved.error().message, "owned failure");
}

TEST(ResultTest, CarriesStaticLifetimeErrorWithoutOwningCopy) {
  static const Error kStaticError{"E_STATIC", "static failure"};
  static_assert(noexcept(Result<int>::ErrFromStaticLifetime(kStaticError)));

  auto original = Result<int>::ErrFromStaticLifetime(kStaticError);
  auto copied = original;
  auto moved = std::move(copied);

  ASSERT_FALSE(original.ok());
  ASSERT_FALSE(moved.ok());
  EXPECT_EQ(&original.error(), &kStaticError);
  EXPECT_EQ(&moved.error(), &kStaticError);
  EXPECT_EQ(moved.error().code, "E_STATIC");
}

TEST(ResultTest, VoidResultCarriesStaticLifetimeError) {
  static const Error kStaticError{"E_STATIC_VOID", "static void failure"};
  static_assert(noexcept(Result<void>::ErrFromStaticLifetime(kStaticError)));

  auto result = Result<void>::ErrFromStaticLifetime(kStaticError);
  auto copied = result;

  ASSERT_FALSE(result.ok());
  ASSERT_FALSE(copied.ok());
  EXPECT_EQ(&result.error(), &kStaticError);
  EXPECT_EQ(&copied.error(), &kStaticError);
}
