#include "camera_firmware/ai/AlignedBufferPool.hpp"

#include <cstdint>
#include <memory>

#include <unistd.h>

#include <gtest/gtest.h>

namespace {

using camera_firmware::ai::AlignedBufferPool;
using camera_firmware::ai::PageAlignedBuffer;

std::size_t PageSize() {
  const long value = ::sysconf(_SC_PAGESIZE);
  return value > 0 ? static_cast<std::size_t>(value) : 4096U;
}

TEST(AlignedBufferPoolTest, AllocatesPageAlignedStorageOfRequestedSize) {
  auto pool = std::make_shared<AlignedBufferPool>(2U);
  auto buffer = pool->Acquire(1000U);
  ASSERT_NE(buffer, nullptr);
  EXPECT_EQ(buffer->size, 1000U);
  EXPECT_GE(buffer->allocated_size, 1000U);
  EXPECT_EQ(buffer->allocated_size % PageSize(), 0U);
  EXPECT_EQ(reinterpret_cast<std::uintptr_t>(buffer->data) % PageSize(), 0U);
}

TEST(AlignedBufferPoolTest, RejectsZeroSize) {
  auto pool = std::make_shared<AlignedBufferPool>(2U);
  EXPECT_EQ(pool->Acquire(0U), nullptr);
}

TEST(AlignedBufferPoolTest, ReusesReleasedBufferThatFits) {
  auto pool = std::make_shared<AlignedBufferPool>(2U);
  auto first = pool->Acquire(1000U);
  ASSERT_NE(first, nullptr);
  std::uint8_t* storage = first->data;
  first.reset();  // back to the pool

  // A smaller request must reuse the retained allocation, re-labeling its
  // requested size while keeping the same backing storage.
  auto second = pool->Acquire(500U);
  ASSERT_NE(second, nullptr);
  EXPECT_EQ(second->data, storage);
  EXPECT_EQ(second->size, 500U);
}

TEST(AlignedBufferPoolTest, AllocatesFreshWhenRetainedBufferIsTooSmall) {
  auto pool = std::make_shared<AlignedBufferPool>(2U);
  auto small = pool->Acquire(100U);
  ASSERT_NE(small, nullptr);
  const std::size_t small_allocated = small->allocated_size;
  std::uint8_t* small_storage = small->data;
  small.reset();

  auto large = pool->Acquire(small_allocated + PageSize());
  ASSERT_NE(large, nullptr);
  EXPECT_NE(large->data, small_storage);
  EXPECT_GE(large->allocated_size, small_allocated + PageSize());
}

TEST(AlignedBufferPoolTest, BoundsRetainedBuffers) {
  auto pool = std::make_shared<AlignedBufferPool>(1U);
  auto first = pool->Acquire(100U);
  auto second = pool->Acquire(100U);
  std::uint8_t* first_storage = first->data;
  first.reset();   // retained (fills the single slot)
  second.reset();  // over capacity -- freed outright

  // The retained buffer comes back by identity. The evicted one was freed;
  // its old address may legitimately be recycled by the allocator for the
  // second acquire, so only the retention half is address-assertable.
  auto reused = pool->Acquire(100U);
  auto fresh = pool->Acquire(100U);
  ASSERT_NE(reused, nullptr);
  ASSERT_NE(fresh, nullptr);
  EXPECT_EQ(reused->data, first_storage);
  EXPECT_NE(fresh->data, reused->data);
}

TEST(AlignedBufferPoolTest, OutstandingBuffersSurviveThePool) {
  std::shared_ptr<PageAlignedBuffer> survivor;
  {
    auto pool = std::make_shared<AlignedBufferPool>(2U);
    survivor = pool->Acquire(64U);
    ASSERT_NE(survivor, nullptr);
    survivor->data[0] = 9U;
  }
  EXPECT_EQ(survivor->data[0], 9U);
  survivor.reset();  // plain free, no pool left -- must not crash/leak
}

}  // namespace
