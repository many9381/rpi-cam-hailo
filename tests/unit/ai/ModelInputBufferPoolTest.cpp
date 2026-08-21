#include "camera_firmware/ai/ModelInputBufferPool.hpp"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace {

using camera_firmware::ai::ModelInputBuffer;
using camera_firmware::ai::ModelInputBufferPool;

TEST(ModelInputBufferPoolTest, ReusesReleasedBuffersByIdentity) {
  auto pool = std::make_shared<ModelInputBufferPool>(3U);

  auto first = pool->Acquire();
  ASSERT_NE(first, nullptr);
  first->bytes.assign(64U, 1U);
  ModelInputBuffer* first_address = first.get();
  first.reset();  // released back to the pool, not freed

  auto second = pool->Acquire();
  ASSERT_NE(second, nullptr);
  EXPECT_EQ(second.get(), first_address);
  EXPECT_EQ(second->bytes.size(), 64U);  // storage survives recycling
}

TEST(ModelInputBufferPoolTest, HandsOutDistinctBuffersWhileHeld) {
  auto pool = std::make_shared<ModelInputBufferPool>(3U);

  auto first = pool->Acquire();
  auto second = pool->Acquire();
  ASSERT_NE(first, nullptr);
  ASSERT_NE(second, nullptr);
  EXPECT_NE(first.get(), second.get());
}

TEST(ModelInputBufferPoolTest, BoundsRetainedBuffersAtCapacity) {
  auto pool = std::make_shared<ModelInputBufferPool>(1U);

  auto first = pool->Acquire();
  auto second = pool->Acquire();
  ModelInputBuffer* first_address = first.get();
  first.reset();   // fills the single retained slot
  second.reset();  // beyond capacity -- freed, not retained

  auto reused = pool->Acquire();
  auto fresh = pool->Acquire();
  EXPECT_EQ(reused.get(), first_address);
  EXPECT_NE(fresh.get(), first_address);
}

TEST(ModelInputBufferPoolTest, OutstandingBuffersSurviveThePool) {
  std::shared_ptr<ModelInputBuffer> survivor;
  {
    auto pool = std::make_shared<ModelInputBufferPool>(2U);
    survivor = pool->Acquire();
    survivor->bytes.assign(16U, 7U);
  }
  // The pool is gone; releasing the buffer now must plainly free it
  // without touching pool state (no crash, no leak under ASan).
  ASSERT_NE(survivor, nullptr);
  EXPECT_EQ(survivor->bytes[0], 7U);
  survivor.reset();
}

}  // namespace
