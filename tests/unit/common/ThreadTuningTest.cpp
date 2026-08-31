#include "camera_firmware/common/ThreadTuning.hpp"

#include <cerrno>
#include <string>
#include <thread>

#include <pthread.h>
#include <sys/resource.h>
#include <unistd.h>

#include <gtest/gtest.h>

using camera_firmware::common::DeprioritizeCurrentThread;
using camera_firmware::common::NameCurrentThread;

TEST(ThreadTuningTest, NameCurrentThreadSetsThreadName) {
  std::string observed_name;
  std::thread worker([&observed_name] {
    NameCurrentThread("tt-name");
    char buffer[16] = {};
    ASSERT_EQ(pthread_getname_np(pthread_self(), buffer, sizeof(buffer)), 0);
    observed_name = buffer;
  });
  worker.join();

  EXPECT_EQ(observed_name, "tt-name");
}

TEST(ThreadTuningTest, DeprioritizeCurrentThreadIncreasesNiceValue) {
  int prior = 0;
  int after = 0;
  bool succeeded = false;
  std::thread worker([&prior, &after, &succeeded] {
    errno = 0;
    prior = getpriority(PRIO_PROCESS, static_cast<id_t>(gettid()));
    ASSERT_EQ(errno, 0);

    succeeded = DeprioritizeCurrentThread(5);

    errno = 0;
    after = getpriority(PRIO_PROCESS, static_cast<id_t>(gettid()));
    ASSERT_EQ(errno, 0);
  });
  worker.join();

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(after, prior + 5);
}
