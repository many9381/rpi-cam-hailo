#include "camera_firmware/service/ServiceStartup.hpp"
#include "camera_firmware/service/ServiceApp.hpp"

#include <chrono>
#include <future>
#include <thread>

#include <gtest/gtest.h>

TEST(ServiceStartupSignalTest, WaitReturnsReadyFromRunThread) {
  camera_firmware::service::ServiceStartupSignal signal;

  std::thread run_thread([&signal] { signal.ReportReady(); });

  auto startup = signal.Wait();

  run_thread.join();
  EXPECT_TRUE(startup.ok());
}

TEST(ServiceStartupSignalTest, WaitReturnsStartupErrorFromRunThread) {
  camera_firmware::service::ServiceStartupSignal signal;

  std::thread run_thread([&signal] {
    signal.ReportError({"E_SERVICE_START", "listener failed"});
  });

  auto startup = signal.Wait();

  run_thread.join();
  ASSERT_FALSE(startup.ok());
  EXPECT_EQ(startup.error().code, "E_SERVICE_START");
  EXPECT_EQ(startup.error().message, "listener failed");
}

TEST(ServiceStartupSignalTest, WaitReturnsStartupErrorOnTimeout) {
  camera_firmware::service::ServiceStartupSignal signal;

  auto startup = signal.Wait(std::chrono::milliseconds(1));

  ASSERT_FALSE(startup.ok());
  EXPECT_EQ(startup.error().code, "E_SERVICE_START");
  EXPECT_NE(startup.error().message.find("timed out"), std::string::npos);
}

TEST(ServiceStartupSignalTest, TimeoutRemainsTerminalAfterLateReady) {
  camera_firmware::service::ServiceStartupSignal signal;

  auto first_wait = signal.Wait(std::chrono::milliseconds(1));

  ASSERT_FALSE(first_wait.ok());
  EXPECT_EQ(first_wait.error().code, "E_SERVICE_START");
  EXPECT_NE(first_wait.error().message.find("timed out"), std::string::npos);

  signal.ReportReady();

  auto second_wait = signal.Wait(std::chrono::milliseconds(1));

  ASSERT_FALSE(second_wait.ok());
  EXPECT_EQ(second_wait.error().code, "E_SERVICE_START");
  EXPECT_NE(second_wait.error().message.find("timed out"), std::string::npos);
}

TEST(ServiceStartupSignalTest, CleanupJoinsCompletedServiceThread) {
  auto completion = std::make_shared<std::promise<void>>();
  auto completion_future = completion->get_future().share();
  std::thread service_thread([completion] { completion->set_value(); });
  bool stop_requested = false;

  auto stopped = camera_firmware::service::internal::StopServiceThreadWithin(
      service_thread,
      completion_future,
      std::chrono::seconds(1),
      [&stop_requested] { stop_requested = true; });

  ASSERT_TRUE(stopped.ok()) << stopped.error().message;
  EXPECT_TRUE(stop_requested);
  EXPECT_FALSE(service_thread.joinable());
}

TEST(ServiceStartupSignalTest, CleanupTimesOutWithoutUnboundedJoin) {
  auto completion = std::make_shared<std::promise<void>>();
  auto completion_future = completion->get_future().share();
  auto release = std::make_shared<std::promise<void>>();
  auto release_future = release->get_future().share();
  std::thread service_thread([completion, release_future] {
    release_future.wait();
    completion->set_value();
  });
  bool stop_requested = false;

  const auto start = std::chrono::steady_clock::now();
  auto stopped = camera_firmware::service::internal::StopServiceThreadWithin(
      service_thread,
      completion_future,
      std::chrono::milliseconds(10),
      [&stop_requested] { stop_requested = true; });
  const auto elapsed = std::chrono::steady_clock::now() - start;

  release->set_value();
  ASSERT_FALSE(stopped.ok());
  EXPECT_EQ(stopped.error().code, "E_SERVICE_THREAD_STOP_TIMEOUT");
  EXPECT_NE(stopped.error().message.find("service thread stop timed out"),
            std::string::npos);
  EXPECT_TRUE(stop_requested);
  EXPECT_FALSE(service_thread.joinable());
  EXPECT_LT(elapsed, std::chrono::milliseconds(500));
}
