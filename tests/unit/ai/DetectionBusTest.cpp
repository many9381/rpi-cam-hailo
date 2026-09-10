#include "camera_firmware/ai/DetectionBus.hpp"

#include <memory>
#include <type_traits>

#include <gtest/gtest.h>

TEST(DetectionBusTest, PublishesToSubscribers) {
  camera_firmware::ai::DetectionBus bus;
  int seen = 0;
  auto sub = bus.Subscribe([&](const camera_firmware::ai::DetectionEvent& e) {
    seen += static_cast<int>(e.detections.size());
  });

  camera_firmware::ai::DetectionEvent event;
  event.camera_id = "imx708-main";
  event.detections.push_back({0, "person", 0.9f, {0.1f, 0.2f, 0.3f, 0.4f}});

  bus.Publish(event);

  EXPECT_EQ(seen, 1);
}

TEST(DetectionBusTest, IsNotCopyableOrMovable) {
  using Bus = camera_firmware::ai::DetectionBus;

  EXPECT_FALSE(std::is_copy_constructible_v<Bus>);
  EXPECT_FALSE(std::is_copy_assignable_v<Bus>);
  EXPECT_FALSE(std::is_move_constructible_v<Bus>);
  EXPECT_FALSE(std::is_move_assignable_v<Bus>);
}

TEST(DetectionBusTest, UnsubscribeStopsDelivery) {
  camera_firmware::ai::DetectionBus bus;
  int a = 0;
  int b = 0;

  auto sub_a =
      bus.Subscribe([&](const camera_firmware::ai::DetectionEvent&) { ++a; });
  {
    auto sub_b =
        bus.Subscribe([&](const camera_firmware::ai::DetectionEvent&) { ++b; });
    bus.Publish(camera_firmware::ai::DetectionEvent{});
  }

  bus.Publish(camera_firmware::ai::DetectionEvent{});

  EXPECT_EQ(a, 2);
  EXPECT_EQ(b, 1);
  EXPECT_TRUE(sub_a.valid());
}

TEST(DetectionBusTest, SubscriptionDropAfterBusDestructionIsSafe) {
  auto bus = std::make_unique<camera_firmware::ai::DetectionBus>();
  auto sub = bus->Subscribe([](const camera_firmware::ai::DetectionEvent&) {});

  bus.reset();

  EXPECT_FALSE(sub.valid());
}

TEST(DetectionBusTest, PublisherAfterBusDestructionIsSafeNoop) {
  auto bus = std::make_unique<camera_firmware::ai::DetectionBus>();
  auto publisher = bus->PublisherHandle();
  ASSERT_TRUE(publisher.valid());

  bus.reset();

  EXPECT_FALSE(publisher.valid());
  EXPECT_NO_THROW(publisher.Publish(camera_firmware::ai::DetectionEvent{}));
}
