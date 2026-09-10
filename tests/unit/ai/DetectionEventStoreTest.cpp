#include "camera_firmware/ai/DetectionEventStore.hpp"

#include "camera_firmware/ai/DetectionBus.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <utility>

#include <gtest/gtest.h>

namespace {

camera_firmware::ai::DetectionEvent Event(std::string camera_id,
                                          std::string model_id,
                                          std::uint64_t sequence,
                                          std::string label = "person") {
  camera_firmware::ai::DetectionEvent event;
  event.camera_id = std::move(camera_id);
  event.model_id = std::move(model_id);
  event.model_kind = "object_detection";
  event.result_state = "decoded";
  event.frame_sequence = sequence;

  camera_firmware::ai::Detection detection;
  detection.label = std::move(label);
  detection.confidence = 0.75F;
  detection.box.x = 0.10F;
  detection.box.y = 0.20F;
  detection.box.width = 0.30F;
  detection.box.height = 0.40F;
  event.detections.push_back(std::move(detection));
  return event;
}

}  // namespace

TEST(DetectionEventStoreTest, StoresLatestEventPerCameraAndModel) {
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::DetectionEventStore store(bus);

  bus.Publish(Event("imx708-main", "objects", 1, "person"));
  bus.Publish(Event("imx708-main", "objects", 2, "car"));

  const auto snapshot = store.Snapshot();

  ASSERT_EQ(snapshot.size(), 1U);
  EXPECT_EQ(snapshot[0].camera_id, "imx708-main");
  EXPECT_EQ(snapshot[0].model_id, "objects");
  EXPECT_EQ(snapshot[0].frame_sequence, 2U);
  ASSERT_EQ(snapshot[0].detections.size(), 1U);
  EXPECT_EQ(snapshot[0].detections[0].label, "car");
}

TEST(DetectionEventStoreTest, KeepsDistinctCameraModelEvents) {
  camera_firmware::ai::DetectionBus bus;
  camera_firmware::ai::DetectionEventStore store(bus);

  bus.Publish(Event("imx708-main", "objects", 1, "person"));
  bus.Publish(Event("imx708-main", "pose", 2, "keypoint"));
  bus.Publish(Event("imx219-wide", "objects", 3, "car"));

  const auto snapshot = store.Snapshot();

  ASSERT_EQ(snapshot.size(), 3U);
  EXPECT_EQ(snapshot[0].camera_id, "imx708-main");
  EXPECT_EQ(snapshot[0].model_id, "objects");
  EXPECT_EQ(snapshot[1].camera_id, "imx708-main");
  EXPECT_EQ(snapshot[1].model_id, "pose");
  EXPECT_EQ(snapshot[2].camera_id, "imx219-wide");
  EXPECT_EQ(snapshot[2].model_id, "objects");
}

TEST(DetectionEventStoreTest,
     SnapshotProviderReturnsEmptyAfterStoreDestruction) {
  camera_firmware::ai::DetectionBus bus;
  std::function<std::vector<camera_firmware::ai::DetectionEvent>()> provider;
  {
    camera_firmware::ai::DetectionEventStore store(bus);
    provider = store.SnapshotProvider();
    bus.Publish(Event("imx708-main", "objects", 1, "person"));
    ASSERT_EQ(provider().size(), 1U);
  }

  bus.Publish(Event("imx708-main", "objects", 2, "car"));

  ASSERT_TRUE(provider);
  EXPECT_TRUE(provider().empty());
}
