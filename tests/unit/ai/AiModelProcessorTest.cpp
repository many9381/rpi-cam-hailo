#include "camera_firmware/ai/AiModelProcessor.hpp"

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

// Adapter for the canvas-based Preprocess signature: most tests only care
// about the produced bytes, not the recycling contract.
camera_firmware::common::Result<camera_firmware::ai::ModelInputBuffer>
PreprocessToBuffer(camera_firmware::ai::AiModelProcessor& processor,
                   const camera_firmware::media::FrameLease& lease) {
  camera_firmware::ai::ModelInputBuffer canvas;
  auto converted = processor.Preprocess(lease, canvas);
  if (!converted.ok()) {
    return camera_firmware::common::Result<
        camera_firmware::ai::ModelInputBuffer>::Err(converted.error());
  }
  return camera_firmware::common::Result<
      camera_firmware::ai::ModelInputBuffer>::Ok(std::move(canvas));
}


camera_firmware::config::AiModelConfig ProcessorModel(std::string id,
                                                      std::string kind) {
  camera_firmware::config::AiModelConfig model;
  model.id = std::move(id);
  model.kind = std::move(kind);
  model.hef_path = "/opt/cf/models/" + model.id + ".hef";
  model.input.width = 4;
  model.input.height = 2;
  model.input.format = "rgb8";
  return model;
}

int CreateAnonymousFile(const std::vector<std::uint8_t>& bytes) {
  std::array<char, 32> path{"/tmp/cf-ai-nv12-XXXXXX"};
  int fd = ::mkstemp(path.data());
  if (fd < 0) {
    return -1;
  }
  (void)::unlink(path.data());
  if (::ftruncate(fd, static_cast<off_t>(bytes.size())) != 0) {
    (void)::close(fd);
    return -1;
  }
  if (::write(fd, bytes.data(), bytes.size()) !=
      static_cast<ssize_t>(bytes.size())) {
    (void)::close(fd);
    return -1;
  }
  return fd;
}

camera_firmware::media::FrameLease Nv12Lease(
    std::uint64_t sequence = 1,
    std::vector<std::uint8_t> y_plane =
        std::vector<std::uint8_t>(8U * 4U, 16U),
    std::vector<std::uint8_t> uv_plane =
        std::vector<std::uint8_t>(8U * 2U, 128U)) {
  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 8;
  handle.height = 4;
  handle.sequence = sequence;
  handle.plane_count = 2;
  handle.planes[0].stride = 8;
  handle.planes[0].length = 32;
  handle.planes[0].offset = 0;
  handle.planes[1].stride = 8;
  handle.planes[1].length = 16;
  handle.planes[1].offset = handle.planes[0].length;

  std::vector<std::uint8_t> bytes;
  bytes.reserve(y_plane.size() + uv_plane.size());
  bytes.insert(bytes.end(), y_plane.begin(), y_plane.end());
  bytes.insert(bytes.end(), uv_plane.begin(), uv_plane.end());
  const int fd = CreateAnonymousFile(bytes);
  handle.planes[0].dmabuf_fd = fd;
  handle.planes[1].dmabuf_fd = fd;

  return camera_firmware::media::FrameLease(handle, [fd] {
    if (fd >= 0) {
      (void)::close(fd);
    }
  });
}

camera_firmware::media::FrameHandle SourceFrame(std::uint64_t sequence,
                                                std::uint32_t width = 8,
                                                std::uint32_t height = 4) {
  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = width;
  handle.height = height;
  handle.sequence = sequence;
  return handle;
}

std::vector<std::uint8_t> YoloNmsOutputBytes(float confidence,
                                            float y_min = 0.25F,
                                            float x_min = 0.10F,
                                            float y_max = 0.75F,
                                            float x_max = 0.60F) {
  constexpr int kClassCount = 80;
  constexpr int kMaxBoxesPerClass = 100;
  constexpr int kValuesPerClass = 1 + (kMaxBoxesPerClass * 5);

  std::vector<float> tensor(kClassCount * kValuesPerClass, 0.0F);
  std::size_t offset = 0U;
  for (int class_index = 0; class_index < kClassCount; ++class_index) {
    if (class_index != 2) {
      tensor[offset++] = 0.0F;
      continue;
    }

    tensor[offset++] = 1.0F;
    tensor[offset++] = y_min;
    tensor[offset++] = x_min;
    tensor[offset++] = y_max;
    tensor[offset++] = x_max;
    tensor[offset++] = confidence;
  }

  std::vector<std::uint8_t> bytes(tensor.size() * sizeof(float));
  std::memcpy(bytes.data(), tensor.data(), bytes.size());
  return bytes;
}

std::vector<std::uint8_t> YoloPoseOutputBytes(
    float confidence = 0.92F,
    float x_min = 0.10F,
    float y_min = 0.25F,
    float x_max = 0.60F,
    float y_max = 0.75F,
    float nose_y = 0.25F) {
  constexpr std::size_t kPoseRowFloats = 5U + (17U * 3U);
  std::vector<float> tensor(kPoseRowFloats, 0.0F);
  tensor[0] = x_min;
  tensor[1] = y_min;
  tensor[2] = x_max;
  tensor[3] = y_max;
  tensor[4] = confidence;
  tensor[5] = 0.45F;
  tensor[6] = nose_y;
  tensor[7] = 0.95F;
  const std::size_t left_shoulder = 5U + (5U * 3U);
  tensor[left_shoulder] = 0.34F;
  tensor[left_shoulder + 1U] = 0.52F;
  tensor[left_shoulder + 2U] = 0.81F;

  std::vector<std::uint8_t> bytes(tensor.size() * sizeof(float));
  std::memcpy(bytes.data(), tensor.data(), bytes.size());
  return bytes;
}

}  // namespace

TEST(AiModelProcessorTest, CreatesObjectDetectionAndPoseProcessors) {
  auto detection = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("objects", "object_detection"));
  auto pose = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("pose", "pose"));

  ASSERT_TRUE(detection.ok()) << detection.error().message;
  ASSERT_TRUE(pose.ok()) << pose.error().message;
  EXPECT_EQ(detection.value()->model_id(), "objects");
  EXPECT_EQ(detection.value()->model_kind(), "object_detection");
  EXPECT_EQ(pose.value()->model_id(), "pose");
  EXPECT_EQ(pose.value()->model_kind(), "pose");
}

TEST(AiModelProcessorTest, PreprocessBuildsRgb8InputSizedForModel) {
  auto processor = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("objects", "object_detection"));
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  auto input = PreprocessToBuffer(*processor.value(), Nv12Lease());

  ASSERT_TRUE(input.ok()) << input.error().message;
  EXPECT_EQ(input.value().bytes.size(), 4U * 2U * 3U);
  EXPECT_EQ(input.value().view().data, input.value().bytes.data());
  EXPECT_EQ(input.value().view().size, input.value().bytes.size());
}

TEST(AiModelProcessorTest, PreprocessMapsNv12PlanesWithBilinearRgbResize) {
  auto model = ProcessorModel("objects", "object_detection");
  model.input.width = 2;
  model.input.height = 2;
  auto processor = camera_firmware::ai::CreateAiModelProcessor(model);
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  std::vector<std::uint8_t> y_plane = {
      16, 16, 16, 16, 235, 235, 235, 235,
      16, 16, 16, 16, 235, 235, 235, 235,
      16, 16, 16, 16, 235, 235, 235, 235,
      16, 16, 16, 16, 235, 235, 235, 235,
  };
  std::vector<std::uint8_t> uv_plane(8U * 2U, 128U);

  auto input = PreprocessToBuffer(*processor.value(), 
      Nv12Lease(4, std::move(y_plane), std::move(uv_plane)));

  ASSERT_TRUE(input.ok()) << input.error().message;
  const std::vector<std::uint8_t> expected = {
      34, 34, 34, 228, 228, 228,
      114, 114, 114, 114, 114, 114,
  };
  EXPECT_EQ(input.value().bytes, expected);
}

TEST(AiModelProcessorTest, PreprocessRejectsNonNv12Frame) {
  auto processor = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("objects", "object_detection"));
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "RGB";
  handle.width = 8;
  handle.height = 4;
  handle.sequence = 2;

  auto input = PreprocessToBuffer(*processor.value(), 
      camera_firmware::media::FrameLease(handle, [] {}));

  ASSERT_FALSE(input.ok());
  EXPECT_EQ(input.error().code, "E_AI_PREPROCESS");
}

TEST(AiModelProcessorTest, PreprocessRejectsInvalidPlaneFd) {
  auto processor = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("objects", "object_detection"));
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  auto lease = Nv12Lease(5);
  camera_firmware::media::FrameHandle handle = lease.handle();
  handle.planes[0].dmabuf_fd = -1;
  handle.planes[1].dmabuf_fd = -1;

  auto input = PreprocessToBuffer(*processor.value(), 
      camera_firmware::media::FrameLease(handle, [] {}));

  ASSERT_FALSE(input.ok());
  EXPECT_EQ(input.error().code, "E_AI_PREPROCESS");
}

TEST(AiModelProcessorTest, PreprocessRejectsOddNv12Dimensions) {
  auto model = ProcessorModel("objects", "object_detection");
  model.input.width = 5;
  model.input.height = 4;
  auto processor = camera_firmware::ai::CreateAiModelProcessor(model);
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  std::vector<std::uint8_t> bytes;
  bytes.insert(bytes.end(), 5U * 4U, 16U);
  bytes.insert(bytes.end(), 5U * 2U, 128U);
  const int fd = CreateAnonymousFile(bytes);

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 5;
  handle.height = 4;
  handle.sequence = 6;
  handle.plane_count = 2;
  handle.planes[0].dmabuf_fd = fd;
  handle.planes[0].stride = 5;
  handle.planes[0].length = 20;
  handle.planes[0].offset = 0;
  handle.planes[1].dmabuf_fd = fd;
  handle.planes[1].stride = 5;
  handle.planes[1].length = 10;
  handle.planes[1].offset = handle.planes[0].length;

  auto input = PreprocessToBuffer(*processor.value(), 
      camera_firmware::media::FrameLease(handle, [fd] {
        if (fd >= 0) {
          (void)::close(fd);
        }
      }));

  ASSERT_FALSE(input.ok());
  EXPECT_EQ(input.error().code, "E_AI_PREPROCESS");
}

TEST(AiModelProcessorTest, PreprocessRejectsPlaneOffsetLengthOverflow) {
  auto processor = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("objects", "object_detection"));
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  auto lease = Nv12Lease(7);
  camera_firmware::media::FrameHandle handle = lease.handle();
  handle.planes[0].offset = std::numeric_limits<std::size_t>::max();

  auto input = PreprocessToBuffer(*processor.value(), 
      camera_firmware::media::FrameLease(handle, [] {}));

  ASSERT_FALSE(input.ok());
  EXPECT_EQ(input.error().code, "E_AI_PREPROCESS");
}

TEST(AiModelProcessorTest, PreprocessRejectsPlaneRangeBeyondBackingFile) {
  auto processor = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("objects", "object_detection"));
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  std::vector<std::uint8_t> bytes(8U * 4U, 16U);
  const int fd = CreateAnonymousFile(bytes);

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 8;
  handle.height = 4;
  handle.sequence = 8;
  handle.plane_count = 2;
  handle.planes[0].dmabuf_fd = fd;
  handle.planes[0].stride = 8;
  handle.planes[0].length = 32;
  handle.planes[0].offset = 0;
  handle.planes[1].dmabuf_fd = fd;
  handle.planes[1].stride = 8;
  handle.planes[1].length = 16;
  handle.planes[1].offset = handle.planes[0].length;

  auto input = PreprocessToBuffer(*processor.value(), 
      camera_firmware::media::FrameLease(handle, [fd] {
        if (fd >= 0) {
          (void)::close(fd);
        }
      }));

  ASSERT_FALSE(input.ok());
  EXPECT_EQ(input.error().code, "E_AI_PREPROCESS");
}

TEST(AiModelProcessorTest, PreprocessRejectsOversizedModelInput) {
  auto model = ProcessorModel("objects", "object_detection");
  model.input.width = std::numeric_limits<unsigned int>::max();
  model.input.height = std::numeric_limits<unsigned int>::max();
  auto processor = camera_firmware::ai::CreateAiModelProcessor(model);
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  auto input = PreprocessToBuffer(*processor.value(), Nv12Lease(9));

  ASSERT_FALSE(input.ok());
  EXPECT_EQ(input.error().code, "E_AI_PREPROCESS");
}

TEST(AiModelProcessorTest, PreprocessRejectsShortNv12Planes) {
  auto processor = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("objects", "object_detection"));
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  camera_firmware::media::FrameHandle handle;
  handle.camera_id = "imx708-main";
  handle.format = "NV12";
  handle.width = 8;
  handle.height = 4;
  handle.sequence = 3;
  handle.plane_count = 2;
  handle.planes[0].stride = 8;
  handle.planes[0].length = 31;
  handle.planes[1].stride = 8;
  handle.planes[1].length = 16;

  auto input = PreprocessToBuffer(*processor.value(), 
      camera_firmware::media::FrameLease(handle, [] {}));

  ASSERT_FALSE(input.ok());
  EXPECT_EQ(input.error().code, "E_AI_PREPROCESS");
}

TEST(AiModelProcessorTest, PostprocessPublishesDecodedYoloDetections) {
  auto model = ProcessorModel("objects", "object_detection");
  model.confidence_threshold = 0.50F;
  auto processor = camera_firmware::ai::CreateAiModelProcessor(model);
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  camera_firmware::ai::DetectionBus bus;
  std::vector<camera_firmware::ai::DetectionEvent> events;
  auto subscription = bus.Subscribe(
      [&events](const camera_firmware::ai::DetectionEvent& event) {
        events.push_back(event);
      });
  auto bytes = YoloNmsOutputBytes(0.91F);
  camera_firmware::ai::OutputView output{bytes.data(), bytes.size()};

  processor.value()->Postprocess(
      camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
          output),
      SourceFrame(22),
      bus.PublisherHandle());

  ASSERT_EQ(events.size(), 1U);
  EXPECT_EQ(events[0].camera_id, "imx708-main");
  EXPECT_EQ(events[0].model_id, "objects");
  EXPECT_EQ(events[0].model_kind, "object_detection");
  EXPECT_EQ(events[0].result_state, "decoded");
  EXPECT_EQ(events[0].frame_sequence, 22U);
  ASSERT_EQ(events[0].detections.size(), 1U);
  EXPECT_EQ(events[0].detections[0].class_id, 2);
  EXPECT_EQ(events[0].detections[0].label, "car");
  EXPECT_FLOAT_EQ(events[0].detections[0].confidence, 0.91F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.x, 0.10F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.y, 0.25F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.width, 0.50F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.height, 0.50F);
  EXPECT_TRUE(subscription.valid());
}

TEST(AiModelProcessorTest, PostprocessMapsLetterboxYoloBoxesToSourceFrame) {
  auto model = ProcessorModel("objects", "object_detection");
  model.input.width = 4;
  model.input.height = 4;
  model.input.letterbox = true;
  model.confidence_threshold = 0.50F;
  auto processor = camera_firmware::ai::CreateAiModelProcessor(model);
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  camera_firmware::ai::DetectionBus bus;
  std::vector<camera_firmware::ai::DetectionEvent> events;
  auto subscription = bus.Subscribe(
      [&events](const camera_firmware::ai::DetectionEvent& event) {
        events.push_back(event);
      });
  auto bytes = YoloNmsOutputBytes(0.91F);
  camera_firmware::ai::OutputView output{bytes.data(), bytes.size()};

  processor.value()->Postprocess(
      camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
          output),
      SourceFrame(24),
      bus.PublisherHandle());

  ASSERT_EQ(events.size(), 1U);
  ASSERT_EQ(events[0].detections.size(), 1U);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.x, 0.10F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.y, 0.0F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.width, 0.50F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.height, 1.0F);
  EXPECT_TRUE(subscription.valid());
}

TEST(AiModelProcessorTest,
     PostprocessMapsLetterboxYoloBoxesUsingIntegerPreprocessGeometry) {
  auto model = ProcessorModel("objects", "object_detection");
  model.input.width = 4;
  model.input.height = 4;
  model.input.letterbox = true;
  model.confidence_threshold = 0.50F;
  auto processor = camera_firmware::ai::CreateAiModelProcessor(model);
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  camera_firmware::ai::DetectionBus bus;
  std::vector<camera_firmware::ai::DetectionEvent> events;
  auto subscription = bus.Subscribe(
      [&events](const camera_firmware::ai::DetectionEvent& event) {
        events.push_back(event);
      });
  auto bytes = YoloNmsOutputBytes(0.91F);
  camera_firmware::ai::OutputView output{bytes.data(), bytes.size()};

  processor.value()->Postprocess(
      camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
          output),
      SourceFrame(26, 10, 6),
      bus.PublisherHandle());

  ASSERT_EQ(events.size(), 1U);
  ASSERT_EQ(events[0].detections.size(), 1U);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.x, 0.10F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.y, 0.0F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.width, 0.50F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.height, 1.0F);
  EXPECT_TRUE(subscription.valid());
}

TEST(AiModelProcessorTest, PostprocessClampsLetterboxYoloBoxesToSourceFrame) {
  auto model = ProcessorModel("objects", "object_detection");
  model.input.width = 4;
  model.input.height = 4;
  model.input.letterbox = true;
  model.confidence_threshold = 0.50F;
  auto processor = camera_firmware::ai::CreateAiModelProcessor(model);
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  camera_firmware::ai::DetectionBus bus;
  std::vector<camera_firmware::ai::DetectionEvent> events;
  auto subscription = bus.Subscribe(
      [&events](const camera_firmware::ai::DetectionEvent& event) {
        events.push_back(event);
      });
  auto bytes = YoloNmsOutputBytes(0.91F, 0.0F, 0.0F, 1.0F, 1.0F);
  camera_firmware::ai::OutputView output{bytes.data(), bytes.size()};

  processor.value()->Postprocess(
      camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
          output),
      SourceFrame(27, 8, 4),
      bus.PublisherHandle());

  ASSERT_EQ(events.size(), 1U);
  ASSERT_EQ(events[0].detections.size(), 1U);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.x, 0.0F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.y, 0.0F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.width, 1.0F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.height, 1.0F);
  EXPECT_TRUE(subscription.valid());
}

TEST(AiModelProcessorTest, PostprocessPreservesDirectResizeYoloBoxes) {
  auto model = ProcessorModel("objects", "object_detection");
  model.input.width = 4;
  model.input.height = 4;
  model.input.letterbox = false;
  model.confidence_threshold = 0.50F;
  auto processor = camera_firmware::ai::CreateAiModelProcessor(model);
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  camera_firmware::ai::DetectionBus bus;
  std::vector<camera_firmware::ai::DetectionEvent> events;
  auto subscription = bus.Subscribe(
      [&events](const camera_firmware::ai::DetectionEvent& event) {
        events.push_back(event);
      });
  auto bytes = YoloNmsOutputBytes(0.91F);
  camera_firmware::ai::OutputView output{bytes.data(), bytes.size()};

  processor.value()->Postprocess(
      camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
          output),
      SourceFrame(25),
      bus.PublisherHandle());

  ASSERT_EQ(events.size(), 1U);
  ASSERT_EQ(events[0].detections.size(), 1U);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.x, 0.10F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.y, 0.25F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.width, 0.50F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.height, 0.50F);
  EXPECT_TRUE(subscription.valid());
}

TEST(AiModelProcessorTest, PostprocessPublishesDecodedPoseKeypoints) {
  auto model = ProcessorModel("pose", "pose");
  model.confidence_threshold = 0.50F;
  auto processor = camera_firmware::ai::CreateAiModelProcessor(model);
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  camera_firmware::ai::DetectionBus bus;
  std::vector<camera_firmware::ai::DetectionEvent> events;
  auto subscription = bus.Subscribe(
      [&events](const camera_firmware::ai::DetectionEvent& event) {
        events.push_back(event);
      });
  auto bytes = YoloPoseOutputBytes();
  camera_firmware::ai::OutputView output{bytes.data(), bytes.size()};
  auto source_frame = SourceFrame(42);
  source_frame.timestamp = std::chrono::nanoseconds{123456};

  processor.value()->Postprocess(
      camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
          output),
      source_frame,
      bus.PublisherHandle());

  ASSERT_EQ(events.size(), 1U);
  EXPECT_EQ(events[0].camera_id, "imx708-main");
  EXPECT_EQ(events[0].model_id, "pose");
  EXPECT_EQ(events[0].model_kind, "pose");
  EXPECT_EQ(events[0].result_state, "decoded");
  EXPECT_EQ(events[0].frame_sequence, 42U);
  EXPECT_EQ(events[0].frame_timestamp, std::chrono::nanoseconds{123456});
  ASSERT_EQ(events[0].detections.size(), 1U);
  EXPECT_EQ(events[0].detections[0].class_id, 0);
  EXPECT_EQ(events[0].detections[0].label, "person");
  EXPECT_FLOAT_EQ(events[0].detections[0].confidence, 0.92F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.x, 0.10F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.y, 0.25F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.width, 0.50F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.height, 0.50F);
  ASSERT_EQ(events[0].detections[0].keypoints.size(), 2U);
  EXPECT_EQ(events[0].detections[0].keypoints[0].name, "nose");
  EXPECT_FLOAT_EQ(events[0].detections[0].keypoints[0].x, 0.45F);
  EXPECT_FLOAT_EQ(events[0].detections[0].keypoints[0].y, 0.25F);
  EXPECT_FLOAT_EQ(events[0].detections[0].keypoints[0].confidence, 0.95F);
  EXPECT_EQ(events[0].detections[0].keypoints[1].name, "left_shoulder");
  EXPECT_TRUE(subscription.valid());
}

TEST(AiModelProcessorTest, PostprocessMapsLetterboxPoseKeypointsToSourceFrame) {
  auto model = ProcessorModel("pose", "pose");
  model.input.width = 4;
  model.input.height = 4;
  model.input.letterbox = true;
  model.confidence_threshold = 0.50F;
  auto processor = camera_firmware::ai::CreateAiModelProcessor(model);
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  camera_firmware::ai::DetectionBus bus;
  std::vector<camera_firmware::ai::DetectionEvent> events;
  auto subscription = bus.Subscribe(
      [&events](const camera_firmware::ai::DetectionEvent& event) {
        events.push_back(event);
      });
  auto bytes = YoloPoseOutputBytes();
  camera_firmware::ai::OutputView output{bytes.data(), bytes.size()};

  processor.value()->Postprocess(
      camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
          output),
      SourceFrame(43, 8, 4),
      bus.PublisherHandle());

  ASSERT_EQ(events.size(), 1U);
  ASSERT_EQ(events[0].detections.size(), 1U);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.x, 0.10F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.y, 0.0F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.width, 0.50F);
  EXPECT_FLOAT_EQ(events[0].detections[0].box.height, 1.0F);
  ASSERT_EQ(events[0].detections[0].keypoints.size(), 2U);
  EXPECT_FLOAT_EQ(events[0].detections[0].keypoints[0].x, 0.45F);
  EXPECT_FLOAT_EQ(events[0].detections[0].keypoints[0].y, 0.0F);
  EXPECT_FLOAT_EQ(events[0].detections[0].keypoints[1].x, 0.34F);
  EXPECT_FLOAT_EQ(events[0].detections[0].keypoints[1].y, 0.54F);
  EXPECT_TRUE(subscription.valid());
}

TEST(AiModelProcessorTest, PostprocessRejectsUnalignedPoseOutputBytes) {
  auto processor = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("pose", "pose"));
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  std::vector<std::uint8_t> bytes(3U, 0U);
  camera_firmware::ai::OutputView output{bytes.data(), bytes.size()};
  camera_firmware::ai::DetectionBus bus;

  try {
    processor.value()->Postprocess(
        camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
            output),
        SourceFrame(44),
        bus.PublisherHandle());
    FAIL() << "Expected pose postprocess to reject unaligned bytes";
  } catch (const std::runtime_error& error) {
    const std::string message = error.what();
    EXPECT_NE(message.find("3 bytes"), std::string::npos) << message;
    EXPECT_NE(message.find("float aligned"), std::string::npos) << message;
  }
}

TEST(AiModelProcessorTest, PostprocessRejectsMalformedPoseOutputShape) {
  auto processor = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("pose", "pose"));
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  camera_firmware::ai::DetectionBus bus;
  std::vector<std::uint8_t> truncated(sizeof(float) * 3U, 0U);
  camera_firmware::ai::OutputView output{truncated.data(), truncated.size()};

  try {
    processor.value()->Postprocess(
        camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
            output),
        SourceFrame(45),
        bus.PublisherHandle());
    FAIL() << "Expected pose postprocess to reject malformed row shape";
  } catch (const std::runtime_error& error) {
    const std::string message = error.what();
    EXPECT_NE(message.find("3 floats"), std::string::npos) << message;
    EXPECT_NE(message.find("56-float"), std::string::npos) << message;
  }
}

TEST(AiModelProcessorTest, PostprocessRejectsUnalignedYoloOutputBytes) {
  auto processor = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("objects", "object_detection"));
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  std::vector<std::uint8_t> bytes(3U, 0U);
  camera_firmware::ai::OutputView output{bytes.data(), bytes.size()};
  camera_firmware::ai::DetectionBus bus;

  EXPECT_THROW(
      processor.value()->Postprocess(
          camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
              output),
          SourceFrame(23),
          bus.PublisherHandle()),
      std::runtime_error);
}

TEST(AiModelProcessorTest, PostprocessRejectsMalformedYoloOutputShape) {
  auto processor = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("objects", "object_detection"));
  ASSERT_TRUE(processor.ok()) << processor.error().message;

  camera_firmware::ai::DetectionBus bus;
  std::vector<std::uint8_t> truncated(sizeof(float) * 3U, 0U);
  camera_firmware::ai::OutputView truncated_output{truncated.data(),
                                                   truncated.size()};

  EXPECT_THROW(
      processor.value()->Postprocess(
          camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
              truncated_output),
          SourceFrame(24),
          bus.PublisherHandle()),
      std::runtime_error);

  auto oversized = YoloNmsOutputBytes(0.91F);
  oversized.insert(oversized.end(), sizeof(float), 0U);
  camera_firmware::ai::OutputView oversized_output{oversized.data(),
                                                   oversized.size()};

  EXPECT_THROW(
      processor.value()->Postprocess(
          camera_firmware::common::Result<camera_firmware::ai::OutputView>::Ok(
              oversized_output),
          SourceFrame(25),
          bus.PublisherHandle()),
      std::runtime_error);
}

TEST(AiModelProcessorTest, RejectsUnsupportedModelKind) {
  auto processor = camera_firmware::ai::CreateAiModelProcessor(
      ProcessorModel("custom", "segmentation"));

  ASSERT_FALSE(processor.ok());
  EXPECT_EQ(processor.error().code, "E_AI_MODEL_KIND");
}
