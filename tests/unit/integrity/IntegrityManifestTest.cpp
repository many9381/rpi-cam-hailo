#include "IntegrityTestSupport.hpp"

#include <string>

#include "camera_firmware/integrity/IntegrityManifest.hpp"
#include "IntegrityManifestTestAccess.hpp"

namespace camera_firmware::integrity {
namespace {

constexpr std::string_view kDigest =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

std::string ManifestWithFiles(std::string_view files) {
  return "schema_version: 1\n"
         "product: camera-firmware\n"
         "created_at: '2026-07-19T00:00:00Z'\n"
         "files:\n" +
         std::string(files);
}

TEST(IntegrityManifestTest, ParsesStrictManifestAndPreservesEntryOrder) {
  const auto result = ParseIntegrityManifest(ManifestWithFiles(
      "  - id: firmware-main\n"
      "    category: firmware\n"
      "    path: /opt/camera-firmware\n"
      "    sha256: " + std::string(kDigest) + "\n"
      "  - id: web-main\n"
      "    category: web_asset\n"
      "    path: /opt/web/main.js\n"
      "    sha256: " + std::string(kDigest) + "\n"));

  ASSERT_TRUE(result.ok());
  ASSERT_EQ(result.value().files.size(), 2U);
  EXPECT_EQ(result.value().files[0].id, "firmware-main");
  EXPECT_EQ(result.value().files[0].category, IntegrityCategory::kFirmware);
  EXPECT_EQ(result.value().files[1].id, "web-main");
  EXPECT_EQ(result.value().files[1].category, IntegrityCategory::kWebAsset);
}

TEST(IntegrityManifestTest, RejectsUnknownAndDuplicateKeys) {
  for (const std::string& yaml : {
           ManifestWithFiles("  - id: one\n    category: firmware\n    path: /one\n"
                             "    sha256: " + std::string(kDigest) +
                             "\n    extra: rejected\n"),
           std::string("schema_version: 1\nproduct: camera-firmware\n"
                       "product: camera-firmware\ncreated_at: '2026-07-19T00:00:00Z'\n"
                       "files: []\n"),
       }) {
    const auto result = ParseIntegrityManifest(yaml);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
  }
}

TEST(IntegrityManifestTest, RejectsInvalidScalarAndEntryConstraints) {
  const std::string entry = "  - id: item\n    category: firmware\n    path: /item\n"
                            "    sha256: " + std::string(kDigest) + "\n";
  for (const std::string& yaml : {
           ManifestWithFiles(""),
           ManifestWithFiles("  - id: item\n    category: unsupported\n    path: /item\n"
                             "    sha256: " + std::string(kDigest) + "\n"),
           ManifestWithFiles("  - id: item\n    category: firmware\n    path: relative\n"
                             "    sha256: " + std::string(kDigest) + "\n"),
           ManifestWithFiles("  - id: item\n    category: firmware\n    path: /one/../item\n"
                             "    sha256: " + std::string(kDigest) + "\n"),
           ManifestWithFiles("  - id: \\u00e9\n    category: firmware\n    path: /item\n"
                             "    sha256: " + std::string(kDigest) + "\n"),
           ManifestWithFiles("  - id: item\n    category: firmware\n    path: /item\n"
                             "    sha256: " + std::string(kDigest).substr(0, 63U) + "\n"),
           ManifestWithFiles("  - id: item\n    category: firmware\n    path: /item\n"
                             "    sha256: " + std::string(kDigest) + "\n"
                             "    sha256: " + std::string(kDigest) + "\n"),
           "schema_version: 2\nproduct: camera-firmware\n"
           "created_at: '2026-07-19T00:00:00Z'\nfiles:\n" + entry,
           "schema_version: 1\nproduct: another-product\n"
           "created_at: '2026-07-19T00:00:00Z'\nfiles:\n" + entry,
           "schema_version: 1\nproduct: camera-firmware\n"
           "created_at: '2026-02-29T00:00:00+00:00'\nfiles:\n" + entry,
           ManifestWithFiles(entry + entry),
       }) {
    const auto result = ParseIntegrityManifest(yaml);
    ASSERT_FALSE(result.ok()) << yaml;
    EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
  }
}

TEST(IntegrityManifestTest, RejectsExplicitYamlTags) {
  for (const std::string& schema : {"!!str 1", "! 1"}) {
    const auto result = ParseIntegrityManifest(
        "schema_version: " + schema +
        "\nproduct: camera-firmware\n"
        "created_at: '2026-07-19T00:00:00Z'\n"
        "files:\n"
        "  - id: firmware\n"
        "    category: firmware\n"
        "    path: /opt/camera-firmware\n"
        "    sha256: " +
        std::string(kDigest) + "\n");

    ASSERT_FALSE(result.ok()) << schema;
    EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
  }
}

TEST(IntegrityManifestTest, RejectsBareTagsAtEveryNodePosition) {
  const std::string header =
      "schema_version: 1\n"
      "product: camera-firmware\n"
      "created_at: '2026-07-19T00:00:00Z'\n";
  const std::string flow_entry =
      "{id: firmware, category: firmware, path: /opt/camera-firmware, "
      "sha256: " +
      std::string(kDigest) + "}";
  for (const std::string& yaml : {
           "schema_version: ! 1\n"
           "product: camera-firmware\n"
           "created_at: '2026-07-19T00:00:00Z'\n"
           "files: [" +
               flow_entry + "]\n",
           header + "files:\n  - ! " + flow_entry + "\n",
           header + "files: ! [" + flow_entry + "]\n",
       }) {
    EXPECT_FALSE(testing::RestrictedYamlPreflightAcceptsForTest(yaml));
    const auto result = ParseIntegrityManifest(yaml);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
  }
}

TEST(IntegrityManifestTest, RejectsBareTagsWithCommentsAndWhitespace) {
  const std::string files =
      "files:\n"
      "  - id: firmware\n"
      "    category: firmware\n"
      "    path: /opt/camera-firmware\n"
      "    sha256: " +
      std::string(kDigest) + "\n";
  for (const std::string& yaml : {
           "schema_version:    !    1 # explicit bare tag\n"
           "product: camera-firmware\n"
           "created_at: '2026-07-19T00:00:00Z'\n" +
               files,
           "schema_version:\n"
           "  # comment before the explicit tag\n"
           "  ! 1\n"
           "product: camera-firmware\n"
           "created_at: '2026-07-19T00:00:00Z'\n" +
               files,
       }) {
    EXPECT_FALSE(testing::RestrictedYamlPreflightAcceptsForTest(yaml));
    EXPECT_FALSE(ParseIntegrityManifest(yaml).ok());
  }
}

TEST(IntegrityManifestTest, RejectsBareTagsOnNullNodesDuringPreflight) {
  for (const std::string_view yaml : {
           "!\n",
           "! # explicit bare tag on null\n",
           "--- !\n",
       }) {
    EXPECT_FALSE(testing::RestrictedYamlPreflightAcceptsForTest(yaml)) << yaml;
  }
}

TEST(IntegrityManifestTest, AllowsImplicitQuotedScalarsAndBangInPaths) {
  for (const std::string& path : {
           std::string{"/opt/camera!firmware"},
           std::string{"'/opt/camera!firmware'"},
           std::string{"\"/opt/camera!firmware\""},
       }) {
    const std::string yaml =
        "schema_version: \"1\"\n"
        "product: 'camera-firmware'\n"
        "created_at: \"2026-07-19T00:00:00Z\"\n"
        "files:\n"
        "  - id: firmware\n"
        "    category: firmware\n"
        "    path: " +
        path +
        "\n"
        "    sha256: " +
        std::string(kDigest) + "\n";

    EXPECT_TRUE(testing::RestrictedYamlPreflightAcceptsForTest(yaml));
    EXPECT_TRUE(ParseIntegrityManifest(yaml).ok());
  }
}

TEST(IntegrityManifestTest, RejectsYamlAnchorsAndAliases) {
  for (const std::string& yaml : {
           "schema_version: &schema 1\n"
           "product: camera-firmware\n"
           "created_at: '2026-07-19T00:00:00Z'\n"
           "files:\n"
           "  - id: firmware\n"
           "    category: firmware\n"
           "    path: /opt/camera-firmware\n"
           "    sha256: " +
               std::string(kDigest) + "\n",
           ManifestWithFiles(
               "  - id: one\n"
               "    category: library\n"
               "    path: /lib/one\n"
               "    sha256: &digest " +
               std::string(kDigest) +
               "\n"
               "  - id: two\n"
               "    category: library\n"
               "    path: /lib/two\n"
               "    sha256: *digest\n"),
       }) {
    const auto result = ParseIntegrityManifest(yaml);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
  }
}

TEST(IntegrityManifestTest, RejectsEmptyAndIdsBeyondPublicResultBound) {
  for (const std::string& id : {std::string{}, std::string(65U, 'a')}) {
    const auto result = ParseIntegrityManifest(ManifestWithFiles(
        "  - id: '" + id +
        "'\n"
        "    category: library\n"
        "    path: /lib/item\n"
        "    sha256: " +
        std::string(kDigest) + "\n"));

    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
  }
}

TEST(IntegrityManifestTest, RejectsDuplicateIdsWithDistinctPaths) {
  const auto result = ParseIntegrityManifest(ManifestWithFiles(
      "  - id: duplicate\n"
      "    category: library\n"
      "    path: /lib/one\n"
      "    sha256: " +
      std::string(kDigest) +
      "\n"
      "  - id: duplicate\n"
      "    category: library\n"
      "    path: /lib/two\n"
      "    sha256: " +
      std::string(kDigest) + "\n"));

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
}

TEST(IntegrityManifestTest, RejectsDuplicatePathsWithDistinctIds) {
  const auto result = ParseIntegrityManifest(ManifestWithFiles(
      "  - id: one\n"
      "    category: library\n"
      "    path: /lib/duplicate\n"
      "    sha256: " +
      std::string(kDigest) +
      "\n"
      "  - id: two\n"
      "    category: library\n"
      "    path: /lib/duplicate\n"
      "    sha256: " +
      std::string(kDigest) + "\n"));

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
}

TEST(IntegrityManifestTest, RejectsEmbeddedNulAndOverlongEntryPaths) {
  const std::string overlong_path = "/" + std::string(4096U, 'a');
  for (const std::string& path : {std::string{"\"/lib/item\\0suffix\""},
                                  overlong_path}) {
    const auto result = ParseIntegrityManifest(ManifestWithFiles(
        "  - id: item\n"
        "    category: library\n"
        "    path: " +
        path +
        "\n"
        "    sha256: " +
        std::string(kDigest) + "\n"));

    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
  }
}

TEST(IntegrityManifestTest, RejectsPathologicalYamlWithinLimits) {
  std::string excessive_depth = "value: ";
  excessive_depth.append(64U, '[');
  excessive_depth += "0";
  excessive_depth.append(64U, ']');
  EXPECT_FALSE(
      testing::RestrictedYamlPreflightAcceptsForTest(excessive_depth));
  auto depth_result = ParseIntegrityManifest(excessive_depth);
  ASSERT_FALSE(depth_result.ok());
  EXPECT_EQ(depth_result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");

  std::string excessive_events = "values:\n";
  for (std::size_t index = 0U; index < 50000U; ++index) {
    excessive_events += "  - x\n";
  }
  EXPECT_FALSE(
      testing::RestrictedYamlPreflightAcceptsForTest(excessive_events));
  auto event_result = ParseIntegrityManifest(excessive_events);
  ASSERT_FALSE(event_result.ok());
  EXPECT_EQ(event_result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
}

TEST(IntegrityManifestTest, RejectsMoreThan4096Entries) {
  std::string files;
  for (std::size_t index = 0U; index < 4097U; ++index) {
    files += "  - id: item-" + std::to_string(index) + "\n"
             "    category: library\n"
             "    path: /lib/item-" + std::to_string(index) + "\n"
             "    sha256: " + std::string(kDigest) + "\n";
  }

  const auto result = ParseIntegrityManifest(ManifestWithFiles(files));

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
}

TEST(IntegrityManifestTest, Accepts4096EntriesWithinEventLimit) {
  std::string files;
  for (std::size_t index = 0U; index < 4096U; ++index) {
    files += "  - id: item-" + std::to_string(index) + "\n"
             "    category: library\n"
             "    path: /lib/item-" + std::to_string(index) + "\n"
             "    sha256: " + std::string(kDigest) + "\n";
  }

  const std::string yaml = ManifestWithFiles(files);
  EXPECT_TRUE(testing::RestrictedYamlPreflightAcceptsForTest(yaml));
  const auto result = ParseIntegrityManifest(yaml);

  ASSERT_TRUE(result.ok()) << result.error().message;
  EXPECT_EQ(result.value().files.size(), 4096U);
}

TEST(IntegrityManifestTest, RejectsMultipleDocumentsDuringPreflight) {
  const std::string document = ManifestWithFiles(
      "  - id: firmware\n"
      "    category: firmware\n"
      "    path: /opt/camera-firmware\n"
      "    sha256: " +
      std::string(kDigest) + "\n");
  const std::string multiple = document + "---\n" + document;

  EXPECT_FALSE(testing::RestrictedYamlPreflightAcceptsForTest(multiple));
  const auto result = ParseIntegrityManifest(multiple);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
}

TEST(IntegrityManifestTest, RejectsEmptyManifestEntryPath) {
  const auto result = ParseIntegrityManifest(ManifestWithFiles(
      "  - id: firmware\n"
      "    category: firmware\n"
      "    path: ''\n"
      "    sha256: " +
      std::string(kDigest) + "\n"));

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
}

TEST(IntegrityManifestTest, RejectsNonCanonicalPathSpellingAndOversizedInput) {
  const auto noncanonical = ParseIntegrityManifest(ManifestWithFiles(
      "  - id: firmware\n"
      "    category: firmware\n"
      "    path: /opt//camera-firmware\n"
      "    sha256: " + std::string(kDigest) + "\n"));
  ASSERT_FALSE(noncanonical.ok());
  EXPECT_EQ(noncanonical.error().code, "E_INTEGRITY_MANIFEST_FORMAT");

  const std::string oversized(1024U * 1024U + 1U, '#');
  const auto oversized_result = ParseIntegrityManifest(oversized);
  ASSERT_FALSE(oversized_result.ok());
  EXPECT_EQ(oversized_result.error().code, "E_INTEGRITY_MANIFEST_FORMAT");
}

TEST(IntegrityManifestTest, ConvertsEverySupportedCategory) {
  for (const auto [text, category] : {
           std::pair{"firmware", IntegrityCategory::kFirmware},
           {"library", IntegrityCategory::kLibrary},
           {"configuration", IntegrityCategory::kConfiguration},
           {"web_asset", IntegrityCategory::kWebAsset},
           {"kernel", IntegrityCategory::kKernel},
           {"kernel_module", IntegrityCategory::kKernelModule},
       }) {
    const auto parsed = ParseIntegrityCategory(text);
    ASSERT_TRUE(parsed.ok());
    EXPECT_EQ(parsed.value(), category);
    EXPECT_EQ(IntegrityCategoryName(category), text);
  }
}

}  // namespace
}  // namespace camera_firmware::integrity
