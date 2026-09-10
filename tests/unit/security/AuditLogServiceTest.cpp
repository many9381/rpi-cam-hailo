#include "camera_firmware/security/AuditLogService.hpp"

#include "AuditLogServiceTestAccess.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <sqlite3.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "camera_firmware/security/AuthService.hpp"
#include "camera_firmware/security/SecurityStore.hpp"
#include "camera_firmware/security/SecurityTypes.hpp"

void ConfigureSecurityStoreTransactionFailuresForTest(bool commit,
                                                      bool rollback);

namespace {

using camera_firmware::security::AuditEvent;
using camera_firmware::security::AuditEventPage;
using camera_firmware::security::AuditLogService;
using camera_firmware::security::AuditLogServiceTestAccess;
using camera_firmware::security::AuditQueryParameters;
using camera_firmware::security::Principal;
using camera_firmware::security::SecurityStore;
using camera_firmware::security::UserRole;

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    std::array<char, 44> pattern{"/tmp/cf-audit-log-service-XXXXXX"};
    char* created = ::mkdtemp(pattern.data());
    if (created == nullptr) {
      throw std::system_error(errno, std::generic_category(), "mkdtemp");
    }
    path_ = created;
  }

  ~TemporaryDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

  [[nodiscard]] std::filesystem::path StatePath() const {
    return path_ / "security";
  }

 private:
  std::filesystem::path path_;
};

class DatabaseConnection {
 public:
  explicit DatabaseConnection(const std::filesystem::path& path) {
    if (::sqlite3_open_v2(path.c_str(), &database_,
                          SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW,
                          nullptr) != SQLITE_OK) {
      throw std::runtime_error("sqlite3_open_v2 failed");
    }
  }

  ~DatabaseConnection() {
    if (database_ != nullptr) {
      (void)::sqlite3_close_v2(database_);
    }
  }

  DatabaseConnection(const DatabaseConnection&) = delete;
  DatabaseConnection& operator=(const DatabaseConnection&) = delete;

  [[nodiscard]] sqlite3* get() const noexcept { return database_; }

 private:
  sqlite3* database_{nullptr};
};

void ExecuteSql(const std::filesystem::path& path, const char* sql) {
  DatabaseConnection connection(path);
  char* error_message = nullptr;
  const int result =
      ::sqlite3_exec(connection.get(), sql, nullptr, nullptr, &error_message);
  if (error_message != nullptr) {
    ::sqlite3_free(error_message);
  }
  if (result != SQLITE_OK) {
    throw std::runtime_error("sqlite3_exec failed");
  }
}

std::vector<std::int64_t> QueryInt64Rows(const std::filesystem::path& path,
                                         const char* sql) {
  DatabaseConnection connection(path);
  sqlite3_stmt* statement = nullptr;
  if (::sqlite3_prepare_v2(connection.get(), sql, -1, &statement, nullptr) !=
      SQLITE_OK) {
    throw std::runtime_error("sqlite3_prepare_v2 failed");
  }
  std::vector<std::int64_t> values;
  int step = SQLITE_ROW;
  while ((step = ::sqlite3_step(statement)) == SQLITE_ROW) {
    values.push_back(::sqlite3_column_int64(statement, 0));
  }
  const int finalized = ::sqlite3_finalize(statement);
  if (step != SQLITE_DONE || finalized != SQLITE_OK) {
    throw std::runtime_error("sqlite3 query failed");
  }
  return values;
}

Principal Actor(UserRole role) {
  return {1, "operator.one", role, {}};
}

std::unique_ptr<SecurityStore> OpenStore(const std::filesystem::path& state,
                                         std::uint64_t max_events,
                                         std::uint32_t warning_percent) {
  auto opened = SecurityStore::Open({state, max_events, warning_percent});
  if (!opened.ok()) {
    throw std::runtime_error(opened.error().message);
  }
  return std::move(opened).value();
}

void InsertEvents(SecurityStore& store, std::int64_t first_timestamp,
                  std::size_t count) {
  for (std::size_t index = 0; index < count; ++index) {
    auto inserted = AuditLogServiceTestAccess::InsertCommittedEvent(
        store, first_timestamp + static_cast<std::int64_t>(index));
    ASSERT_TRUE(inserted.ok()) << inserted.error().message;
  }
}

void SeedEvent(const std::filesystem::path& path, const AuditEvent& event) {
  DatabaseConnection connection(path);
  sqlite3_stmt* statement = nullptr;
  constexpr const char* kSql =
      "INSERT INTO audit_events "
      "(sequence, server_timestamp_seconds, event_type, outcome, "
      "actor_user_id, actor_identity, peer_ip, detail_code, subject_type, "
      "subject_identity) VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8, "
      "?9);";
  if (::sqlite3_prepare_v2(connection.get(), kSql, -1, &statement, nullptr) !=
      SQLITE_OK) {
    throw std::runtime_error("sqlite3_prepare_v2 failed");
  }
  const auto bind_text = [statement](int index, const std::string& value) {
    return ::sqlite3_bind_text(statement, index, value.data(),
                               static_cast<int>(value.size()),
                               SQLITE_TRANSIENT) == SQLITE_OK;
  };
  const bool bound =
      ::sqlite3_bind_int64(statement, 1, event.sequence) == SQLITE_OK &&
      ::sqlite3_bind_int64(statement, 2, event.server_timestamp_seconds) ==
          SQLITE_OK &&
      bind_text(3, event.event_type) && bind_text(4, event.outcome) &&
      bind_text(5, event.actor_identity) && bind_text(6, event.peer_ip) &&
      bind_text(7, event.detail_code) && bind_text(8, event.subject_type) &&
      bind_text(9, event.subject_identity);
  const int stepped = bound ? ::sqlite3_step(statement) : SQLITE_ERROR;
  const int finalized = ::sqlite3_finalize(statement);
  if (stepped != SQLITE_DONE || finalized != SQLITE_OK) {
    throw std::runtime_error("sqlite3 insert failed");
  }
}

void SeedQueryEvents(const SecurityStore& store) {
  const std::array<AuditEvent, 6> events{{
      {1, 100, "login", "failure", "alice", "192.0.2.10", "d1", "user",
       "viewer"},
      {2, 100, "login", "success", "bob", "2001:db8::1", "d2", "user",
       "viewer"},
      {3, 200, "config_changed", "failure", "alice", "192.0.2.11", "d3",
       "config", "network"},
      {4, 200, "login", "success", "charlie", "2001:db8::1", "d4", "user",
       "camera"},
      {5, 300, "zeta", "failure", "bob", "192.0.2.10", "d5", "device",
       "camera"},
      {6, 300, "login", "success", "alice", "192.0.2.12", "d6", "user",
       "viewer"},
  }};
  for (const auto& event : events) {
    SeedEvent(store.database_path(), event);
  }
}

std::vector<std::int64_t> Sequences(const AuditEventPage& page) {
  std::vector<std::int64_t> values;
  values.reserve(page.events.size());
  for (const auto& event : page.events) {
    values.push_back(event.sequence);
  }
  return values;
}

AuditEventPage ListOrThrow(AuditLogService& service,
                           const AuditQueryParameters& parameters) {
  auto listed = service.ListEvents(parameters, Actor(UserRole::kAdministrator));
  if (!listed.ok()) {
    throw std::runtime_error(listed.error().code + ": " +
                             listed.error().message);
  }
  return std::move(listed).value();
}

void ExpectInvalid(AuditLogService& service,
                   const AuditQueryParameters& parameters) {
  auto listed = service.ListEvents(parameters, Actor(UserRole::kAdministrator));
  ASSERT_FALSE(listed.ok());
  EXPECT_EQ(listed.error().code, "E_AUDIT_QUERY_INVALID");
  EXPECT_EQ(listed.error().message, "audit query is invalid");
}

constexpr std::string_view kBase64UrlAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string EncodeBase64Url(const std::vector<unsigned char>& bytes) {
  std::string encoded;
  encoded.reserve((bytes.size() * 4U + 2U) / 3U);
  for (std::size_t index = 0; index < bytes.size(); index += 3U) {
    const std::size_t remaining = bytes.size() - index;
    const std::uint32_t block =
        static_cast<std::uint32_t>(bytes[index]) << 16U |
        (remaining > 1U ? static_cast<std::uint32_t>(bytes[index + 1U]) << 8U
                        : 0U) |
        (remaining > 2U ? static_cast<std::uint32_t>(bytes[index + 2U]) : 0U);
    encoded.push_back(kBase64UrlAlphabet[(block >> 18U) & 0x3fU]);
    encoded.push_back(kBase64UrlAlphabet[(block >> 12U) & 0x3fU]);
    if (remaining > 1U) {
      encoded.push_back(kBase64UrlAlphabet[(block >> 6U) & 0x3fU]);
    }
    if (remaining > 2U) {
      encoded.push_back(kBase64UrlAlphabet[block & 0x3fU]);
    }
  }
  return encoded;
}

std::vector<unsigned char> DecodeBase64Url(std::string_view encoded) {
  std::vector<unsigned char> decoded;
  std::uint32_t accumulator = 0U;
  int bits = 0;
  for (const char character : encoded) {
    const auto position = kBase64UrlAlphabet.find(character);
    if (position == std::string_view::npos) {
      throw std::runtime_error("invalid test base64url");
    }
    accumulator = (accumulator << 6U) | static_cast<std::uint32_t>(position);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      decoded.push_back(
          static_cast<unsigned char>((accumulator >> bits) & 0xffU));
    }
  }
  return decoded;
}

void AppendUint64(std::vector<unsigned char>& bytes, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    bytes.push_back(static_cast<unsigned char>((value >> shift) & 0xffU));
  }
}

std::vector<unsigned char> IntegerKey(std::uint64_t value) {
  std::vector<unsigned char> key;
  AppendUint64(key, value);
  return key;
}

std::vector<unsigned char> TextKey(std::string_view value) {
  return {value.begin(), value.end()};
}

std::vector<unsigned char> CursorPayload(
    unsigned char sort, unsigned char direction, unsigned char kind,
    std::uint64_t sequence, const std::vector<unsigned char>& key,
    std::optional<std::uint16_t> declared_length = std::nullopt) {
  std::vector<unsigned char> payload{1U, sort, direction, kind};
  AppendUint64(payload, sequence);
  const std::uint16_t length =
      declared_length.value_or(static_cast<std::uint16_t>(key.size()));
  payload.push_back(static_cast<unsigned char>((length >> 8U) & 0xffU));
  payload.push_back(static_cast<unsigned char>(length & 0xffU));
  payload.insert(payload.end(), key.begin(), key.end());
  return payload;
}

std::uint64_t ReadUint64(const std::vector<unsigned char>& bytes,
                         std::size_t offset) {
  std::uint64_t value = 0U;
  for (std::size_t index = 0; index < 8U; ++index) {
    value = (value << 8U) | bytes[offset + index];
  }
  return value;
}

TEST(AuditLogServiceTest, AdministratorReadsEmptyStatus) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 5U, 80U);
  AuditLogService service(*store);

  auto status = service.ReadStatus(Actor(UserRole::kAdministrator));

  ASSERT_TRUE(status.ok()) << status.error().message;
  EXPECT_EQ(status.value().current_events, 0U);
  EXPECT_EQ(status.value().max_events, 5U);
  EXPECT_EQ(status.value().usage_percent, 0U);
  EXPECT_FALSE(status.value().warning);
  EXPECT_EQ(status.value().rotated_event_count, 0U);
  EXPECT_FALSE(status.value().last_rotation_at_seconds.has_value());
  EXPECT_FALSE(status.value().last_rotated_sequence.has_value());
}

TEST(AuditLogServiceTest, ViewerIsRejectedBeforeStoreAccess) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 5U, 80U);
  ExecuteSql(store->database_path(), "DROP TABLE audit_state;");
  AuditLogService service(*store);

  auto status = service.ReadStatus(Actor(UserRole::kViewer));

  ASSERT_FALSE(status.ok());
  EXPECT_EQ(status.error().code, "E_AUDIT_FORBIDDEN");
}

TEST(AuditLogServiceTest, StoreFailureIsSanitized) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 5U, 80U);
  ExecuteSql(store->database_path(), "DROP TABLE audit_state;");
  AuditLogService service(*store);

  auto status = service.ReadStatus(Actor(UserRole::kAdministrator));

  ASSERT_FALSE(status.ok());
  EXPECT_EQ(status.error().code, "E_AUDIT_UNAVAILABLE");
  EXPECT_EQ(status.error().message, "audit status is unavailable");
  EXPECT_EQ(status.error().message.find("sqlite"), std::string::npos);
  EXPECT_EQ(status.error().message.find("audit_state"), std::string::npos);
  EXPECT_EQ(status.error().message.find(root.StatePath().string()),
            std::string::npos);
}

TEST(AuditLogServiceTest, UsagePercentageUsesIntegerFloor) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 6U, 80U);
  InsertEvents(*store, 1000, 1U);
  AuditLogService service(*store);

  auto status = service.ReadStatus(Actor(UserRole::kAdministrator));

  ASSERT_TRUE(status.ok()) << status.error().message;
  EXPECT_EQ(status.value().current_events, 1U);
  EXPECT_EQ(status.value().usage_percent, 16U);
  EXPECT_FALSE(status.value().warning);
}

TEST(AuditLogServiceTest, WarningBeginsAtExactConfiguredThreshold) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 5U, 80U);
  AuditLogService service(*store);
  const Principal administrator = Actor(UserRole::kAdministrator);

  for (std::uint64_t count = 0U; count < 4U; ++count) {
    auto status = service.ReadStatus(administrator);
    ASSERT_TRUE(status.ok()) << status.error().message;
    EXPECT_EQ(status.value().current_events, count);
    EXPECT_FALSE(status.value().warning);
    ASSERT_TRUE(AuditLogServiceTestAccess::InsertCommittedEvent(
                    *store, 1100 + static_cast<std::int64_t>(count))
                    .ok());
  }

  auto status = service.ReadStatus(administrator);
  ASSERT_TRUE(status.ok()) << status.error().message;
  EXPECT_EQ(status.value().current_events, 4U);
  EXPECT_EQ(status.value().usage_percent, 80U);
  EXPECT_TRUE(status.value().warning);
}

TEST(AuditLogServiceTest, SixthEventRotatesOnlyOldestRow) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 5U, 80U);
  InsertEvents(*store, 1201, 6U);
  AuditLogService service(*store);

  auto status = service.ReadStatus(Actor(UserRole::kAdministrator));

  ASSERT_TRUE(status.ok()) << status.error().message;
  EXPECT_EQ(status.value().current_events, 5U);
  EXPECT_EQ(status.value().rotated_event_count, 1U);
  EXPECT_EQ(status.value().last_rotation_at_seconds,
            std::optional<std::int64_t>(1206));
  EXPECT_EQ(status.value().last_rotated_sequence,
            std::optional<std::int64_t>(1));
  EXPECT_EQ(QueryInt64Rows(store->database_path(),
                           "SELECT sequence FROM audit_events "
                           "ORDER BY sequence;"),
            (std::vector<std::int64_t>{2, 3, 4, 5, 6}));
}

TEST(AuditLogServiceTest, LoweredLimitClampsStatusAndCatchesUpOnInsertion) {
  TemporaryDirectory root;
  {
    auto original = OpenStore(root.StatePath(), 10U, 80U);
    InsertEvents(*original, 1301, 7U);
  }
  auto store = OpenStore(root.StatePath(), 5U, 80U);
  AuditLogService service(*store);
  const Principal administrator = Actor(UserRole::kAdministrator);

  auto before = service.ReadStatus(administrator);
  ASSERT_TRUE(before.ok()) << before.error().message;
  EXPECT_EQ(before.value().current_events, 7U);
  EXPECT_EQ(before.value().max_events, 5U);
  EXPECT_EQ(before.value().usage_percent, 100U);
  EXPECT_TRUE(before.value().warning);

  ASSERT_TRUE(
      AuditLogServiceTestAccess::InsertCommittedEvent(*store, 1308).ok());
  auto after = service.ReadStatus(administrator);
  ASSERT_TRUE(after.ok()) << after.error().message;
  EXPECT_EQ(after.value().current_events, 5U);
  EXPECT_EQ(after.value().rotated_event_count, 3U);
  EXPECT_EQ(after.value().last_rotation_at_seconds,
            std::optional<std::int64_t>(1308));
  EXPECT_EQ(after.value().last_rotated_sequence,
            std::optional<std::int64_t>(3));
  EXPECT_EQ(QueryInt64Rows(store->database_path(),
                           "SELECT sequence FROM audit_events "
                           "ORDER BY sequence;"),
            (std::vector<std::int64_t>{4, 5, 6, 7, 8}));
}

TEST(AuditLogServiceTest, SingleEventLimitPreservesMonotonicSequences) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 1U, 80U);
  InsertEvents(*store, 1351, 3U);
  AuditLogService service(*store);

  EXPECT_EQ(QueryInt64Rows(store->database_path(),
                           "SELECT sequence FROM audit_events;"),
            (std::vector<std::int64_t>{3}));
  auto status = service.ReadStatus(Actor(UserRole::kAdministrator));

  ASSERT_TRUE(status.ok()) << status.error().message;
  EXPECT_EQ(status.value().current_events, 1U);
  EXPECT_EQ(status.value().rotated_event_count, 2U);
  EXPECT_EQ(status.value().last_rotated_sequence,
            std::optional<std::int64_t>(2));
}

TEST(AuditLogServiceTest, RotationCounterOverflowRollsBackDeletionAndEvent) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 5U, 80U);
  InsertEvents(*store, 1401, 5U);
  ExecuteSql(store->database_path(),
             "UPDATE audit_state SET rotated_event_count = "
             "9223372036854775807 WHERE id = 1;");

  auto inserted = AuditLogServiceTestAccess::InsertCommittedEvent(*store, 1406);

  ASSERT_FALSE(inserted.ok());
  EXPECT_EQ(inserted.error().code, "E_SECURITY_DB_AUDIT");
  EXPECT_EQ(QueryInt64Rows(store->database_path(),
                           "SELECT sequence FROM audit_events "
                           "ORDER BY sequence;"),
            (std::vector<std::int64_t>{1, 2, 3, 4, 5}));
  EXPECT_EQ(QueryInt64Rows(store->database_path(),
                           "SELECT rotated_event_count FROM audit_state;"),
            (std::vector<std::int64_t>{9223372036854775807LL}));
}

TEST(AuditLogServiceTest, QueryDefaultsToTimestampDescendingAndFifty) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 100U, 80U);
  for (std::int64_t sequence = 1; sequence <= 55; ++sequence) {
    SeedEvent(store->database_path(),
              {sequence, 1000 + sequence, "bulk", "success", "system",
               "192.0.2.1", "", "", ""});
  }
  AuditLogService service(*store);

  const auto page = ListOrThrow(service, {});

  ASSERT_EQ(page.events.size(), 50U);
  EXPECT_EQ(page.events.front().sequence, 55);
  EXPECT_EQ(page.events.back().sequence, 6);
  EXPECT_TRUE(page.next_cursor.has_value());
}

TEST(AuditLogServiceTest, FiltersAreExactAndAndedWithInclusiveTimeBounds) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  SeedQueryEvents(*store);
  AuditLogService service(*store);
  AuditQueryParameters query;

  query.from_seconds = "200";
  EXPECT_EQ(Sequences(ListOrThrow(service, query)),
            (std::vector<std::int64_t>{6, 5, 4, 3}));
  query = {};
  query.to_seconds = "200";
  EXPECT_EQ(Sequences(ListOrThrow(service, query)),
            (std::vector<std::int64_t>{4, 3, 2, 1}));
  query = {};
  query.event_type = "login";
  EXPECT_EQ(Sequences(ListOrThrow(service, query)),
            (std::vector<std::int64_t>{6, 4, 2, 1}));
  query = {};
  query.outcome = "failure";
  EXPECT_EQ(Sequences(ListOrThrow(service, query)),
            (std::vector<std::int64_t>{5, 3, 1}));
  query = {};
  query.actor_identity = "alice";
  EXPECT_EQ(Sequences(ListOrThrow(service, query)),
            (std::vector<std::int64_t>{6, 3, 1}));
  query = {};
  query.peer_ip = "192.0.2.10";
  EXPECT_EQ(Sequences(ListOrThrow(service, query)),
            (std::vector<std::int64_t>{5, 1}));
  query = {};
  query.subject_type = "user";
  EXPECT_EQ(Sequences(ListOrThrow(service, query)),
            (std::vector<std::int64_t>{6, 4, 2, 1}));
  query = {};
  query.subject_identity = "viewer";
  EXPECT_EQ(Sequences(ListOrThrow(service, query)),
            (std::vector<std::int64_t>{6, 2, 1}));

  query = {};
  query.from_seconds = "200";
  query.to_seconds = "200";
  EXPECT_EQ(Sequences(ListOrThrow(service, query)),
            (std::vector<std::int64_t>{4, 3}));

  query = {};
  query.from_seconds = "100";
  query.to_seconds = "100";
  query.event_type = "login";
  query.outcome = "failure";
  query.actor_identity = "alice";
  query.peer_ip = "192.0.2.10";
  query.subject_type = "user";
  query.subject_identity = "viewer";
  EXPECT_EQ(Sequences(ListOrThrow(service, query)),
            (std::vector<std::int64_t>{1}));

  query.event_type = "Login";
  EXPECT_TRUE(ListOrThrow(service, query).events.empty());
}

TEST(AuditLogServiceTest, FilterNormalizesExactIpv4AndIpv6Hosts) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  SeedQueryEvents(*store);
  AuditLogService service(*store);
  AuditQueryParameters query;

  query.peer_ip = "192.0.2.10";
  EXPECT_EQ(Sequences(ListOrThrow(service, query)),
            (std::vector<std::int64_t>{5, 1}));

  query.peer_ip = "2001:0db8:0000:0000:0000:0000:0000:0001";
  EXPECT_EQ(Sequences(ListOrThrow(service, query)),
            (std::vector<std::int64_t>{4, 2}));
  for (const auto& event : ListOrThrow(service, query).events) {
    EXPECT_EQ(event.peer_ip, "2001:db8::1");
  }
}

TEST(AuditLogServiceTest, SortsAllFieldsBothDirectionsWithSequenceTieBreaker) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  SeedQueryEvents(*store);
  AuditLogService service(*store);
  struct SortCase {
    std::string field;
    std::vector<std::int64_t> ascending;
    std::vector<std::int64_t> descending;
  };
  const std::vector<SortCase> cases{
      {"timestamp", {1, 2, 3, 4, 5, 6}, {6, 5, 4, 3, 2, 1}},
      {"event_type", {3, 1, 2, 4, 6, 5}, {5, 6, 4, 2, 1, 3}},
      {"outcome", {1, 3, 5, 2, 4, 6}, {6, 4, 2, 5, 3, 1}},
      {"actor", {1, 3, 6, 2, 5, 4}, {4, 5, 2, 6, 3, 1}},
      {"peer_ip", {1, 5, 3, 6, 2, 4}, {4, 2, 6, 3, 5, 1}},
      {"subject", {4, 5, 3, 1, 2, 6}, {6, 2, 1, 3, 5, 4}},
  };

  for (const auto& item : cases) {
    AuditQueryParameters query;
    query.sort_by = item.field;
    query.sort_direction = "asc";
    EXPECT_EQ(Sequences(ListOrThrow(service, query)), item.ascending)
        << item.field;
    query.sort_direction = "desc";
    EXPECT_EQ(Sequences(ListOrThrow(service, query)), item.descending)
        << item.field;
  }
}

TEST(AuditLogServiceTest, CursorTraversesDuplicateKeysForEverySort) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  SeedQueryEvents(*store);
  AuditLogService service(*store);
  struct SortCase {
    std::string field;
    std::string direction;
    std::vector<std::int64_t> expected;
  };
  const std::vector<SortCase> cases{
      {"timestamp", "asc", {1, 2, 3, 4, 5, 6}},
      {"timestamp", "desc", {6, 5, 4, 3, 2, 1}},
      {"event_type", "asc", {3, 1, 2, 4, 6, 5}},
      {"event_type", "desc", {5, 6, 4, 2, 1, 3}},
      {"outcome", "asc", {1, 3, 5, 2, 4, 6}},
      {"outcome", "desc", {6, 4, 2, 5, 3, 1}},
      {"actor", "asc", {1, 3, 6, 2, 5, 4}},
      {"actor", "desc", {4, 5, 2, 6, 3, 1}},
      {"peer_ip", "asc", {1, 5, 3, 6, 2, 4}},
      {"peer_ip", "desc", {4, 2, 6, 3, 5, 1}},
      {"subject", "asc", {4, 5, 3, 1, 2, 6}},
      {"subject", "desc", {6, 2, 1, 3, 5, 4}},
  };

  for (const auto& item : cases) {
    AuditQueryParameters query;
    query.sort_by = item.field;
    query.sort_direction = item.direction;
    query.limit = "1";
    std::vector<std::int64_t> traversed;
    for (std::size_t page_number = 0; page_number < 10U; ++page_number) {
      const auto page = ListOrThrow(service, query);
      const auto sequences = Sequences(page);
      traversed.insert(traversed.end(), sequences.begin(), sequences.end());
      if (!page.next_cursor.has_value()) {
        break;
      }
      query.cursor = page.next_cursor;
    }
    EXPECT_EQ(traversed, item.expected) << item.field << " " << item.direction;
  }
}

TEST(AuditLogServiceTest, QueryAcceptsLimitOneAndOneHundred) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  SeedQueryEvents(*store);
  AuditLogService service(*store);
  AuditQueryParameters query;

  query.limit = "1";
  const auto one = ListOrThrow(service, query);
  EXPECT_EQ(one.events.size(), 1U);
  EXPECT_TRUE(one.next_cursor.has_value());

  query.limit = "100";
  query.cursor.reset();
  const auto hundred = ListOrThrow(service, query);
  EXPECT_EQ(hundred.events.size(), 6U);
  EXPECT_FALSE(hundred.next_cursor.has_value());
}

TEST(AuditLogServiceTest, QueryRejectsInvalidSemanticValues) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  AuditLogService service(*store);
  const std::string invalid_utf8{"\xc3\x28", 2U};
  const std::string embedded_nul{"ab\0cd", 5U};
  const std::string oversized(65U, 'x');
  std::vector<AuditQueryParameters> invalid;

  AuditQueryParameters query;
  query.event_type = "";
  invalid.push_back(query);
  query.event_type = oversized;
  invalid.push_back(query);
  query.event_type = invalid_utf8;
  invalid.push_back(query);
  query = {};
  query.outcome = "partial";
  invalid.push_back(query);
  query.outcome = "";
  invalid.push_back(query);
  query = {};
  query.actor_identity = embedded_nul;
  invalid.push_back(query);
  query.actor_identity = oversized;
  invalid.push_back(query);
  query = {};
  query.peer_ip = "camera.local";
  invalid.push_back(query);
  query.peer_ip = embedded_nul;
  invalid.push_back(query);
  query = {};
  query.subject_type = "";
  invalid.push_back(query);
  query.subject_type = oversized;
  invalid.push_back(query);
  query = {};
  query.subject_identity = "";
  invalid.push_back(query);
  query.subject_identity = oversized;
  invalid.push_back(query);

  for (const std::string value :
       {"", "-1", "+1", " 1", "1x", "9223372036854775808"}) {
    query = {};
    query.from_seconds = value;
    invalid.push_back(query);
  }
  query = {};
  query.from_seconds = "2";
  query.to_seconds = "1";
  invalid.push_back(query);
  query = {};
  query.sort_by = "Timestamp";
  invalid.push_back(query);
  query.sort_by = "sequence";
  invalid.push_back(query);
  query = {};
  query.sort_direction = "ascending";
  invalid.push_back(query);
  for (const std::string value : {"", "0", "101", "-1", "1x"}) {
    query = {};
    query.limit = value;
    invalid.push_back(query);
  }
  query = {};
  query.cursor = std::string(513U, 'A');
  invalid.push_back(query);

  for (const auto& parameters : invalid) {
    ExpectInvalid(service, parameters);
  }
}

TEST(AuditLogServiceTest, QueryRejectsNoncanonicalDecimalForms) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  AuditLogService service(*store);
  const std::string arabic_indic_one{"\xd9\xa1", 2U};
  std::vector<AuditQueryParameters> invalid;

  const std::vector<std::string> epoch_invalid{
      "-0", "+1", " 1", "1 ", arabic_indic_one, "00000000000000000001"};
  for (const std::string& value : epoch_invalid) {
    AuditQueryParameters query;
    query.from_seconds = value;
    invalid.push_back(query);
    query = {};
    query.to_seconds = value;
    invalid.push_back(query);
  }
  const std::vector<std::string> limit_invalid{
      "-0", "+1", " 1", "1 ", arabic_indic_one, "0001"};
  for (const std::string& value : limit_invalid) {
    AuditQueryParameters query;
    query.limit = value;
    invalid.push_back(query);
  }

  for (const auto& parameters : invalid) {
    ExpectInvalid(service, parameters);
  }

  AuditQueryParameters query;
  query.from_seconds = "9223372036854775807";
  query.to_seconds = "9223372036854775807";
  query.limit = "100";
  EXPECT_NO_THROW((void)ListOrThrow(service, query));
}

TEST(AuditLogServiceTest, CursorUsesExactVersionedBinaryFormat) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  SeedQueryEvents(*store);
  AuditLogService service(*store);
  AuditQueryParameters query;
  query.limit = "1";

  const auto timestamp_page = ListOrThrow(service, query);
  ASSERT_TRUE(timestamp_page.next_cursor.has_value());
  const auto timestamp = DecodeBase64Url(*timestamp_page.next_cursor);
  ASSERT_EQ(timestamp.size(), 22U);
  EXPECT_EQ(timestamp[0], 1U);
  EXPECT_EQ(timestamp[1], 0U);
  EXPECT_EQ(timestamp[2], 1U);
  EXPECT_EQ(timestamp[3], 0U);
  EXPECT_EQ(ReadUint64(timestamp, 4U), 6U);
  EXPECT_EQ((static_cast<std::uint16_t>(timestamp[12]) << 8U | timestamp[13]),
            8U);
  EXPECT_EQ(ReadUint64(timestamp, 14U), 300U);

  query.sort_by = "event_type";
  query.sort_direction = "asc";
  const auto text_page = ListOrThrow(service, query);
  ASSERT_TRUE(text_page.next_cursor.has_value());
  const auto text = DecodeBase64Url(*text_page.next_cursor);
  ASSERT_GE(text.size(), 14U);
  EXPECT_EQ(text[0], 1U);
  EXPECT_EQ(text[1], 1U);
  EXPECT_EQ(text[2], 0U);
  EXPECT_EQ(text[3], 1U);
  EXPECT_EQ(ReadUint64(text, 4U), 3U);
  const std::size_t key_length =
      static_cast<std::size_t>(text[12]) << 8U | text[13];
  ASSERT_EQ(text.size(), 14U + key_length);
  EXPECT_EQ(std::string(text.begin() + 14, text.end()), "config_changed");
}

TEST(AuditLogServiceTest, CursorRejectsNoncanonicalAndMalformedPayloads) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  SeedQueryEvents(*store);
  AuditLogService service(*store);
  const auto expect_timestamp_payload_invalid =
      [&service](std::vector<unsigned char> payload) {
        AuditQueryParameters query;
        query.cursor = EncodeBase64Url(payload);
        ExpectInvalid(service, query);
      };

  auto payload = CursorPayload(0U, 1U, 0U, 6U, IntegerKey(300U));
  payload[0] = 2U;
  expect_timestamp_payload_invalid(payload);
  payload = CursorPayload(6U, 1U, 0U, 6U, IntegerKey(300U));
  expect_timestamp_payload_invalid(payload);
  payload = CursorPayload(0U, 2U, 0U, 6U, IntegerKey(300U));
  expect_timestamp_payload_invalid(payload);
  payload = CursorPayload(0U, 1U, 2U, 6U, IntegerKey(300U));
  expect_timestamp_payload_invalid(payload);
  payload = CursorPayload(0U, 1U, 0U, 0U, IntegerKey(300U));
  expect_timestamp_payload_invalid(payload);
  payload = CursorPayload(0U, 1U, 0U, 1ULL << 63U, IntegerKey(300U));
  expect_timestamp_payload_invalid(payload);
  payload = CursorPayload(0U, 1U, 0U, 6U, IntegerKey(300U), 7U);
  expect_timestamp_payload_invalid(payload);
  payload =
      CursorPayload(0U, 1U, 0U, 6U, std::vector<unsigned char>(7U, 0U), 8U);
  expect_timestamp_payload_invalid(payload);
  payload = CursorPayload(0U, 1U, 0U, 6U, IntegerKey(1ULL << 63U));
  expect_timestamp_payload_invalid(payload);
  payload = CursorPayload(0U, 1U, 1U, 6U, TextKey("300"));
  expect_timestamp_payload_invalid(payload);
  payload = CursorPayload(0U, 1U, 0U, 6U, IntegerKey(300U));
  payload.push_back(0U);
  expect_timestamp_payload_invalid(payload);

  const auto expect_event_payload_invalid =
      [&service](const std::vector<unsigned char>& event_payload) {
        AuditQueryParameters query;
        query.sort_by = "event_type";
        query.cursor = EncodeBase64Url(event_payload);
        ExpectInvalid(service, query);
      };
  expect_event_payload_invalid(CursorPayload(1U, 1U, 1U, 1U, {}));
  expect_event_payload_invalid(
      CursorPayload(1U, 1U, 1U, 1U, std::vector<unsigned char>(65U, 'x')));
  expect_event_payload_invalid(CursorPayload(1U, 1U, 1U, 1U, {0xc3U, 0x28U}));
  expect_event_payload_invalid(CursorPayload(1U, 1U, 1U, 1U, {'a', 0U, 'b'}));

  AuditQueryParameters query;
  query.cursor = "A";
  ExpectInvalid(service, query);
  query.cursor = "A+";
  ExpectInvalid(service, query);
  query.cursor = std::string(513U, 'A');
  ExpectInvalid(service, query);

  query = {};
  query.limit = "1";
  const auto page = ListOrThrow(service, query);
  ASSERT_TRUE(page.next_cursor.has_value());
  query.cursor = *page.next_cursor + "=";
  ExpectInvalid(service, query);
  std::string noncanonical = *page.next_cursor;
  const auto final_index = kBase64UrlAlphabet.find(noncanonical.back());
  ASSERT_NE(final_index, std::string_view::npos);
  noncanonical.back() = kBase64UrlAlphabet[final_index ^ 1U];
  query.cursor = noncanonical;
  ExpectInvalid(service, query);
}

TEST(AuditLogServiceTest, CursorRejectsSortAndDirectionMismatch) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  SeedQueryEvents(*store);
  AuditLogService service(*store);
  AuditQueryParameters query;
  query.limit = "1";
  const auto page = ListOrThrow(service, query);
  ASSERT_TRUE(page.next_cursor.has_value());

  query.cursor = page.next_cursor;
  query.sort_by = "event_type";
  ExpectInvalid(service, query);
  query.sort_by.reset();
  query.sort_direction = "asc";
  ExpectInvalid(service, query);
}

TEST(AuditLogServiceTest, CursorRemainsStableWhenNewerEventIsInserted) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  for (std::int64_t sequence = 1; sequence <= 5; ++sequence) {
    SeedEvent(store->database_path(),
              {sequence, sequence * 100, "stable", "success", "system",
               "192.0.2.1", "", "", ""});
  }
  AuditLogService service(*store);
  AuditQueryParameters query;
  query.limit = "2";
  const auto first = ListOrThrow(service, query);
  ASSERT_EQ(Sequences(first), (std::vector<std::int64_t>{5, 4}));
  ASSERT_TRUE(first.next_cursor.has_value());

  ASSERT_TRUE(
      AuditLogServiceTestAccess::InsertCommittedEvent(*store, 600).ok());
  std::vector<std::int64_t> traversed = Sequences(first);
  query.cursor = first.next_cursor;
  while (true) {
    const auto page = ListOrThrow(service, query);
    const auto page_sequences = Sequences(page);
    traversed.insert(traversed.end(), page_sequences.begin(),
                     page_sequences.end());
    if (!page.next_cursor.has_value()) {
      break;
    }
    query.cursor = page.next_cursor;
  }

  EXPECT_EQ(traversed, (std::vector<std::int64_t>{5, 4, 3, 2, 1}));
  EXPECT_EQ(std::count(traversed.begin(), traversed.end(), 6), 0);
}

TEST(AuditLogServiceTest, CursorDoesNotRepeatRowsWhenPageOneRowRotates) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 6U, 80U);
  for (std::int64_t sequence = 1; sequence <= 6; ++sequence) {
    SeedEvent(store->database_path(),
              {sequence, 700 - sequence * 100, "rotating", "success", "system",
               "192.0.2.1", "", "", ""});
  }
  AuditLogService service(*store);
  AuditQueryParameters query;
  query.limit = "2";
  const auto first = ListOrThrow(service, query);
  ASSERT_EQ(Sequences(first), (std::vector<std::int64_t>{1, 2}));
  ASSERT_TRUE(first.next_cursor.has_value());

  ASSERT_TRUE(
      AuditLogServiceTestAccess::InsertCommittedEvent(*store, 800).ok());
  std::vector<std::int64_t> traversed = Sequences(first);
  query.cursor = first.next_cursor;
  while (true) {
    const auto page = ListOrThrow(service, query);
    const auto page_sequences = Sequences(page);
    traversed.insert(traversed.end(), page_sequences.begin(),
                     page_sequences.end());
    if (!page.next_cursor.has_value()) {
      break;
    }
    query.cursor = page.next_cursor;
  }

  for (std::int64_t sequence = 1; sequence <= 6; ++sequence) {
    EXPECT_EQ(std::count(traversed.begin(), traversed.end(), sequence), 1)
        << sequence;
  }
  EXPECT_EQ(std::count(traversed.begin(), traversed.end(), 7), 0);
}

TEST(AuditLogServiceTest, QueryAuthorizationPrecedesParsingAndStoreAccess) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  ExecuteSql(store->database_path(), "DROP TABLE audit_events;");
  AuditLogService service(*store);
  AuditQueryParameters query;
  query.limit = "invalid";

  const auto listed = service.ListEvents(query, Actor(UserRole::kViewer));

  ASSERT_FALSE(listed.ok());
  EXPECT_EQ(listed.error().code, "E_AUDIT_FORBIDDEN");
}

TEST(AuditLogServiceTest, QueryStoreFailureIsSanitized) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 20U, 80U);
  ExecuteSql(store->database_path(), "DROP TABLE audit_events;");
  AuditLogService service(*store);

  const auto listed = service.ListEvents({}, Actor(UserRole::kAdministrator));

  ASSERT_FALSE(listed.ok());
  EXPECT_EQ(listed.error().code, "E_AUDIT_UNAVAILABLE");
  EXPECT_EQ(listed.error().message, "audit events are unavailable");
  EXPECT_EQ(listed.error().message.find("sqlite"), std::string::npos);
  EXPECT_EQ(listed.error().message.find("audit_events"), std::string::npos);
  EXPECT_EQ(listed.error().message.find(root.StatePath().string()),
            std::string::npos);
}

TEST(AuditLogServiceTest, AppendsSystemAndAdministratorEventsTransactionally) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 5U, 80U);
  ExecuteSql(store->database_path(), R"sql(
INSERT INTO users
  (id, canonical_username, display_username, role, enabled,
   password_algorithm, password_iterations, password_salt, password_derived,
   password_changed_at_seconds, failed_login_count, lock_until_seconds,
   created_at_seconds, last_login_at_seconds)
VALUES
  (1, 'operator.one', 'Operator One', 'administrator', 1,
   'pbkdf2-hmac-sha256', 1000, zeroblob(16), zeroblob(32), 1, 0, NULL, 1,
   NULL);
)sql");
  AuditLogService service(*store);

  ASSERT_TRUE(service
                  .AppendSystemEvent("self_test.started", "success", "OK",
                                     "suite", "self_test")
                  .ok());
  ASSERT_TRUE(service
                  .AppendAdministratorEvent(Actor(UserRole::kAdministrator),
                                            "2001:db8::1",
                                            "self_test.succeeded", "success",
                                            "OK", "suite", "self_test")
                  .ok());

  AuditQueryParameters query;
  query.sort_direction = "asc";
  const auto page = ListOrThrow(service, query);
  ASSERT_EQ(page.events.size(), 2U);
  EXPECT_EQ(page.events[0].sequence, 1);
  EXPECT_EQ(page.events[0].actor_identity, "system");
  EXPECT_EQ(page.events[0].peer_ip, "127.0.0.1");
  EXPECT_EQ(page.events[1].sequence, 2);
  EXPECT_EQ(page.events[1].actor_identity, "operator.one");
  EXPECT_EQ(page.events[1].peer_ip, "2001:db8::1");
  EXPECT_EQ(QueryInt64Rows(store->database_path(),
                           "SELECT actor_user_id IS NULL FROM audit_events "
                           "WHERE sequence = 1;"),
            (std::vector<std::int64_t>{1}));
}

TEST(AuditLogServiceTest, RollsBackFailedAuditAppendTransactions) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 5U, 80U);
  AuditLogService service(*store);

  auto insertion = service.AppendSystemEvent("", "success", "OK");
  ASSERT_FALSE(insertion.ok());
  EXPECT_EQ(insertion.error().code, "E_AUDIT_APPEND_UNAVAILABLE");
  EXPECT_EQ(insertion.error().message, "audit append is unavailable");
  EXPECT_EQ(insertion.error().message.find("sqlite"), std::string::npos);
  EXPECT_EQ(insertion.error().message.find("audit_events"), std::string::npos);
  EXPECT_EQ(insertion.error().message.find(root.StatePath().string()),
            std::string::npos);
  EXPECT_TRUE(ListOrThrow(service, {}).events.empty());

  ConfigureSecurityStoreTransactionFailuresForTest(true, false);
  auto commit = service.AppendSystemEvent("self_test.started", "success", "OK");
  ConfigureSecurityStoreTransactionFailuresForTest(false, false);
  ASSERT_FALSE(commit.ok());
  EXPECT_EQ(commit.error().code, "E_AUDIT_APPEND_UNAVAILABLE");
  EXPECT_EQ(commit.error().message, "audit append is unavailable");
  EXPECT_EQ(commit.error().message.find("sqlite"), std::string::npos);
  EXPECT_EQ(commit.error().message.find("COMMIT"), std::string::npos);
  EXPECT_EQ(commit.error().message.find(root.StatePath().string()),
            std::string::npos);
  EXPECT_TRUE(ListOrThrow(service, {}).events.empty());
}

TEST(AuditLogServiceTest, RejectsNoncanonicalAdministratorPeer) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 5U, 80U);
  AuditLogService service(*store);

  const auto result = service.AppendAdministratorEvent(
      Actor(UserRole::kAdministrator), "2001:0db8::1", "self_test.started",
      "success", "OK");

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_AUDIT_APPEND_INVALID");
  EXPECT_EQ(result.error().message, "audit append is invalid");
  EXPECT_TRUE(ListOrThrow(service, {}).events.empty());
}

TEST(AuditLogServiceTest, RejectsNonAdministratorAuditAppendActor) {
  TemporaryDirectory root;
  auto store = OpenStore(root.StatePath(), 5U, 80U);
  AuditLogService service(*store);

  auto result =
      service.AppendAdministratorEvent(Actor(UserRole::kViewer), "192.0.2.10",
                                       "self_test.started", "success", "OK");

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, "E_AUDIT_FORBIDDEN");
  EXPECT_EQ(result.error().message, "audit append is forbidden");
  EXPECT_TRUE(ListOrThrow(service, {}).events.empty());
}

}  // namespace
