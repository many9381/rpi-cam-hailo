#include "camera_firmware/service/SystemProtectionHttp.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "camera_firmware/integrity/IntegrityManifest.hpp"

namespace camera_firmware::service {
namespace {

using security::ProtectionState;
using security::ProtectionSuite;
using security::ProtectionSuiteSnapshot;
using security::ProtectionTrigger;

common::Result<Json::Value> InvalidResult() {
  return common::Result<Json::Value>::Err(
      {"E_PROTECTION_RESULT_INVALID", "system protection result is invalid"});
}

std::optional<std::string_view> StateName(ProtectionState state) noexcept {
  switch (state) {
    case ProtectionState::kChecking:
      return "checking";
    case ProtectionState::kOperational:
      return "operational";
    case ProtectionState::kRestricted:
      return "restricted";
    case ProtectionState::kStopping:
      return std::nullopt;
  }
  return std::nullopt;
}

std::optional<std::string_view> SuiteName(ProtectionSuite suite) noexcept {
  switch (suite) {
    case ProtectionSuite::kSelfTest:
      return "self_test";
    case ProtectionSuite::kIntegrity:
      return "integrity";
  }
  return std::nullopt;
}

std::optional<std::string_view> TriggerName(
    ProtectionTrigger trigger) noexcept {
  switch (trigger) {
    case ProtectionTrigger::kStartup:
      return "startup";
    case ProtectionTrigger::kManual:
      return "manual";
    case ProtectionTrigger::kPeriodic:
      return "periodic";
  }
  return std::nullopt;
}

std::optional<std::string_view> CategoryName(
    integrity::IntegrityCategory category) noexcept {
  switch (category) {
    case integrity::IntegrityCategory::kFirmware:
      return "firmware";
    case integrity::IntegrityCategory::kLibrary:
      return "library";
    case integrity::IntegrityCategory::kConfiguration:
      return "configuration";
    case integrity::IntegrityCategory::kWebAsset:
      return "web_asset";
    case integrity::IntegrityCategory::kKernel:
      return "kernel";
    case integrity::IntegrityCategory::kKernelModule:
      return "kernel_module";
  }
  return std::nullopt;
}

bool ValidText(std::string_view text) noexcept {
  return text.size() <= kMaximumProtectionResultTextBytes;
}

bool ValidSuite(const ProtectionSuiteSnapshot& snapshot,
                ProtectionSuite expected_suite) noexcept {
  if (snapshot.suite != expected_suite || !SuiteName(snapshot.suite) ||
      !TriggerName(snapshot.trigger) ||
      snapshot.self_test_items.size() > kMaximumProtectionResultItems ||
      snapshot.integrity_items.size() > kMaximumProtectionResultItems) {
    return false;
  }
  if (expected_suite == ProtectionSuite::kSelfTest) {
    if (!snapshot.integrity_items.empty()) {
      return false;
    }
    for (const auto& item : snapshot.self_test_items) {
      if (!ValidText(item.id) || !ValidText(item.code)) {
        return false;
      }
    }
    return true;
  }
  if (!snapshot.self_test_items.empty()) {
    return false;
  }
  for (const auto& item : snapshot.integrity_items) {
    if (!ValidText(item.id) || !ValidText(item.code) ||
        !CategoryName(item.category)) {
      return false;
    }
  }
  return true;
}

Json::Value BuildSuiteJson(const ProtectionSuiteSnapshot& snapshot) {
  Json::Value json(Json::objectValue);
  // Both names were validated before this builder runs.
  json["suite"] = std::string(SuiteName(snapshot.suite).value_or("unknown"));
  json["trigger"] =
      std::string(TriggerName(snapshot.trigger).value_or("unknown"));
  json["passed"] = snapshot.passed;
  json["started_at_seconds"] = Json::Int64(snapshot.started_at_seconds);
  json["finished_at_seconds"] = Json::Int64(snapshot.finished_at_seconds);

  Json::Value items(Json::arrayValue);
  if (snapshot.suite == ProtectionSuite::kSelfTest) {
    for (const auto& item : snapshot.self_test_items) {
      Json::Value item_json(Json::objectValue);
      item_json["id"] = item.id;
      item_json["category"] = Json::Value(Json::nullValue);
      item_json["passed"] = item.passed;
      item_json["code"] = item.code;
      items.append(std::move(item_json));
    }
  } else {
    for (const auto& item : snapshot.integrity_items) {
      Json::Value item_json(Json::objectValue);
      item_json["id"] = item.id;
      item_json["category"] = std::string(*CategoryName(item.category));
      item_json["passed"] = item.passed;
      item_json["code"] = item.code;
      items.append(std::move(item_json));
    }
  }
  json["items"] = std::move(items);
  return json;
}

drogon::HttpResponsePtr JsonResponse(Json::Value json,
                                     drogon::HttpStatusCode status) {
  auto response = drogon::HttpResponse::newHttpJsonResponse(std::move(json));
  response->setStatusCode(status);
  return response;
}

drogon::HttpResponsePtr PublicError(drogon::HttpStatusCode status,
                                    std::string_view code,
                                    std::string_view message) {
  Json::Value json(Json::objectValue);
  json["code"] = std::string(code);
  json["message"] = std::string(message);
  return JsonResponse(std::move(json), status);
}

drogon::HttpResponsePtr UnavailableResponse() {
  return PublicError(drogon::k503ServiceUnavailable,
                     "E_PROTECTION_UNAVAILABLE",
                     "system protection is unavailable");
}

drogon::HttpResponsePtr InvalidResultResponse() {
  return PublicError(drogon::k503ServiceUnavailable,
                     "E_PROTECTION_RESULT_INVALID",
                     "system protection result is invalid");
}

drogon::HttpResponsePtr SnapshotResponse(
    const security::SystemProtectionSnapshot& snapshot,
    drogon::HttpStatusCode status) {
  auto json = BuildSystemProtectionJson(snapshot);
  if (!json.ok()) {
    return InvalidResultResponse();
  }
  return JsonResponse(std::move(json).value(), status);
}

}  // namespace

common::Result<Json::Value> BuildSystemProtectionJson(
    const security::SystemProtectionSnapshot& snapshot) {
  const auto state = StateName(snapshot.state);
  if (!state ||
      (snapshot.self_test &&
       !ValidSuite(*snapshot.self_test, ProtectionSuite::kSelfTest)) ||
      (snapshot.integrity &&
       !ValidSuite(*snapshot.integrity, ProtectionSuite::kIntegrity))) {
    return InvalidResult();
  }

  Json::Value json(Json::objectValue);
  json["state"] = std::string(*state);
  json["check_running"] = snapshot.check_running;
  json["next_periodic_at_seconds"] =
      Json::Int64(snapshot.next_periodic_at_seconds);
  json["self_test"] = snapshot.self_test
                          ? BuildSuiteJson(*snapshot.self_test)
                          : Json::Value(Json::nullValue);
  json["integrity"] = snapshot.integrity
                          ? BuildSuiteJson(*snapshot.integrity)
                          : Json::Value(Json::nullValue);
  return common::Result<Json::Value>::Ok(std::move(json));
}

drogon::HttpResponsePtr BuildSystemProtectionStatusResponse(
    const SystemProtectionSnapshotProvider& snapshot_provider) {
  if (!snapshot_provider) {
    return UnavailableResponse();
  }
  try {
    return SnapshotResponse(snapshot_provider(), drogon::k200OK);
  } catch (...) {
    return UnavailableResponse();
  }
}

drogon::HttpResponsePtr BuildSystemProtectionStartResponse(
    const SystemProtectionStartProvider& start_provider) {
  if (!start_provider) {
    return UnavailableResponse();
  }
  try {
    auto started = start_provider();
    if (started.ok()) {
      return SnapshotResponse(started.value(), drogon::k202Accepted);
    }
    if (started.error().code == "E_PROTECTION_CHECK_RUNNING") {
      return PublicError(drogon::k409Conflict,
                         "E_PROTECTION_CHECK_RUNNING",
                         "protection check is already running");
    }
    if (started.error().code == "E_PROTECTION_TRANSITION_BUSY") {
      return PublicError(drogon::k409Conflict,
                         "E_PROTECTION_TRANSITION_BUSY",
                         "runtime transition is busy");
    }
    if (started.error().code == "E_PROTECTION_RESULT_INVALID") {
      return InvalidResultResponse();
    }
    return UnavailableResponse();
  } catch (...) {
    return UnavailableResponse();
  }
}

}  // namespace camera_firmware::service
