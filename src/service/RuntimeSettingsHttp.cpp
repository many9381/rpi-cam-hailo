#include "camera_firmware/service/RuntimeSettingsHttp.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <initializer_list>
#include <memory>
#include <string>
#include <utility>

#include <json/reader.h>

#include "camera_firmware/settings/RuntimeSettings.hpp"

namespace camera_firmware::service {
namespace {

struct PublicError {
  drogon::HttpStatusCode status;
  std::string_view code;
  std::string_view message;
};

template <typename T>
common::Result<T> InvalidRequest() {
  return common::Result<T>::Err(
      {"E_SETTINGS_REQUEST_INVALID", "runtime settings request is invalid"});
}

bool IsValidUtf8(std::string_view input) {
  for (std::size_t index = 0U; index < input.size();) {
    const auto byte = static_cast<unsigned char>(input[index]);
    if (byte <= 0x7fU) {
      ++index;
      continue;
    }

    std::size_t length = 0U;
    unsigned char minimum_second = 0x80U;
    unsigned char maximum_second = 0xbfU;
    if (byte >= 0xc2U && byte <= 0xdfU) {
      length = 2U;
    } else if (byte == 0xe0U) {
      length = 3U;
      minimum_second = 0xa0U;
    } else if (byte >= 0xe1U && byte <= 0xecU) {
      length = 3U;
    } else if (byte == 0xedU) {
      length = 3U;
      maximum_second = 0x9fU;
    } else if (byte >= 0xeeU && byte <= 0xefU) {
      length = 3U;
    } else if (byte == 0xf0U) {
      length = 4U;
      minimum_second = 0x90U;
    } else if (byte >= 0xf1U && byte <= 0xf3U) {
      length = 4U;
    } else if (byte == 0xf4U) {
      length = 4U;
      maximum_second = 0x8fU;
    } else {
      return false;
    }

    if (index + length > input.size()) {
      return false;
    }
    const auto second = static_cast<unsigned char>(input[index + 1U]);
    if (second < minimum_second || second > maximum_second) {
      return false;
    }
    for (std::size_t offset = 2U; offset < length; ++offset) {
      const auto continuation =
          static_cast<unsigned char>(input[index + offset]);
      if (continuation < 0x80U || continuation > 0xbfU) {
        return false;
      }
    }
    index += length;
  }
  return true;
}

bool IsJsonContentType(std::string_view content_type) {
  std::string normalized(content_type);
  std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                 [](unsigned char value) {
                   return static_cast<char>(std::tolower(value));
                 });
  return normalized == "application/json" ||
         normalized == "application/json; charset=utf-8";
}

bool HasExactKeys(const Json::Value& object,
                  std::initializer_list<std::string_view> keys) {
  if (!object.isObject() || object.size() != keys.size()) {
    return false;
  }
  for (const auto key : keys) {
    if (!object.isMember(std::string(key))) {
      return false;
    }
  }
  return true;
}

bool HasKeysWithOptional(const Json::Value& object,
                         std::initializer_list<std::string_view> required_keys,
                         std::string_view optional_key) {
  if (!object.isObject()) {
    return false;
  }
  for (const auto key : required_keys) {
    if (!object.isMember(std::string(key))) {
      return false;
    }
  }
  const auto required_count = required_keys.size();
  if (object.size() == required_count) {
    return true;
  }
  if (object.size() == required_count + 1U &&
      object.isMember(std::string(optional_key))) {
    return true;
  }
  return false;
}

bool IsIntegralJsonValue(const Json::Value& value) {
  return value.type() == Json::intValue || value.type() == Json::uintValue;
}

common::Result<Json::Value> ParseStrictJson(std::string_view body,
                                            std::string_view content_type) {
  if (body.empty() || body.size() > kMaximumRuntimeSettingsBodyBytes ||
      !IsJsonContentType(content_type) || !IsValidUtf8(body)) {
    return InvalidRequest<Json::Value>();
  }

  Json::CharReaderBuilder builder;
  builder["collectComments"] = false;
  builder["allowComments"] = false;
  builder["allowTrailingCommas"] = false;
  builder["strictRoot"] = true;
  builder["allowDroppedNullPlaceholders"] = false;
  builder["allowNumericKeys"] = false;
  builder["allowSingleQuotes"] = false;
  builder["stackLimit"] = 32;
  builder["failIfExtra"] = true;
  builder["rejectDupKeys"] = true;
  builder["allowSpecialFloats"] = false;
  builder["skipBom"] = false;

  Json::Value root;
  std::string errors;
  const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  if (!reader->parse(body.data(), body.data() + body.size(), &root, &errors)) {
    return InvalidRequest<Json::Value>();
  }
  return common::Result<Json::Value>::Ok(std::move(root));
}

common::Result<std::uint64_t> ParseRevision(const Json::Value& value) {
  if (!IsIntegralJsonValue(value) || !value.isUInt64()) {
    return InvalidRequest<std::uint64_t>();
  }
  return common::Result<std::uint64_t>::Ok(value.asUInt64());
}

common::Result<unsigned int> ParseUnsigned(const Json::Value& value) {
  if (!IsIntegralJsonValue(value) || !value.isUInt()) {
    return InvalidRequest<unsigned int>();
  }
  return common::Result<unsigned int>::Ok(value.asUInt());
}

common::Result<settings::RuntimeSettings> ParseSettings(
    const Json::Value& value) {
  if (!HasKeysWithOptional(value, {"camera", "models"}, "sub_stream") ||
      !HasExactKeys(value["camera"],
                    {"profile_id", "bitrate_kbps", "gop"}) ||
      !value["camera"]["profile_id"].isString() ||
      !IsValidUtf8(value["camera"]["profile_id"].asString()) ||
      !value["models"].isArray()) {
    return InvalidRequest<settings::RuntimeSettings>();
  }

  const auto bitrate = ParseUnsigned(value["camera"]["bitrate_kbps"]);
  const auto gop = ParseUnsigned(value["camera"]["gop"]);
  if (!bitrate.ok() || !gop.ok()) {
    return InvalidRequest<settings::RuntimeSettings>();
  }

  settings::RuntimeSettings parsed;
  parsed.camera = {value["camera"]["profile_id"].asString(), bitrate.value(),
                   gop.value()};

  if (value.isMember("sub_stream")) {
    const auto& sub_stream_value = value["sub_stream"];
    if (!HasExactKeys(sub_stream_value,
                      {"enabled", "width", "height", "fps",
                       "bitrate_kbps"}) ||
        !sub_stream_value["enabled"].isBool()) {
      return InvalidRequest<settings::RuntimeSettings>();
    }
    const auto width = ParseUnsigned(sub_stream_value["width"]);
    const auto height = ParseUnsigned(sub_stream_value["height"]);
    const auto fps = ParseUnsigned(sub_stream_value["fps"]);
    const auto sub_bitrate = ParseUnsigned(sub_stream_value["bitrate_kbps"]);
    if (!width.ok() || !height.ok() || !fps.ok() || !sub_bitrate.ok()) {
      return InvalidRequest<settings::RuntimeSettings>();
    }
    parsed.sub_stream = {sub_stream_value["enabled"].asBool(), width.value(),
                         height.value(), fps.value(), sub_bitrate.value()};
  } else {
    parsed.sub_stream = {false, 640U, 360U, 15U, 1000U};
  }

  parsed.models.reserve(value["models"].size());
  for (const auto& model : value["models"]) {
    if (!HasExactKeys(model,
                      {"id", "enabled", "confidence_threshold"}) ||
        !model["id"].isString() ||
        !IsValidUtf8(model["id"].asString()) ||
        !model["enabled"].isBool() ||
        !model["confidence_threshold"].isNumeric()) {
      return InvalidRequest<settings::RuntimeSettings>();
    }
    const double confidence = model["confidence_threshold"].asDouble();
    if (!std::isfinite(confidence) || confidence < 0.0 || confidence > 1.0) {
      return InvalidRequest<settings::RuntimeSettings>();
    }
    parsed.models.push_back({model["id"].asString(),
                             model["enabled"].asBool(),
                             static_cast<float>(confidence)});
  }
  return common::Result<settings::RuntimeSettings>::Ok(std::move(parsed));
}

Json::Value BuildSettingsJson(const settings::RuntimeSettings& settings) {
  Json::Value json(Json::objectValue);
  Json::Value camera(Json::objectValue);
  camera["profile_id"] = settings.camera.profile_id;
  camera["bitrate_kbps"] = settings.camera.bitrate_kbps;
  camera["gop"] = settings.camera.gop;
  json["camera"] = std::move(camera);

  Json::Value sub_stream(Json::objectValue);
  sub_stream["enabled"] = settings.sub_stream.enabled;
  sub_stream["width"] = settings.sub_stream.width;
  sub_stream["height"] = settings.sub_stream.height;
  sub_stream["fps"] = settings.sub_stream.fps;
  sub_stream["bitrate_kbps"] = settings.sub_stream.bitrate_kbps;
  json["sub_stream"] = std::move(sub_stream);

  Json::Value models(Json::arrayValue);
  for (const auto& model : settings.models) {
    Json::Value model_json(Json::objectValue);
    model_json["id"] = model.id;
    model_json["enabled"] = model.enabled;
    model_json["confidence_threshold"] = model.confidence_threshold;
    models.append(std::move(model_json));
  }
  json["models"] = std::move(models);
  return json;
}

std::string_view StateName(settings::RuntimeSettingsState state) {
  switch (state) {
    case settings::RuntimeSettingsState::kClean:
      return "clean";
    case settings::RuntimeSettingsState::kPending:
      return "pending";
    case settings::RuntimeSettingsState::kApplying:
      return "applying";
    case settings::RuntimeSettingsState::kFailed:
      return "failed";
    case settings::RuntimeSettingsState::kRecoveryRequired:
      return "recovery_required";
  }
  return "recovery_required";
}

std::string_view ApplyStatusName(settings::ApplyStatus status) {
  switch (status) {
    case settings::ApplyStatus::kNever:
      return "never";
    case settings::ApplyStatus::kSuccess:
      return "success";
    case settings::ApplyStatus::kFailed:
      return "failed";
  }
  return "failed";
}

PublicError MapPublicError(const common::Error& error) {
  if (error.code == "E_SETTINGS_REQUEST_INVALID") {
    return {drogon::k400BadRequest, "E_SETTINGS_REQUEST_INVALID",
            "runtime settings request is invalid"};
  }
  if (error.code == "E_RUNTIME_SETTINGS_REVISION" ||
      error.code == "E_SETTINGS_REVISION_CONFLICT") {
    return {drogon::k409Conflict, "E_SETTINGS_REVISION_CONFLICT",
            "runtime settings revision conflict"};
  }
  if (error.code == "E_RUNTIME_SETTINGS_NO_PENDING" ||
      error.code == "E_SETTINGS_NO_PENDING") {
    return {drogon::k409Conflict, "E_SETTINGS_NO_PENDING",
            "no pending runtime settings"};
  }
  if (error.code == "E_RUNTIME_SETTINGS_BUSY" ||
      error.code == "E_SETTINGS_BUSY") {
    return {drogon::k409Conflict, "E_SETTINGS_BUSY",
            "runtime settings are busy"};
  }
  if (error.code == "E_RUNTIME_SETTINGS_CAPTURE_MODE" ||
      error.code == "E_RUNTIME_SETTINGS_BITRATE" ||
      error.code == "E_RUNTIME_SETTINGS_GOP" ||
      error.code == "E_RUNTIME_SETTINGS_AI_DISABLED" ||
      error.code.starts_with("E_RUNTIME_SETTINGS_MODEL_") ||
      error.code.starts_with("E_RUNTIME_SETTINGS_SUB") ||
      error.code.starts_with("E_CONFIG_") ||
      error.code == "E_PIPELINE_CANDIDATE" ||
      error.code == "E_SETTINGS_UNSUPPORTED") {
    return {drogon::k422UnprocessableEntity, "E_SETTINGS_UNSUPPORTED",
            "runtime settings are unsupported"};
  }
  if (error.code == "E_RUNTIME_SETTINGS_STORE" ||
      error.code == "E_RUNTIME_SETTINGS_PATH" ||
      error.code == "E_RUNTIME_SETTINGS_DOCUMENT" ||
      error.code == "E_RUNTIME_SETTINGS_STATE_MODE" ||
      error.code == "E_RUNTIME_SETTINGS_STATE_OWNER" ||
      error.code == "E_RUNTIME_SETTINGS_FILE_MODE" ||
      error.code == "E_RUNTIME_SETTINGS_FILE_OWNER" ||
      error.code == "E_RUNTIME_SETTINGS_REVISION_OVERFLOW" ||
      error.code == "E_SETTINGS_STORE") {
    return {drogon::k500InternalServerError, "E_SETTINGS_STORE",
            "runtime settings store failed"};
  }
  if (error.code == "E_SETTINGS_UNAVAILABLE") {
    return {drogon::k503ServiceUnavailable, "E_SETTINGS_UNAVAILABLE",
            "runtime settings are unavailable"};
  }
  return {drogon::k503ServiceUnavailable, "E_SETTINGS_APPLY_FAILED",
          "runtime settings apply failed"};
}

drogon::HttpResponsePtr JsonResponse(
    Json::Value json,
    drogon::HttpStatusCode status = drogon::k200OK) {
  auto response = drogon::HttpResponse::newHttpJsonResponse(std::move(json));
  response->setStatusCode(status);
  return response;
}

}  // namespace

common::Result<RuntimeSettingsUpdateRequest> ParseRuntimeSettingsUpdateJson(
    std::string_view body,
    std::string_view content_type) {
  auto root = ParseStrictJson(body, content_type);
  if (!root.ok() ||
      !HasExactKeys(root.value(), {"expected_revision", "settings"})) {
    return InvalidRequest<RuntimeSettingsUpdateRequest>();
  }
  auto revision = ParseRevision(root.value()["expected_revision"]);
  auto settings = ParseSettings(root.value()["settings"]);
  if (!revision.ok() || !settings.ok()) {
    return InvalidRequest<RuntimeSettingsUpdateRequest>();
  }
  return common::Result<RuntimeSettingsUpdateRequest>::Ok(
      {revision.value(), std::move(settings).value()});
}

common::Result<RuntimeSettingsCommandRequest> ParseRuntimeSettingsCommandJson(
    std::string_view body,
    std::string_view content_type) {
  auto root = ParseStrictJson(body, content_type);
  if (!root.ok() ||
      !HasExactKeys(root.value(), {"expected_revision"})) {
    return InvalidRequest<RuntimeSettingsCommandRequest>();
  }
  auto revision = ParseRevision(root.value()["expected_revision"]);
  if (!revision.ok()) {
    return InvalidRequest<RuntimeSettingsCommandRequest>();
  }
  return common::Result<RuntimeSettingsCommandRequest>::Ok(
      {revision.value()});
}

Json::Value BuildRuntimeSettingsSnapshotJson(
    const settings::RuntimeSettingsSnapshot& snapshot) {
  Json::Value json(Json::objectValue);
  json["schema_version"] = 1U;
  json["revision"] = Json::UInt64(snapshot.revision);
  json["state"] = std::string(StateName(snapshot.state));

  Json::Value capabilities(Json::objectValue);
  Json::Value camera_profiles(Json::arrayValue);
  for (const auto& profile : snapshot.camera_profiles) {
    Json::Value profile_json(Json::objectValue);
    profile_json["id"] = profile.id;
    profile_json["label"] = profile.label;
    profile_json["width"] = profile.width;
    profile_json["height"] = profile.height;
    profile_json["fps"] = profile.fps;
    camera_profiles.append(std::move(profile_json));
  }
  capabilities["camera_profiles"] = std::move(camera_profiles);

  Json::Value bitrate(Json::objectValue);
  bitrate["minimum"] = settings::kMinBitrateKbps;
  bitrate["maximum"] = settings::kMaxBitrateKbps;
  capabilities["bitrate_kbps"] = std::move(bitrate);
  Json::Value gop(Json::objectValue);
  gop["minimum"] = settings::kMinGop;
  gop["maximum"] = settings::kMaxGop;
  capabilities["gop"] = std::move(gop);

  Json::Value models(Json::arrayValue);
  for (const auto& model : snapshot.model_capabilities) {
    Json::Value model_json(Json::objectValue);
    model_json["id"] = model.id;
    model_json["kind"] = model.kind;
    model_json["input_width"] = model.input_width;
    model_json["input_height"] = model.input_height;
    model_json["input_format"] = model.input_format;
    model_json["letterbox"] = model.letterbox;
    model_json["labels"] = model.labels;
    models.append(std::move(model_json));
  }
  capabilities["models"] = std::move(models);
  json["capabilities"] = std::move(capabilities);

  json["active"] = BuildSettingsJson(snapshot.active);
  if (snapshot.pending.has_value()) {
    json["pending"] = BuildSettingsJson(*snapshot.pending);
  } else {
    json["pending"] = Json::Value(Json::nullValue);
  }

  Json::Value last_apply(Json::objectValue);
  last_apply["status"] = std::string(ApplyStatusName(snapshot.last_apply.status));
  last_apply["code"] = snapshot.last_apply.status == settings::ApplyStatus::kFailed
                           ? "E_SETTINGS_APPLY_FAILED"
                           : "";
  last_apply["restored"] = snapshot.last_apply.restored;
  json["last_apply"] = std::move(last_apply);
  return json;
}

drogon::HttpResponsePtr BuildRuntimeSettingsSnapshotResponse(
    const settings::RuntimeSettingsSnapshot& snapshot) {
  return JsonResponse(BuildRuntimeSettingsSnapshotJson(snapshot));
}

drogon::HttpResponsePtr BuildRuntimeSettingsErrorResponse(
    const common::Error& error) {
  const auto mapped = MapPublicError(error);
  Json::Value json(Json::objectValue);
  json["code"] = std::string(mapped.code);
  json["message"] = std::string(mapped.message);
  return JsonResponse(std::move(json), mapped.status);
}

drogon::HttpResponsePtr BuildRuntimeSettingsApplyResponse(
    const settings::SettingsApplyResult& result) {
  Json::Value json = BuildRuntimeSettingsSnapshotJson(result.snapshot);
  json["applied"] = result.applied;
  json["restored"] = result.restored;
  if (result.applied) {
    return JsonResponse(std::move(json));
  }

  const auto mapped = MapPublicError(result.error);
  json["code"] = std::string(mapped.code);
  json["message"] = std::string(mapped.message);
  return JsonResponse(std::move(json), mapped.status);
}

drogon::HttpResponsePtr BuildProtectionRestrictedResponse() {
  Json::Value json(Json::objectValue);
  json["code"] = "E_PROTECTION_RESTRICTED";
  json["message"] = "runtime control is restricted";
  return JsonResponse(std::move(json), drogon::k423Locked);
}

}  // namespace camera_firmware::service
