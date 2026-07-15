#include "RuntimeSettingsDocumentCodec.hpp"

#include <array>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <json/reader.h>
#include <json/value.h>

namespace camera_firmware::settings::internal {
namespace {

constexpr std::size_t kMaximumDocumentBytes = 16U * 1024U;
constexpr std::size_t kMaximumApplyCodeBytes = 64U;

common::Error DocumentError() {
  return {"E_RUNTIME_SETTINGS_DOCUMENT", "runtime settings document is invalid"};
}

template <typename T>
common::Result<T> InvalidDocument() {
  return common::Result<T>::Err(DocumentError());
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

bool IsPublicApplyCode(std::string_view code) {
  if (code.empty() || code.size() > kMaximumApplyCodeBytes) {
    return false;
  }
  for (const unsigned char character : code) {
    if ((character < 'A' || character > 'Z') &&
        (character < '0' || character > '9') && character != '_') {
      return false;
    }
  }
  return true;
}

bool IsValidLastApply(const LastApplyResult& last_apply) {
  switch (last_apply.status) {
    case ApplyStatus::kNever:
    case ApplyStatus::kSuccess:
      return last_apply.code.empty() && !last_apply.restored;
    case ApplyStatus::kFailed:
      return IsPublicApplyCode(last_apply.code);
  }
  return false;
}

bool IsIntegralJsonValue(const Json::Value& value) {
  return value.type() == Json::intValue || value.type() == Json::uintValue;
}

common::Result<unsigned int> DecodeUnsigned(const Json::Value& value) {
  if (!IsIntegralJsonValue(value) || !value.isUInt()) {
    return InvalidDocument<unsigned int>();
  }
  return common::Result<unsigned int>::Ok(value.asUInt());
}

common::Result<RuntimeSettings> DecodeSettings(
    const Json::Value& value,
    const config::AppConfig& base_config,
    const CameraProfileCatalog& profiles) {
  if (!HasExactKeys(value, {"camera", "models"}) ||
      !HasExactKeys(value["camera"], {"profile_id", "bitrate_kbps", "gop"}) ||
      !value["camera"]["profile_id"].isString() ||
      !IsValidUtf8(value["camera"]["profile_id"].asString()) ||
      !value["models"].isArray()) {
    return InvalidDocument<RuntimeSettings>();
  }

  const auto bitrate = DecodeUnsigned(value["camera"]["bitrate_kbps"]);
  const auto gop = DecodeUnsigned(value["camera"]["gop"]);
  if (!bitrate.ok() || !gop.ok()) {
    return InvalidDocument<RuntimeSettings>();
  }

  RuntimeSettings settings{
      .camera = {value["camera"]["profile_id"].asString(), bitrate.value(),
                 gop.value()},
  };
  settings.models.reserve(value["models"].size());
  for (const auto& model_value : value["models"]) {
    if (!HasExactKeys(
            model_value, {"id", "enabled", "confidence_threshold"}) ||
        !model_value["id"].isString() ||
        !IsValidUtf8(model_value["id"].asString()) ||
        !model_value["enabled"].isBool() ||
        !model_value["confidence_threshold"].isNumeric()) {
      return InvalidDocument<RuntimeSettings>();
    }

    const double threshold = model_value["confidence_threshold"].asDouble();
    if (!std::isfinite(threshold) || threshold < 0.0 || threshold > 1.0) {
      return InvalidDocument<RuntimeSettings>();
    }
    settings.models.push_back(
        {model_value["id"].asString(), model_value["enabled"].asBool(),
         static_cast<float>(threshold)});
  }

  const auto validated = ValidateRuntimeSettings(settings, base_config, profiles);
  if (!validated.ok()) {
    return InvalidDocument<RuntimeSettings>();
  }
  return common::Result<RuntimeSettings>::Ok(std::move(settings));
}

common::Result<LastApplyResult> DecodeLastApply(const Json::Value& value) {
  if (!HasExactKeys(value, {"status", "code", "restored"}) ||
      !value["status"].isString() || !value["code"].isString() ||
      !value["restored"].isBool()) {
    return InvalidDocument<LastApplyResult>();
  }

  const std::string status = value["status"].asString();
  const std::string code = value["code"].asString();
  if (!IsValidUtf8(status) || !IsValidUtf8(code)) {
    return InvalidDocument<LastApplyResult>();
  }

  LastApplyResult last_apply{.code = code,
                             .restored = value["restored"].asBool()};
  if (status == "never") {
    last_apply.status = ApplyStatus::kNever;
  } else if (status == "success") {
    last_apply.status = ApplyStatus::kSuccess;
  } else if (status == "failed") {
    last_apply.status = ApplyStatus::kFailed;
  } else {
    return InvalidDocument<LastApplyResult>();
  }
  if (!IsValidLastApply(last_apply)) {
    return InvalidDocument<LastApplyResult>();
  }
  return common::Result<LastApplyResult>::Ok(std::move(last_apply));
}

void AppendUnsigned(std::string& output, std::uint64_t value) {
  std::array<char, 32U> buffer{};
  const auto [end, error] = std::to_chars(buffer.data(),
                                          buffer.data() + buffer.size(), value);
  if (error == std::errc()) {
    output.append(buffer.data(), end);
  }
}

void AppendFloat(std::string& output, float value) {
  std::array<char, 32U> buffer{};
  const auto [end, error] = std::to_chars(buffer.data(),
                                          buffer.data() + buffer.size(), value);
  if (error == std::errc()) {
    output.append(buffer.data(), end);
  }
}

void AppendString(std::string& output, std::string_view value) {
  static constexpr char kHex[] = "0123456789abcdef";
  output.push_back('"');
  for (const unsigned char character : value) {
    switch (character) {
      case '"':
        output.append("\\\"");
        break;
      case '\\':
        output.append("\\\\");
        break;
      case '\b':
        output.append("\\b");
        break;
      case '\f':
        output.append("\\f");
        break;
      case '\n':
        output.append("\\n");
        break;
      case '\r':
        output.append("\\r");
        break;
      case '\t':
        output.append("\\t");
        break;
      default:
        if (character < 0x20U) {
          output.append("\\u00");
          output.push_back(kHex[(character >> 4U) & 0x0fU]);
          output.push_back(kHex[character & 0x0fU]);
        } else {
          output.push_back(static_cast<char>(character));
        }
        break;
    }
  }
  output.push_back('"');
}

void AppendSettings(std::string& output, const RuntimeSettings& settings) {
  output.append("{\"camera\":{\"profile_id\":");
  AppendString(output, settings.camera.profile_id);
  output.append(",\"bitrate_kbps\":");
  AppendUnsigned(output, settings.camera.bitrate_kbps);
  output.append(",\"gop\":");
  AppendUnsigned(output, settings.camera.gop);
  output.append("},\"models\":[");
  for (std::size_t index = 0U; index < settings.models.size(); ++index) {
    if (index != 0U) {
      output.push_back(',');
    }
    const auto& model = settings.models[index];
    output.append("{\"id\":");
    AppendString(output, model.id);
    output.append(",\"enabled\":");
    output.append(model.enabled ? "true" : "false");
    output.append(",\"confidence_threshold\":");
    AppendFloat(output, model.confidence_threshold);
    output.push_back('}');
  }
  output.append("]}");
}

std::string_view ApplyStatusName(ApplyStatus status) {
  switch (status) {
    case ApplyStatus::kNever:
      return "never";
    case ApplyStatus::kSuccess:
      return "success";
    case ApplyStatus::kFailed:
      return "failed";
  }
  return "";
}

bool IsValidSettingsForDocument(const RuntimeSettings& settings,
                                const config::AppConfig& base_config,
                                const CameraProfileCatalog& profiles) {
  if (!IsValidUtf8(settings.camera.profile_id)) {
    return false;
  }
  for (const auto& model : settings.models) {
    if (!IsValidUtf8(model.id)) {
      return false;
    }
  }
  return ValidateRuntimeSettings(settings, base_config, profiles).ok();
}

}  // namespace

common::Result<RuntimeSettingsDocument> DecodeRuntimeSettingsDocument(
    std::string_view input,
    const config::AppConfig& base_config,
    const CameraProfileCatalog& profiles) {
  if (input.size() > kMaximumDocumentBytes || !IsValidUtf8(input)) {
    return InvalidDocument<RuntimeSettingsDocument>();
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
  if (!reader->parse(input.data(), input.data() + input.size(), &root, &errors) ||
      !HasExactKeys(root,
                    {"schema_version", "revision", "active", "pending",
                     "last_apply"}) ||
      !IsIntegralJsonValue(root["schema_version"]) ||
      !root["schema_version"].isUInt() ||
      root["schema_version"].asUInt() != 1U ||
      !IsIntegralJsonValue(root["revision"]) ||
      !root["revision"].isUInt64()) {
    return InvalidDocument<RuntimeSettingsDocument>();
  }

  const auto active = DecodeSettings(root["active"], base_config, profiles);
  if (!active.ok()) {
    return InvalidDocument<RuntimeSettingsDocument>();
  }
  std::optional<RuntimeSettings> pending;
  if (!root["pending"].isNull()) {
    const auto decoded_pending =
        DecodeSettings(root["pending"], base_config, profiles);
    if (!decoded_pending.ok()) {
      return InvalidDocument<RuntimeSettingsDocument>();
    }
    pending = decoded_pending.value();
  }
  const auto last_apply = DecodeLastApply(root["last_apply"]);
  if (!last_apply.ok()) {
    return InvalidDocument<RuntimeSettingsDocument>();
  }

  RuntimeSettingsDocument document{
      .revision = root["revision"].asUInt64(),
      .active = active.value(),
      .pending = std::move(pending),
      .last_apply = last_apply.value(),
  };
  return common::Result<RuntimeSettingsDocument>::Ok(std::move(document));
}

common::Result<std::string> EncodeRuntimeSettingsDocument(
    const RuntimeSettingsDocument& document,
    const config::AppConfig& base_config,
    const CameraProfileCatalog& profiles) {
  if (!IsValidSettingsForDocument(document.active, base_config, profiles) ||
      (document.pending.has_value() &&
       !IsValidSettingsForDocument(*document.pending, base_config, profiles)) ||
      !IsValidLastApply(document.last_apply)) {
    return InvalidDocument<std::string>();
  }

  std::string output;
  output.reserve(1024U);
  output.append("{\"schema_version\":1,\"revision\":");
  AppendUnsigned(output, document.revision);
  output.append(",\"active\":");
  AppendSettings(output, document.active);
  output.append(",\"pending\":");
  if (document.pending.has_value()) {
    AppendSettings(output, *document.pending);
  } else {
    output.append("null");
  }
  output.append(",\"last_apply\":{\"status\":");
  AppendString(output, ApplyStatusName(document.last_apply.status));
  output.append(",\"code\":");
  AppendString(output, document.last_apply.code);
  output.append(",\"restored\":");
  output.append(document.last_apply.restored ? "true" : "false");
  output.append("}}");

  if (output.size() > kMaximumDocumentBytes) {
    return InvalidDocument<std::string>();
  }
  return common::Result<std::string>::Ok(std::move(output));
}

}  // namespace camera_firmware::settings::internal
