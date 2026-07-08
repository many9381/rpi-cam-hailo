#pragma once

#include <cassert>
#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace camera_firmware::common {

struct Error {
  std::string code;
  std::string message;
};

template <typename T>
class Result {
 public:
  static Result Ok(T value) { return Result(std::move(value)); }

  static Result Err(Error error) { return Result(std::move(error)); }

  [[nodiscard]] bool ok() const noexcept {
    return std::holds_alternative<T>(state_);
  }

  [[nodiscard]] const T& value() const& {
    assert(ok());
    return std::get<T>(state_);
  }

  [[nodiscard]] T& value() & {
    assert(ok());
    return std::get<T>(state_);
  }

  [[nodiscard]] T&& value() && {
    assert(ok());
    return std::get<T>(std::move(state_));
  }

  [[nodiscard]] const Error& error() const& {
    assert(!ok());
    return std::get<Error>(state_);
  }

 private:
  explicit Result(T value) : state_(std::move(value)) {}
  explicit Result(Error error) : state_(std::move(error)) {}

  std::variant<T, Error> state_;
};

template <>
class Result<void> {
 public:
  static Result Ok() { return Result(); }

  static Result Err(Error error) { return Result(std::move(error)); }

  [[nodiscard]] bool ok() const noexcept { return !error_.has_value(); }

  [[nodiscard]] const Error& error() const& {
    assert(!ok());
    return *error_;
  }

 private:
  Result() = default;
  explicit Result(Error error) : error_(std::move(error)) {}

  std::optional<Error> error_;
};

}  // namespace camera_firmware::common
