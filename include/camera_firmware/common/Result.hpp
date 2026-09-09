#pragma once

#include <cassert>
#include <exception>
#include <optional>
#include <string>
#include <type_traits>
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
  static Result Ok(T value) noexcept(std::is_nothrow_move_constructible_v<T>) {
    return Result(std::move(value));
  }

  static Result Err(Error error) { return Result(std::move(error)); }

  // The referenced Error must have static storage duration. This path stores
  // only its address so resource-exhaustion handlers can return without
  // allocation.
  static Result ErrFromStaticLifetime(const Error& error) noexcept {
    return Result(&error);
  }

  [[nodiscard]] bool ok() const noexcept { return state_.index() == 0U; }

  [[nodiscard]] const T& value() const& {
    assert(ok());
    return std::get<0U>(state_);
  }

  [[nodiscard]] T& value() & {
    assert(ok());
    return std::get<0U>(state_);
  }

  [[nodiscard]] T&& value() && {
    assert(ok());
    return std::get<0U>(std::move(state_));
  }

  [[nodiscard]] const Error& error() const& noexcept {
    assert(!ok());
    if (const auto* owned = std::get_if<1U>(&state_)) {
      return *owned;
    }
    if (const auto* const* static_error = std::get_if<2U>(&state_)) {
      return **static_error;
    }
    // error() on an Ok result violates the precondition above; under
    // noexcept the former bad_variant_access terminated as well.
    std::terminate();
  }

 private:
  explicit Result(T value) noexcept(std::is_nothrow_move_constructible_v<T>)
      : state_(std::move(value)) {}
  explicit Result(Error error) : state_(std::move(error)) {}
  explicit Result(const Error* static_error) noexcept
      : state_(std::in_place_index<2U>, static_error) {}

  std::variant<T, Error, const Error*> state_;
};

template <>
class Result<void> {
 public:
  static Result Ok() noexcept { return Result(); }

  static Result Err(Error error) { return Result(std::move(error)); }

  // The referenced Error must have static storage duration. This path stores
  // only its address so resource-exhaustion handlers can return without
  // allocation.
  static Result ErrFromStaticLifetime(const Error& error) noexcept {
    return Result(&error);
  }

  [[nodiscard]] bool ok() const noexcept {
    return !error_.has_value() && static_error_ == nullptr;
  }

  [[nodiscard]] const Error& error() const& noexcept {
    assert(!ok());
    return error_.has_value() ? *error_ : *static_error_;
  }

 private:
  Result() noexcept = default;
  explicit Result(Error error) : error_(std::move(error)) {}
  explicit Result(const Error* static_error) noexcept
      : static_error_(static_error) {}

  std::optional<Error> error_;
  const Error* static_error_{nullptr};
};

}  // namespace camera_firmware::common
