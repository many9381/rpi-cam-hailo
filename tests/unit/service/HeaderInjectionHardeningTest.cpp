#include <string>

#include <drogon/Cookie.h>
#include <drogon/HttpResponse.h>
#include <gtest/gtest.h>

// Pins patches/drogon-1.9.0-strip-crlf-in-headers.patch (CVE-2023-26137 /
// CVE-2023-26138): a CR or LF reaching a response header or Set-Cookie line
// must never be serialized, so it cannot terminate the line and inject
// further headers.
namespace {

TEST(HeaderInjectionHardeningTest, ResponseHeaderValuesDropCarriageReturnAndLineFeed) {
  auto response = drogon::HttpResponse::newHttpResponse();
  response->addHeader("X-Test", "safe\r\nInjected: 1\n");
  EXPECT_EQ(response->getHeader("x-test"), "safeInjected: 1");
  response->addHeader("X-Moved", std::string("a\rb\nc"));
  EXPECT_EQ(response->getHeader("x-moved"), "abc");
}

TEST(HeaderInjectionHardeningTest, ResponseHeaderNamesDropCarriageReturnAndLineFeed) {
  auto response = drogon::HttpResponse::newHttpResponse();
  response->addHeader("X-Name\r\nInjected", "v");
  EXPECT_EQ(response->getHeader("x-nameinjected"), "v");
  EXPECT_TRUE(response->getHeader("injected").empty());
}

TEST(HeaderInjectionHardeningTest, SetCookieLineDropsCarriageReturnAndLineFeed) {
  drogon::Cookie cookie("session", "abc\r\nSet-Cookie: evil=1");
  cookie.setPath("/\r\nX-Injected: 1");
  cookie.setDomain("cam.local\n");
  const std::string line = cookie.cookieString();
  ASSERT_GE(line.size(), 2U);
  const std::string body = line.substr(0, line.size() - 2);  // strip the CRLF terminator
  EXPECT_EQ(body.find('\r'), std::string::npos);
  EXPECT_EQ(body.find('\n'), std::string::npos);
  EXPECT_NE(body.find("session=abcSet-Cookie: evil=1"), std::string::npos);
  EXPECT_NE(body.find("Path=/X-Injected: 1"), std::string::npos);
  EXPECT_NE(body.find("Domain=cam.local"), std::string::npos);
}

}  // namespace
