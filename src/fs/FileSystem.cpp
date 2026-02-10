#include "FileSystem.h"
#include "../external/nlohmann/json.hpp"
#include <filesystem>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
namespace fs_op = std::filesystem;
namespace fs {
    std::string Browse(const std::string& path) {
        nlohmann::json results = nlohmann::json::array();
        try {
            fs_op::path p(path); if (!fs_op::exists(p)) return "{\"error\": \"Path does not exist\"}";
            for (const auto& entry : fs_op::directory_iterator(p)) {
                nlohmann::json item;
                item["name"] = entry.path().filename().string();
                item["type"] = entry.is_directory() ? "dir" : "file";
                std::error_code ec;
                auto size = entry.is_regular_file() ? entry.file_size(ec) : 0;
                item["size"] = size;
                auto ftime = entry.last_write_time(ec);
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(ftime - fs_op::file_time_type::clock::now() + std::chrono::system_clock::now());
                std::time_t tt = std::chrono::system_clock::to_time_t(sctp);
                std::stringstream ss; std::tm gmt;
#ifdef _WIN32
                gmtime_s(&gmt, &tt);
#else
                gmtime_r(&tt, &gmt);
#endif
                ss << std::put_time(&gmt, "%Y-%m-%dT%H:%M:%SZ");
                item["modified"] = ss.str();
                results.push_back(item);
            }
        } catch (const std::exception& e) { return "{\"error\": \"" + std::string(e.what()) + "\"}"; }
        return "FS_LIST:" + results.dump();
    }
    std::vector<BYTE> ReadFileBinary(const std::string& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return {};
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<BYTE> buffer(size);
        if (file.read((char*)buffer.data(), size)) return buffer;
        return {};
    }
    bool WriteFileBinary(const std::string& path, const std::vector<BYTE>& data) {
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) return false;
        file.write((char*)data.data(), data.size());
        return true;
    }
}
