#pragma once

#include "Task.h"
#include "../external/concurrentqueue/concurrentqueue.h"

namespace beacon {

struct Result; // Forward declaration

class TaskDispatcher {
public:
    TaskDispatcher(moodycamel::ConcurrentQueue<Result>& pendingResults);
    void dispatch(const Task& task);

private:
    moodycamel::ConcurrentQueue<Result>& pendingResults_;
};

} // namespace beacon
