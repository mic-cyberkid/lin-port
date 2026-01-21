#include "TaskDispatcher.h"
#include "Beacon.h"
#include "../recon/SysInfo.h"
#include <stdexcept>

namespace beacon {

TaskDispatcher::TaskDispatcher(moodycamel::ConcurrentQueue<Result>& pendingResults)
    : pendingResults_(pendingResults) {}

void TaskDispatcher::dispatch(const Task& task) {
    Result result;
    result.task_id = task.task_id;

    try {
        switch (task.type) {
            case TaskType::SYSINFO:
                result.output = recon::getSysInfo();
                break;
            // Add other task types here as they are implemented
            default:
                result.error = "Unknown or unsupported task type.";
                break;
        }
    } catch (const std::exception& e) {
        result.error = e.what();
    }

    pendingResults_.enqueue(result);
}

} // namespace beacon
