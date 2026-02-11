#include "InMemory.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <fcntl.h>

namespace execution {

    std::string ExecuteInMemory(const std::vector<uint8_t>& elfData, const std::string& args) {
        // 1. Create anonymous file in memory
        int fd = syscall(SYS_memfd_create, "system_update", MFD_CLOEXEC);
        if (fd == -1) return "Error: memfd_create failed";

        // 2. Write ELF data to it
        if (write(fd, elfData.data(), elfData.size()) != (ssize_t)elfData.size()) {
            close(fd);
            return "Error: failed to write ELF to memfd";
        }

        // 3. Prepare for execution
        int pipefd[2];
        if (pipe(pipefd) == -1) {
            close(fd);
            return "Error: pipe failed";
        }

        pid_t pid = fork();
        if (pid == -1) {
            close(fd); close(pipefd[0]); close(pipefd[1]);
            return "Error: fork failed";
        }

        if (pid == 0) {
            // Child process
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            dup2(pipefd[1], STDERR_FILENO);
            close(pipefd[1]);

            // Execute using fexecve if possible, but /proc/self/fd/ is more compatible
            char fdPath[64];
            snprintf(fdPath, sizeof(fdPath), "/proc/self/fd/%d", fd);

            // Simple argument splitting (should be improved)
            std::vector<char*> argv;
            argv.push_back(strdup("mem_exec"));
            char* args_copy = strdup(args.c_str());
            char* token = strtok(args_copy, " ");
            while (token) {
                argv.push_back(strdup(token));
                token = strtok(NULL, " ");
            }
            argv.push_back(NULL);

            execv(fdPath, argv.data());
            _exit(1);
        } else {
            // Parent process
            close(pipefd[1]);
            close(fd);

            std::string output;
            char buf[4096];
            ssize_t n;
            while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
                output.append(buf, n);
            }
            close(pipefd[0]);
            waitpid(pid, NULL, 0);
            return output;
        }
    }

}
