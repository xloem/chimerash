#pragma once

#include <string>
class Process
{
public:
    enum fd_mode { INHERIT, PIPE, PTY };
    Process(fd_mode stdin_mode, fd_mode stdout_mode, fd_mode stderr_mode, char const*fn, char*const argv[], char*const envp[]);
    ~Process();

    bool set_blocking(int fd, bool blocking);

    void write(std::string_view data);
    int wait(int ms = -1);
    bool avail_needslock(int fd = 1);
    std::string_view read(size_t size, int fd = 1);
    std::string_view readline(int fd = 1, char delim = '\n');
    std::string_view readall(int fd = 1);

    template <typename... Params>
    static std::string run(std::string_view input, char const*fn, Params... params);

private:
    static std::string run_impl(std::string_view input, char const*fn, char*const argv[], char*const envp[]);
    static std::string run_impl(std::string_view input, int pid, int pipes[]);

    int fds[3];
    void*files[3];
};

template <typename... Params>
std::string Process::run(std::string_view input, char const*fn, Params... _params)
{
    // copy params into std::string since the subprocess can mutate its arguments

    std::string params[sizeof...(_params)];
    char* argv[sizeof...(_params)+1] = {0};

    unsigned int i = 0;
    ((params[i] = _params, argv[i] = &params[i][0], ++i), ...);

    return run_impl(input, fn, argv, {nullptr});
}
