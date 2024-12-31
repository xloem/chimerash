#include "process.hpp"

#include "wrappers.hpp" // to use real execve

#include <array>
#include <chrono>
#include <csignal>
#include <system_error>
#include <pty.h>
#include <termios.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/wait.h>

/* i use c-style casts because they are more concise */

#include <iostream>
Process::Process(fd_mode stdin_mode, fd_mode stdout_mode, fd_mode stderr_mode, char const*fn, char*const argv[], char*const envp[])
{
    int parent_pty = -1, child_pty = -1;
    int pipes[3][2];
    int child_fds[3], child_pid;
    int r;
    fd_mode modes[3] = {stdin_mode, stdout_mode, stderr_mode};
    for (int num = 0; num < 3; ++ num)
        switch(modes[num]) {
        case INHERIT:
            fds[num] = num;
            child_fds[num] = num;
            break;
        case PIPE:
            r = pipe(pipes[num]);
            if (r == -1) throw std::system_error(errno, std::system_category(), "Process::Process pipe");
            fds[num] = pipes[num][num?0:1];
            child_fds[num] = pipes[num][num?1:0];
            break;
        case PTY:
            if (child_pty == -1) {
                struct termios term;
                struct winsize win;
                r = tcgetattr(num, &term);
                if (r == -1) throw std::system_error(errno, std::system_category(), "Process::Process tcgetattr");
                r = ioctl(num, TIOCGWINSZ, &win);
                if (r == -1) throw std::system_error(errno, std::system_category(), "Process::Process ioctl");
                r = openpty(&parent_pty, &child_pty, nullptr, &term, &win);
                if (r == -1) throw std::system_error(errno, std::system_category(), "Process::Process openpty");
            }
            fds[num] = parent_pty;
            child_fds[num] = child_pty;
            break;
        default:
            throw std::invalid_argument("fd mode must be one of INHERIT, PIPE, or PTY");
        }
    std::cerr << fn << " argv =";
    for (char*const* arg = argv; *arg; ++ arg) {
        std::cerr << " " << *arg;
    }
    std::cerr << " envp = ";
    if (!envp) std::cerr << "0"; else for (char*const* env = envp; *env; ++ env) {
        std::cerr << " " << *env;
    }
    std::cerr << std::endl;
    child_pid = fork();
    if (child_pid == -1) throw std::system_error(errno, std::system_category(), "Process::Process fork");
    if (child_pid == 0) {
        /* child */
        for (int num = 0; num < 3; ++ num) {
            if (fds[num] != num) {
                r = close(fds[num]);
                if (r == -1) _exit(errno);//throw std::system_error(errno, std::system_category());
                r = dup2(child_fds[num],num);
                if (r == -1) _exit(errno);//throw std::system_error(errno, std::system_category());
                r = close(child_fds[num]);
                if (r == -1) _exit(errno);//throw std::system_error(errno, std::system_category());
            }
        }

        /*
        prctl(PR_SET_PDEATHSIG, SIGTERM);

        struct sigaction sig_ign;
        sig_ign.sa_handler = SIG_IGN;
        sig_ign.sa_flags = 0;
        sigemptyset(&sig_ign.sa_mask);
        sigaction(SIGINT, &sig_ign, nullptr);
        sigaction(SIGHUP, &sig_ign, nullptr);
        */

        r = execve(fn, argv, envp);
        _exit(errno);
    } else {
        /* parent */
        try {
            for (int num = 0; num < 3; ++ num) {
                if (fds[num] != num) {
                    r = close(child_fds[num]);
                    if (r == -1) throw std::system_error(errno, std::system_category());
                    files[num] = fdopen(fds[num], num?"rb":"wb");
                    if (!files[num]) throw std::system_error(errno, std::system_category());
                }
            }
        } catch (...) {
            /* figure out what to do with child here */
            throw;
        }
    }
}

/*
bool Process::set_blocking(int fd, bool blocking)
{
    fd = fds[fd];
    int flags = fcntl(fd, F_GETFL);
    bool prev_state = flags & O_NONBLOCK;
    if (flags == -1) throw std::invalid_argument("Process::set_blocking fcntl F_GETFL");
    if (prev_state != blocking) {
        int r = fcntl(fd, F_SETFL, flags ^ O_NONBLOCK;
        if (r == -1) throw std::invalid_argument("Process::set_blocking fcntl F_SETFL");
    }
    return prev_state;
}
*/

void Process::write(std::string_view data)
{
    int fd = 0;
    if (fds[fd] == fd) throw std::invalid_argument("write to invalid fd");
    size_t r = fwrite(data.data(), 1, data.size(), (FILE*)files[fd]);
    if (r != data.size()) throw std::system_error(errno, std::system_category());
    fflush((FILE*)files[fd]);
}

int Process::wait(int ms)
{
    auto deadline = ms == -1 ? std::chrono::steady_clock::time_point::max() : (std::chrono::steady_clock::now() + std::chrono::milliseconds(ms));
    std::unique_ptr<void,void(*)(void*)> epoll_fd(nullptr, (void(*)(void*))close);
    struct epoll_event events[2] = {
        {
            .events = EPOLLIN,
            .data = { .fd = 1 }
        },
        {
            .events = EPOLLIN,
            .data = { .fd = 2 }
        }
    };
    if (avail_needslock(1)) return 1;
    if (avail_needslock(2)) return 2;
    if (!epoll_fd) {
        intptr_t r = epoll_create1(0);
        if (r == -1) throw std::system_error(errno, std::system_category(), "Process::wait epoll_create");
        r = epoll_ctl(r, EPOLL_CTL_ADD, fds[events[0].data.fd], &events[0]);
        if (r == -1) throw std::system_error(errno, std::system_category(), "Process::wait epoll_ctl");
        r = epoll_ctl(r, EPOLL_CTL_ADD, fds[events[1].data.fd], &events[1]);
        if (r == -1) throw std::system_error(errno, std::system_category(), "Process::wait epoll_ctl");
        epoll_fd.reset((void*)r);
    }

    while ("polling") {
        switch (epoll_wait((intptr_t)epoll_fd.get(), events, 2, ms)) {
        case -1:
            if (errno == EINTR && ms != -1) {
                auto now = std::chrono::steady_clock::now();
                if (deadline > now)
                    ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
                else
                    ms = 0;
                continue;
            }
            throw std::system_error(errno, std::system_category(), "Process::wait epoll_wait");
        case 0:
            throw std::system_error(ETIMEDOUT, std::system_category(), "Process::wait");
        default:
            for (int i = 0; i < 2; ++ i)
                if (events[i].events & EPOLLERR)
                    throw std::system_error(errno, std::system_category());
            for (int i = 0; i < 2; ++ i)
                if (events[i].events & EPOLLIN)
                    return events[i].data.u32;
            for (int i = 0; i < 2; ++ i)
                if (events[i].events & EPOLLHUP)
                    return events[i].data.u32;
            throw std::logic_error("no events despite epoll");
        }
    }
}

bool Process::avail_needslock(int fd)
{
    switch (fd) {
    case 0:
        return true;
    case 1:
    case 2:
        if (fds[fd] != fd) break;
    default:
        return false;
    }
    clearerr((FILE*)files[fd]);
    int c = getc((FILE*)files[fd]);
    if (c == EOF) {
        if (ferror((FILE*)files[fd])) throw std::system_error(errno, std::system_category());
        return false;
    } else {
        int r = ungetc(c, (FILE*)files[fd]);
        if (r == EOF) throw std::system_error(errno, std::system_category());
        return true;
    }
}

static thread_local size_t buffer_size = 64;
static thread_local
std::unique_ptr<char, void(*)(char*)> buffer((char*)malloc(buffer_size), (void(*)(char*))free);

std::string_view Process::read(size_t size, int fd)
{
    if ((fd<1||fd>2) || fds[fd] == fd) throw std::invalid_argument("read from invalid fd");

    if (buffer_size <= size) {
        buffer_size = size + 1;
        buffer.reset((char*)realloc(buffer.release(), buffer_size));
    }

    // the intent was to read up until size
    // but i didn't code for nonblocking at this time
    size_t r = 0;
    while ("reading") {
        r += fread(buffer.get()+r, 1, size-r, (FILE*)files[fd]);
        if (r >= size || feof((FILE*)files[fd])) break;
        if (errno != EINTR)
            throw std::system_error(errno, std::system_category(), "Process::read fread");
    }
    buffer.get()[r] = 0;
    return {buffer.get(), r};
}

std::string_view Process::readline(int fd, char delim)
{
    if ((fd<1||fd>2) || fds[fd] == fd) throw std::invalid_argument("read from invalid fd");

    char * buf = buffer.release();
    ssize_t line_size = getdelim(&buf, &buffer_size, delim, (FILE*)files[fd]);
    buffer.reset(buf);

    if (line_size == -1) throw std::system_error(errno, std::system_category(), "Process::readline getdelim");

    return {buffer.get(), (size_t)line_size};
}

std::string_view Process::readall(int fd)
{
    if ((fd<1||fd>2) || fds[fd] == fd) throw std::invalid_argument("read from invalid fd");

    size_t size = 0;
    while ("reading") {
        size += fread(buffer.get() + size, 1, buffer_size - size - 1, (FILE*)files[fd]);
        if (size < buffer_size - 1) break;
        buffer_size *= 2;
        buffer.reset((char*)realloc(buffer.release(), buffer_size));
    }

    if (!feof((FILE*)files[fd])) throw std::system_error(errno, std::system_category(), "Process::readall fread");

    buffer.get()[size] = 0;
    return {buffer.get(), size};
}

Process::~Process()
{
    for (int num = 0; num < 3; ++ num) {
        if (fds[num] != num) {
            fclose((FILE*)files[num]);
        }
    }
}

#include <iostream>
std::string Process::run_impl(std::string_view input, char const*fn, char*const argv[], char*const envp[])
{
    Process process(PIPE, PIPE, INHERIT, fn, argv, envp);
    process.write(input);
    return std::string(process.readall());
}
#if 0
std::string Process::run_impl(std::string_view input, char const*fn, char*const argv[], char*const envp[])
{
    std::array<std::array<int, 2>, 3> pipes;
    pid_t pid;
    int status;
    for (auto & p : pipes)
        if (pipe(p.data()) != 0)
            throw std::system_error(errno, std::system_category());
    pid = fork();
    if (pid == -1) throw std::system_error(errno, std::system_category());
    if (pid == 0) {
        /* child */
        for (size_t i = 0; i < pipes.size(); ++ i) {
            close(pipes[i][i?0:1]);
            dup2(pipes[i][i?1:0],i);
            close(pipes[i][i?1:0]);
        }
        status = execve(fn, argv, envp);
        throw std::system_error(status, std::system_category());
    } else {
        /* parent */
        for (int i = 0; i < 3; ++ i)
            close(pipes[i][i?1:0]);

        int len = ::write(pipes[0][1], input.data(), input.size());
        if (len != (int)input.size())
            throw std::runtime_error("Failed to write input to subprocess");
        close(pipes[0][1]);

        std::string output, error;
        {
            std::array<char, 65536> buf;
            while ((len = read(pipes[1][0], buf.data(), buf.size())) > 0)
                output.append(buf.data(), len);
            close(pipes[1][0]);
            while ((len = read(pipes[2][0], buf.data(), buf.size())) > 0)
                error.append(buf.data(), len);
            close(pipes[2][0]);
        }

        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status)) {
            if (WTERMSIG(status)) {
                throw std::runtime_error("child process terminated by signal " + std::to_string(WTERMSIG(status)) + error);
            } else if (WCOREDUMP(status)) {
                throw std::runtime_error("child process terminated with core dump" + error);
            } else if (errno != 0) {
                throw std::system_error(errno, std::system_category());
            } else {
                throw std::runtime_error("child process terminated abnormally" + error);
            }
        }
        if (WEXITSTATUS(status)) throw std::runtime_error(error);
        if (!output.size()) {
            throw std::runtime_error("nothing on stdout of child process. stderr: " + error);
        }
        return output;
    }
}
#endif

/*
    The plan now is to create a general launcher, where stdin/stdout/stderr can
    be any of dup'd, pty'd, or pipe'd.
*/

#if 0
// one of the approaches opens 3 pipes which propagated the fd information
// to both processes, which then engage the fds.
// the other approach opens a pty fd, which is used by the parent process
// to engage with the subprocess.

// so if the interface were somehow reoriented such that the child process's
// spawn were an outer function, it's a little confusing because different
// initial information happens prior to the fork, different setup.
// in fact, the fork calls are different.
// but, both setups are actually small enough to be made concise.

#include <system_error>
#include <termios.h>
#include <pty.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/wait.h>

class RawMode
{
public:
    RawMode(int pty)
    : pty(pty)
    {
        tcgetattr(pty, &orig_termios);
        struct termios raw_termios = orig_termios;
        raw_termios.c_lflag &= ~(ICANON | ECHO);
        raw_termios.c_cc[VMIN] = 1;
        raw_termios.c_cc[VTIME] = 0;
        tcsetattr(pty, TCSANOW, &raw_termios);
    }
    ~RawMode()
    {
        tcsetattr(pty, TCSANOW, &orig_termios);
    }
private:
    int pty;
    struct termios orig_termios;
};

#include <array>
#include <memory>
#include <cstdio>
#include <tuple>
template <typename... Params>
std::tuple<int,std::string,std::string> run(std::string_view input, Params... params)
{
    std::array<std::array<int, 2>, 3> pipes;
    for (auto & p : pipes)
        if (pipe(p.data()) != 0) throw std::system_error(errno, std::system_category());
    pid_t pid = fork();
    if (pid == -1) throw std::system_error(errno, std::system_category());
    if (pid == 0) {
        /* child */
        close(pipes[0][1]); close(pipes[1][0]); close(pipes[2][0]);
        dup2(pipes[0][0], 0); dup2(pipes[1][1], 1); dup2(pipes[2][1], 2);
        close(pipes[0][0]); close(pipes[1][1]); close(pipes[2][1]);
        execl(params..., nullptr); /* noreturn */
        throw std::system_error(errno, std::system_category());
    } else {
        /* parent */
        close(pipes[0][0]); close(pipes[1][1]); close(pipes[2][1]);
        ssize_t len = write(pipes[0][1], input.data(), input.size());
        close(pipes[0][1]);

        std::string output, error;
        std::array<char, 1024> buf;
        while ((len = read(pipes[1][0], buf.data(), buf.size())) > 0) {
            output.append(buf.data(), len);
        }
        close(pipes[1][0]);
        while ((len = read(pipes[2][0], buf.data(), buf.size())) > 0) {
            error.append(buf.data(), len);
        }
        close(pipes[2][0]);
        close(pipes[1][0]);
        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status)) throw std::system_error(errno, std::system_category());
        //if (!error.empty())
        //    throw std::runtime_error("subproc produced error output: " + error);
        return {WEXITSTATUS(status), output, error};
    }
}

template <typename... Params>
int launch(Params... params)
{
    int pty, status;
    pid_t pid = forkpty(&pty, 0, 0, 0);
    if (pid == -1) throw std::system_error(errno, std::system_category());
    if (!pid) {
        /* child process */
        execl(params..., (char*)0); /* noreturn */
        throw std::system_error(errno, std::system_category()); 
    } else {
        /* parent process */
        epoll_event ev;
        int efd = epoll_create1(0);
        if (efd == -1) throw std::system_error(errno, std::system_category()); 
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = pty;
        if (epoll_ctl(efd, EPOLL_CTL_ADD, pty, &ev) == -1)
            throw std::system_error(errno, std::system_category()); 
        ev.data.fd = STDIN_FILENO;
        if (epoll_ctl(efd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) == -1)
            throw std::system_error(errno, std::system_category()); 
        while ("subprocess running") {
            char buf[1024*1024];
            int nev = epoll_wait(efd, &ev, 1, -1);
            if (nev == -1) throw std::system_error(errno, std::system_category()); 
            if (ev.data.fd == pty) {
                int len = read(pty, buf, sizeof(buf));
                if (len > 0)
                    write(STDOUT_FILENO, buf, len);
                else if (len == 0)
                    break;
                else
                    std::system_error(errno, std::system_category()); 
            } else if (ev.data.fd == STDIN_FILENO) {
                int len = read(STDIN_FILENO, buf, sizeof(buf));
                if (len > 0)
                    write(pty, buf, len);
                else if (len == 0)
                    break;
                else
                    std::system_error(errno, std::system_category()); 
            }
            if (waitpid(pid, &status, WNOHANG) == pid)
                break;
        }
        close(efd);
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status)) throw std::system_error(errno, std::system_category());
        return WEXITSTATUS(status);
    }
}
#endif

/*
#include <iostream>
int main() {
    //RawMode rawmode_in(STDIN_FILENO);
    //RawMode rawmode_out(STDOUT_FILENO);
    //RawMode rawmode_err(STDERR_FILENO);
    ////launch("/usr/local/bin/vim","vim");
    //launch("/usr/bin/bash","bash");
    auto result = Process::run("", "/usr/bin/ls", "ls", "-l");
    //std::cout << std::get<0>(result) << std::get<1>(result) << std::get<2>(result);
    std::cout << result;
}
*/

