#include "wrappers.hpp"
#include "fs.hpp"
#undef execve

#include <cassert>
#include <cstring>
#include <iostream>
#include <ranges>
#include <system_error>
#include <thread>
#include <vector>
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

// defined first so ~Wrapping can join it before it is destroyed
//std::thread pump_thread;

Wrapping wrapping;
void __wrappers_init();

ino_t get_st_ino(char const*path)
{
    struct stat st;
    if (stat(path, &st) == -1)
        throw std::system_error(errno, std::system_category());
    return st.st_ino;
}

char const*get_dli_fname(void*func)
{
    Dl_info info;
    if (dladdr(func, &info) != 0)
        return info.dli_fname;
    else
        throw std::system_error(errno, std::system_category());
}

//void wrapping_pump_handoff() { wrapping.pump(); }

// so we only want wrapping constructed at all, if the check passes
Wrapping::Wrapping()
: fs(nullptr),
  shared(nullptr)
{
    std::cout << "construct" << std::endl;
    assert(this == &::wrapping);
    __wrappers_init();
}

void Wrapping::init()
{
    std::cout << "Launch !" << std::endl;
    if (shared) throw std::logic_error("init already called");
    dli_fname = ::get_dli_fname((void*)&__wrappers_init);
    st_ino = ::get_st_ino(dli_fname);
    pid = ::getpid();
    void*map = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == map)
        throw std::system_error(errno, std::system_category());
    shared = (decltype(shared))map;
    shared->enabled = false;
  //execve{(decltype(execve))dlsym(RTLD_NEXT, "execve")}//,
  //execfn((char const*)getauxval(AT_EXECFN)),
  //running(false)//,

#if 0
    //void*global_execve = dlsym(RTLD_DEFAULT, "execve");
    //if (global_execve != (void*)::execve) {
    //    std::cout << "We weren't first, somebody else has our handle. Hrm." << std::endl;
        Dl_info info;
        if (dladdr((void*)execve, &info) == 0)
            throw std::system_error(errno, std::system_category());
        void * handle = dlopen(info.dli_fname, /*RTLD_NOLOAD*/RTLD_LAZY|RTLD_NODELETE);
        if (handle == 0)
            throw std::runtime_error(std::string()+"got 0 handle for " + info.dli_fname);
        if (dlclose(handle) != 0)
            throw std::runtime_error(std::string()+"failed to close reopened handle for " + info.dli_fname + " ?");
        int ct = 0;
        while (dlclose(handle) == 0)
            ct += 1;
        if (ct == 0)
            throw std::runtime_error(std::string()+"failed to unload " + info.dli_fname);
        //auto global_execve = dlsym(RTLD_DEFAULT, "execve");
        //if (dlsym(RTLD_DEFAULT, "execve") != (void*)::execve)
        //    throw std::runtime_error(std::string()+"well i unloaded " + info.dli_fname + " but the func is now " + std::to_string((uintptr_t)global_execve));
        while (ct--) handle = dlopen(info.dli_fname, RTLD_LAZY);
        //if (dlsym(RTLD_DEFAULT, "execve") != (void*)::execve)
        //    throw std::runtime_error(std::string()+"after i reloaded " + info.dli_fname + " the func is now " + std::to_string((uintptr_t)global_execve));
        if (execve != (decltype(execve))dlsym(handle, "execve"))
            throw std::runtime_error(std::string()+"after i reloaded " + info.dli_fname + " the func address changed");
    //}
#endif
    
    //pipe(pipefd);
    //if ((void*)shared == MAP_FAILED)
    //    throw std::system_error(errno, std::system_category());
    //shared->enabled = true;
    //running = true;
    //pump_thread = std::thread(wrapping_pump_handoff);
}

void Wrapping::set_enabled(bool enabled)
{
    if (!shared) throw std::logic_error("init not called");
    shared->enabled = enabled;
    //if (enabled && getpid() == pid) {
    //}
}

extern "C" bool wrapping_set_path(char const *path)
{
    try {
        if (getpid() != wrapping.pid) throw std::logic_error("wrong pid to load filesystem");
        wrapping.fs = &FS::load_or_get(path);
        return true;
    } catch (std::exception const&e) {
        std::cerr << e.what() << std::endl;
        return false;
    }
}

bool Wrapping::remove_from_ld_preload()
{
    std::string ld_preload = getenv("LD_PRELOAD");
    std::string_view dli_fname = this->dli_fname;
    for (auto const & _submatch : ld_preload|std::views::split(':')) {
        std::string_view submatch(_submatch.begin(), _submatch.end());
        if (dli_fname == submatch) {
            auto start = submatch.begin() - ld_preload.data();
            auto end = submatch.end() - ld_preload.data() + 1;
            std::cerr << "LD_PRELOAD changed from " << ld_preload;
            ld_preload.erase(start, end);
            std::cerr << " to " << ld_preload << std::endl;
            setenv("LD_PRELOAD", ld_preload.c_str(), 1);
            return true;
        }
    }
    std::cerr << dli_fname << " NOT FOUND IN LD_PRELOAD what is going on." << std::endl;
    return false;
}

/*
void* read_fully(int fd, void*_buf, size_t ct)
{
    unsigned char * buf = (unsigned char*)_buf;   
    unsigned char * tail = buf + ct;
    while (buf != tail) {
        int ct_rd = read(fd, buf, ct);
        if (ct_rd > 0) {
            buf += ct_rd;
        } else {
            throw std::system_error(errno, std::system_category());
        }
    };
    return _buf;
}
std::string_view Wrapping::recv() {
    static std::vector<char> buf;
    static size_t len;
    read_fully(pipefd[0], &len, sizeof(len));
    buf.reserve(len);
    read_fully(pipefd[0], buf.data(), len);
    return {buf.data(), len};
}
void Wrapping::send(void const*data, size_t len)
{
    write(pipefd[1], &len, len);
    write(pipefd[1], data, len);
}
void Wrapping::pump()
{
    std::string_view cmd, param;
    while(running) {
        try {
            cmd = recv();
            param = recv();
            std::cout << "Received: " << cmd << " " << param << std::endl;
        } catch (const std::system_error& e) {
            std::cerr << "Error in " << dli_fname << " pipe: " << e.what() << std::endl;
        }
    }
}
*/

Wrapping::~Wrapping()
{
    if (getpid() == pid) {
        std::cerr << "bye!" << std::endl;
        //running = false;
        //close(pipefd[0]);
        //close(pipefd[1]);
        //pump_thread.join();
        if (shared)
            munmap(shared, sizeof(*shared));
    }
}

static thread_local bool do_not_wrap = false;

#include <iostream>

int Wrapping::real_execvpe(const char*filename, char*const argv[], char*const envp[]) noexcept
{
    do_not_wrap = true;
    int result = execvpe(filename, argv, envp);
    do_not_wrap = false;
    return result;
}

int Wrapping::wrapped_execve(const char*filename, char*const argv[], char*const envp[]) noexcept
{
    if (do_not_wrap) return real_execve(filename, argv, envp);

    //std::cerr << "hmm ..." << std::endl;
    if (get_st_ino(filename) == (ino_t)wrapping.st_ino) {
        std::cerr << "Hi !!" << std::endl;
        if (argv[1] && !argv[2] && (!strcmp(argv[1], "help") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
            std::cerr << "Usage:" << std::endl;
            std::cerr << wrapping.dli_fname << " enable # enable" << std::endl;
            std::cerr << wrapping.dli_fname << " local some/command [options...] # run a local command while enabled" << std::endl;
            std::cerr << wrapping.dli_fname << " path # get the remote execution path" << std::endl;
            std::cerr << wrapping.dli_fname << " env # get the current expected remote environment" << std::endl;
            std::cerr << wrapping.dli_fname << " cwd # get the current expected remote pwd" << std::endl;
            std::cerr << wrapping.dli_fname << " disable # disable" << std::endl;
        } else if (argv[1] && !argv[2] && !strcmp(argv[1], "cwd")) {
            class FS * fs = wrapping.get_FS();
            if (fs == 0) {
                std::cerr << "No FS." << std::endl;
                _exit(-1);
            }
            std::cout << fs->get_mnt().remote_to_local(fs->remote_cwd()) << std::endl;
            _exit(0);
        } else if (argv[1] && !argv[2] && !strcmp(argv[1], "env")) {
            class FS * fs = wrapping.get_FS();
            if (fs == 0) {
                std::cerr << "No FS." << std::endl;
                _exit(-1);
            }
            std::cout << fs->remote_env() << std::endl;
            _exit(0);
        } else if (argv[1] && !argv[2] && !strcmp(argv[1], "enable")) {
            /*
            std::string_view cwd;
            try {
                cwd = FS::cwd();
            } catch(std::system_error) {
                perror("getcwd");
                _exit(errno);
            }
            std::cerr << "Sending enable " << cwd << " to parent process." << std::endl;
            wrapping.send("enable", strlen("enable"));
            wrapping.send(cwd.data(), cwd.size());
            */if (wrapping.get_enabled()) {
                std::cerr << wrapping.dli_fname << " is already enabled but I'll rewrite the flag for your peace of mind." << std::endl;
                wrapping.set_enabled(true);
            } else {
                wrapping.set_enabled(true);
                std::cerr << wrapping.dli_fname << " enabled." << std::endl;
            }
        } else if (argv[1] && !argv[2] && !strcmp(argv[1], "disable")) {
            if (!wrapping.get_enabled()) {
                std::cerr << wrapping.dli_fname << " is already disabled but I'll reclear the flag for your peace of mind." << std::endl;
                wrapping.set_enabled(false);
            } else {
                wrapping.set_enabled(false);
                std::cerr << wrapping.dli_fname << " disabled." << std::endl;
            }
        } else if (argv[1] && argv[2] && !strcmp(argv[1], "local")) {
            /*if (!wrapping.shared->enabled) {
                std::cerr << wrapping.dli_fname << " is disabled." << std::endl;
            } else*/ {
                real_execvpe(argv[2], argv+2, envp); // calls execve
                perror(argv[2]);
                _exit(errno);
            }
        } else if (argv[1] && !argv[2] && !strcmp(argv[1], "path")) {
            class FS * fs = wrapping.get_FS();
            if (fs == 0) {
                std::cerr << "No FS." << std::endl;
                _exit(-1);
            }
            std::cout << fs->get_mnt().envPATH << std::endl;
            _exit(0);
        } else {
            std::cerr << "I don't understand !" << std::endl;
        }
        _exit(0);
    }
    if (wrapping.get_enabled() && wrapping.fs) {
        /*if (wrapping.shared->enabled) {
            std::cerr << "enabled !!" << std::endl;
            // might as well call ssh for everything
            // and use a command to run a local thing
        }*/
        ///*

        /*
        std::cerr << std::endl << "the execve wrapping is being called" << std::endl;
        std::cerr << "dli_fname = " << wrapping.dli_fname << std::endl;
        std::cerr << "filename = " << filename << std::endl;
        std::cerr << "argv =";
        for (char*const*item = argv; *item; ++item) {
            std::cerr << " " << *item;
        }
        std::cerr << std::endl;
        std::cerr << "envp = ";
        if (!envp)
            std::cerr << "0";
        else for (char*const*item = envp; *item; ++item) {
            std::cerr << " " << *item;
        }
        std::cerr << std::endl;
        */
        // .. it runs in a subprocess oopsies
        _exit(wrapping.fs->run(wrapping.fs->get_mnt().local_to_remote(FS::cwd()), {}, filename, argv, envp));
    } else {
        //*/
        return wrapping.real_execve(filename,argv,envp);
    }
}
