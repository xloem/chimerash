#include "wrappers.hpp"

#include <iostream>
#include <syscall.h>

#include <libsyscall_intercept_hook_point.h>

int Wrapping::real_execve(char const*filename,char*const argv[],char*const envp[]) noexcept
{ return syscall_no_intercept(SYS_execve, filename, argv, envp); }

static int hook(long syscall_no,
                long arg0, long arg1, long arg2,
                long arg3, long arg4, long arg5,
                long*result)
{
    switch (syscall_no) {
    case SYS_execve:
        //std::cerr << "syscall_intercept execve " << (char const*)arg0 << std::endl;
        *result = wrapping.wrapped_execve((char const*)arg0,(char*const*)arg1,(char*const*)arg2);
        return 0;
    default:
        return 1;
    }
}


void __wrappers_init() noexcept
{
    if (syscall_hook_in_process_allowed()) {
        wrapping.init();
        intercept_hook_point = hook;
        wrapping.set_enabled(true);
    }
}
