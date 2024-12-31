#include "wrappers.hpp"

#include "fs.hpp"

#include <array>

#undef execve


void __wrappers_init() noexcept
{
    wrapping.init();
    wrapping.set_enabled(true);
    wrapping_set_path("/media/remote-extra");
}


int Wrapping::real_execve(const char*filename, char*const argv[], char*const envp[]) noexcept
{
    return execve(filename, argv, envp);
}

int main()
{
    FS & fs = *wrapping.get_FS();
    fs.run("/media/remote-extra/usr/bin/pwd", std::to_array({(char*)"pwd",(char*)nullptr}).data(),0);
}
