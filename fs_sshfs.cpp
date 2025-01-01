#include "fs_sshfs.hpp"
#include "process.hpp"

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <iostream>
#include <ranges>
#include <sstream>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

std::string_view const SSHFS::MNT_TYPE = "fuse.sshfs";

SSHProcess::SSHProcess(char*host, Process::fd_mode fd_modes[3], bool show_banner)
: Process(fd_modes[0], fd_modes[1], fd_modes[2], "/usr/bin/env", std::to_array<char*>({(char*)"env", (char*)"ssh", host, nullptr}).data(), 0),
  fd_modes{fd_modes[0], fd_modes[1], fd_modes[2]}
{
    if (fd_modes[0] == Process::PIPE) {
        write("PS1=''\n");
    }
    if (fd_modes[0] == Process::PIPE && fd_modes[1] == Process::PIPE) {
        write("echo -ne '\\0'\n");
        auto banner = readline(1,'\0');
        banner.remove_suffix(1);
        if (show_banner) std::cerr << banner;

        remote_pid_str = run("echo -n $$");
        auto parsing = std::from_chars(remote_pid_str.data(), &*remote_pid_str.end(), remote_pid);
        if (parsing.ec != std::errc() || parsing.ptr != &*remote_pid_str.end() || !remote_pid_str.size())
            throw std::runtime_error("failed parsing remote pid " + std::make_error_code(parsing.ec).message());
    } else {
        remote_pid = -1;
    }
}

void SSHProcess::send_cmd(std::string_view cmd)
{
    if (fd_modes[1] == Process::PIPE) {
        //     v-  run cmd, output into O  -v             v-     v- the 8-char hex length of the output
        write("O=\"$("); write(cmd); write(")\"\nprintf %08x%s ${#O} \"$O\"\n");
        //                                  then print       ^-         ^- then the actual output
    } else {
        write(cmd); write("\n");
    }
}

std::string_view SSHProcess::get_cmd_output(std::string_view remove_suffix)
{
    if (fd_modes[1] != Process::PIPE) return {};

    uint64_t result_len;
    std::string_view result;

    auto lenstr = read(8);
    auto parsing = std::from_chars(lenstr.data(), lenstr.data()+8, result_len, 16);
    if (parsing.ec != std::errc() || parsing.ptr != lenstr.data()+8)
        throw std::runtime_error("failed parsing length of remote output " + std::make_error_code(parsing.ec).message());

    result = read(result_len);

    if (remove_suffix.size() && result.ends_with(remove_suffix))
        result.remove_suffix(remove_suffix.size());

    return result;
}

std::string_view SSHProcess::run(std::string_view cmd, std::string_view remove_suffix)
{
    send_cmd(cmd);
    return get_cmd_output(remove_suffix);
}

std::string_view SSHProcess::run(std::string_view chdir, std::string_view env, std::string_view cmd, std::string_view remove_suffix)
{
    if (chdir.size()) {
        write("cd '"); write(chdir); write("'\n");
    }
    if (env.size()) {
        write("export");
        for (std::ranges::subrange<const char*> const&var_assignment : env | std::views::split('\n')) {
            write(" '");
            write(std::string_view(var_assignment.begin(), var_assignment.end()));
        }
        write("'\n");
    }
    send_cmd(cmd);
    //this->cwd = chdir;
    //this->env = env;
    return get_cmd_output(remove_suffix);
}

#include <iostream>
SSHFS::SSHFS(std::string_view path)
{
    Mount mnt = Mount::from_path(path);
    if (mnt.type != MNT_TYPE)
        throw std::invalid_argument((std::stringstream{}<<path<<" is on a "<<mnt.type<<" mount rather than a "<<MNT_TYPE<<" mount.").str());

    std::string remote_host{std::string_view(mnt.fsname).substr(0, mnt.fsname.find(':'))};
    std::string_view remote_dir{std::string_view(mnt.fsname).substr(remote_host.size()+1)};

    std::cout << remote_host << " " << remote_dir << std::endl;


    std::cerr << "Connecting to " << remote_host << " .." << std::endl;
    status_process = std::make_unique<SSHProcess>(&remote_host[0], std::to_array({Process::PIPE, Process::PIPE, Process::INHERIT}).data());

    remote_fifo = "/tmp/." + status_process->remote_pid_str + ".fifo";

    status_process->write("trap 'rm "+remote_fifo+"' EXIT\n");
    status_process->send_cmd("mkfifo "+remote_fifo);
    status_process->send_cmd("set");
    status_process->send_cmd("pwd");

    run_process = std::make_unique<SSHProcess>(&remote_host[0], std::to_array({Process::PIPE, Process::INHERIT, Process::INHERIT}).data());

    status_process->get_cmd_output();
    run_process->send_cmd("echo -n $$>"+remote_fifo);

    _env = status_process->get_cmd_output();
    _cwd = status_process->get_cmd_output("\n");

    run_process->remote_pid_str = status_process->run("cat "+remote_fifo);
    run_process->remote_pid = std::stoi(run_process->remote_pid_str);

    std::string_view remote_envPATH;
    auto vars = _env | std::views::split('\n');
    for (auto subrange : vars) {
        std::string_view var(subrange.begin(), subrange.end());
        if (var.starts_with("PATH=")) {
            remote_envPATH = var.substr(strlen("PATH="));
            break;
        }
    }

    this->mnt = std::move(RemoteMount(std::move(mnt), std::string(remote_dir), std::string(remote_envPATH)));

    std::cout << "Remote PATH=" << this->mnt.remote_envPATH << std::endl;
    std::cout << "Local PATH=" << this->mnt.envPATH << std::endl;
}

int SSHFS::run(std::string_view chdir, std::string_view env, std::string_view _filename, char*const argv[], char*const envp[])
{
    // run command remotely
    static thread_local std::string cmd;
    cmd = mnt.local_to_remote(_filename);
    while (*++argv) {
        cmd += " '";
        for (std::ranges::subrange<const char*> const&part_wout_quote : std::string_view(*argv) | std::views::split('\'')) {
            if (part_wout_quote.begin() > *argv) /* avoid writing '\'' at start */
                cmd += "'\\''";
            cmd += std::string_view(part_wout_quote.begin(), part_wout_quote.end());
        }
        cmd += "'";
    }
    // would it work to dup the process's stdin into our stdin?
    cmd += "</dev/null";
    cmd += ";echo -n $?>"+remote_fifo;
    run_process->run(chdir, env, cmd);

    // uhhh we're likely in a subprocess here!
    if (chdir.size()) _cwd = chdir;
    if (env.size()) _env = env;

    auto status_str = status_process->run("cat "+remote_fifo);

    int status;
    auto parsing = std::from_chars(status_str.begin(), status_str.end(), status);
    if (parsing.ec != std::errc() || parsing.ptr != status_str.end())
        throw std::runtime_error("failed parsing exit code " + std::make_error_code(parsing.ec).message());

    return status;
}

//int main(int argc, char**argv)
//{
//    SSHFS sshfs(argv[1]);
//}
