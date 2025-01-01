#include "fs.hpp"

#include "process.hpp"

#include <string_view>

class SSHProcess : public Process
{
    friend class SSHFS;
public:
    /* show_banner would be better done by providing for extra args to ssh to make it interactive or not */
    SSHProcess(char*host, Process::fd_mode fd_modes[3], bool show_banner=false);

private:
    void send_cmd(std::string_view cmd);
    std::string_view get_cmd_output(std::string_view remove_suffix = "");

    std::string_view run(std::string_view cmd, std::string_view remove_suffix = "");
    std::string_view run(std::string_view chdir, std::string_view env, std::string_view cmd, std::string_view remove_suffix = "");
    
    Process::fd_mode fd_modes[3];

    std::string remote_pid_str;
    int remote_pid;
};

#include <memory>
class SSHFS : public FS
{
public:
    SSHFS(std::string_view path);

    RemoteMount const & get_mnt() const
    { return mnt; }

    std::string_view const remote_env() const { return _env; }
    std::string_view const remote_cwd() const { return _cwd; }

    //int run(std::string_view filename, char*const argv[], char*const envp[]);
    int run(std::string_view chdir, std::string_view env, std::string_view local_fn, char*const argv[], char*const envp[]);

private:
    RemoteMount mnt;
    static std::string_view const MNT_TYPE;

    std::unique_ptr<SSHProcess> run_process, status_process;
    std::string remote_fifo;

    std::string _env, _cwd;

    //std::unordered_map<std::array<Process::fd_mode,3>, std::unique_ptr<Process>> procs;
};
