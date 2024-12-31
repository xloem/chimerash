#pragma once

#include <string>

struct Mount
{
public:
    std::string fsname, dir, type, opts;
    static Mount const from_path(std::string_view const path);

	operator bool() const;
};

struct RemoteMount : Mount
{
public:
    RemoteMount(Mount && mnt, std::string && remote_dir, std::string && remote_envPATH);
    RemoteMount() = default;
    RemoteMount& operator=(RemoteMount &&) = default;

    std::string remote_to_local(std::string_view path) const;
    std::string local_to_remote(std::string_view path) const;

    std::string remote_dir;
    std::string remote_envPATH, envPATH;

private:
    std::string remote_prefix;
    std::string local_prefix;
};

class FS
{
public:
    virtual ~FS() {}
    virtual RemoteMount const & get_mnt() const = 0;
    virtual int run(std::string_view chdir, std::string_view env, std::string_view local_fn, char*const argv[], char*const envp[]) = 0;
    virtual std::string_view const remote_env() const { return {}; }
    virtual std::string_view const remote_cwd() const { return get_mnt().remote_dir; }

    static FS & load_or_get(std::string_view path = {});
    //static void unload(std::string_view path);


    static char const * cwd();
};
