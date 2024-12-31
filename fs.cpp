#include "fs.hpp"
#include "fs_sshfs.hpp"

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <ranges>
#include <system_error>
#include <unordered_map>
#include <mntent.h>
#include <unistd.h>

class Mounts
{
public:
    Mounts(char const*path = "/proc/mounts", char const*mode = "r")
    : fp(setmntent(path, mode))
    { if (!fp) throw std::system_error(errno, std::system_category()); }

    Mount get() {
        struct mntent * ent = getmntent(fp);
        if (!ent) return {};
        return {
            .fsname = ent->mnt_fsname, .dir = ent->mnt_dir,
            .type = ent->mnt_type, .opts = ent->mnt_opts
        };
    }
    ~Mounts()
    { endmntent(fp); }

private:
    FILE * const fp;
};

Mount const Mount::from_path(std::string_view const _path)
{
    std::string path = std::filesystem::absolute(_path).lexically_normal().string();
    Mount deepest;
    Mounts mounts;
    for (Mount mnt = mounts.get(); mnt; mnt = mounts.get())
    {
        if (mnt.dir.size() > deepest.dir.size() && path.starts_with(mnt.dir)) {
            deepest = std::move(mnt);
        }
    }
    return deepest;
}

Mount::operator bool() const
{
	return fsname.size() || dir.size() || type.size() || opts.size();
}

RemoteMount::RemoteMount(Mount && mnt, std::string && remote_dir, std::string && remote_envPATH)
: Mount(mnt),
  remote_dir(remote_dir),
  remote_envPATH(remote_envPATH)
{
    // split PATH on :'s to get each item
    // then perform filepath manipulation to remove the remote mount path prefix and prefix the local mount path

    remote_prefix = std::filesystem::absolute(remote_dir).lexically_normal().string();
    local_prefix = std::filesystem::absolute(dir).lexically_normal().string();
    if (remote_prefix.ends_with('/')) remote_prefix = remote_prefix.substr(0,remote_prefix.size()-1);
    if (local_prefix.ends_with('/')) local_prefix = local_prefix.substr(0,local_prefix.size()-1);

    for (auto const&_entry : remote_envPATH | std::views::split(':')) {
        std::string entry(_entry.begin(), _entry.end());
        entry = std::filesystem::absolute(entry).lexically_normal().string();
        if (entry.starts_with(remote_prefix)) {
            if (envPATH.size())
                envPATH += ':';
            envPATH += local_prefix;
            envPATH += std::string_view(entry).substr(remote_prefix.size());
        }
    }
}

std::string RemoteMount::local_to_remote(std::string_view _path) const
{
    std::string path = std::filesystem::absolute(_path).lexically_normal().string();
    if (!path.starts_with(local_prefix))
        throw std::invalid_argument(path + " is not on remote mounted at " + local_prefix);
    return remote_prefix + path.substr(local_prefix.size());
}

std::string RemoteMount::remote_to_local(std::string_view _path) const
{
    std::string path = std::filesystem::absolute(_path).lexically_normal().string();
    if (!path.starts_with(remote_prefix))
        throw std::invalid_argument(path + " is not within mount of " + remote_prefix);
    return local_prefix + path.substr(remote_prefix.size());
}


#include <iostream>
std::unordered_map<std::string_view, std::unique_ptr<FS>>&fss() {
    static std::unordered_map<std::string_view, std::unique_ptr<FS>> impl;
    return impl;
}

FS & FS::load_or_get(std::string_view path)
{
    Mount mnt = Mount::from_path(path.size() ? path : cwd());
    auto it = fss().find(mnt.dir);
    if (it == fss().end()) {
        std::cerr << "fss.size() = " << fss().size() << " and " << mnt.dir << " wasn't found." << std::endl;
        std::unique_ptr<FS> fs = std::unique_ptr<FS>(new SSHFS(mnt.dir));
        assert(fs->get_mnt().dir == mnt.dir);
        it = fss().emplace_hint(it, fs->get_mnt().dir, std::move(fs));
    }
    return *it->second;
}

char const * FS::cwd()
{
    static thread_local size_t len = 16;
    static thread_local char * buf = new char[len];
    while("") {
        if (getcwd(buf, len)!=0)
            break;
        if (errno != ERANGE) {
            throw std::system_error(errno, std::system_category());
        }
        size_t new_len = len * 2;
        len = 0;
        delete [] buf;
        buf = new char[new_len];
        len = new_len;
    }
    return buf;
}
