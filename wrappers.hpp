#include <string_view>
#include <unistd.h>

extern "C" bool wrapping_set_path(char const * path);

class Wrapping
{
    friend int ::execve(const char*,char*const[],char*const[]) noexcept;
    friend bool wrapping_set_path(char const * path);
public:
    Wrapping();
    void init();
    ~Wrapping();

    //char const * const execfn;

    int real_execve(char const*filename,char*const argv[],char*const envp[]) noexcept;
    int real_execvpe(char const*filename,char*const argv[],char*const envp[]) noexcept;
    int wrapped_execve(char const*filename,char*const argv[],char*const envp[]) noexcept;

    void set_enabled(bool);
    inline bool get_init() { return shared; }
    inline bool get_enabled() { return get_init() ? shared->enabled : false; }
    class FS * get_FS() const { return fs; }

// so the idea of where to enable it isn't completely resolved
// when it's run now it can enable itself for the current folder
// but then how do we disable it?
    // i guess let's implement what there is right now
    // we can even listen on the pump thread if desired
        // umm it could check in get_enabled if it needs to start the pump.
            // but it's always in a fork process
                // we code open a pipe for every process ...
// for now it should just listen on the thing in question .. do the current folder

private:

    char const * dli_fname;
    unsigned long long st_ino;
    pid_t pid;
    class FS * fs;
    //void pump();
    //static void pump_handoff();
    //std::string_view recv();
    //void send(void const*data, size_t len);

    bool remove_from_ld_preload();

    //bool running;
    struct {
        bool enabled;
    }*shared;
    //int pipefd[2];
};

extern Wrapping wrapping;

#define execve ::wrapping.real_execve
