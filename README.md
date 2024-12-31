# chimerash

Hook your shell to run commands remotely.

This is pre-alpha hobby tech-demo work for accessing a remote system in a faster-than-mosh kind of way.

The system injects a .so into the running shell, which hooks execve and dispatches commands to the remote server running on an sshfs mount.

It is only a very barebones demo that this is possible.

It is possible to make even very slow remotes appear quite fast.

Right now the code depends on https://github.com/pmem/syscall_intercept but other interception approaches (such as simple LD_PRELOAD) can be added by making a wrappers_*.cpp file for them.

Similarly the only mount used right now is https://github.com/libfuse/sshfs and the only injection approach right now is batch commands to https://sourceware.org/gdb/ , both of which are also dependencies.

## usage

As of 2024-12-31, the code can be tested using something like this:

    make test.so
    # note it's unlikely password login works atm so be sure to have public key authentication configured
    # also note sshfs takes many options that can significantly change experience.
    # on my very old version 2.10 the below existed. look for more options in newer versions.
    #   -d -o cache_timeout=3600 -o entry_timeout=3600 -o negative_timeout=3600 -o attr_timeout=3600 -o max_write=10000000000
    sshfs my_user@my_host:/ /my/mount/path
    bash
    . test.enable.source # tries to use gdb to inject .so into $$ (bash)
    cd /my/mount/path
    remoteexec # tries to place the user in their login folder on the local mount
    # here now run a binary that exists on the remote system, like ls -l or systemctl status
    exit

I've only tested this on one obscure system! It's just a proof of concept!
