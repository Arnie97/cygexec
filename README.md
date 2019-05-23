# CygExec

## Problem
When a FAT formatted removable drive is mounted on Linux, all the scripts and binaries on it lack the execute permissions due to the fact that FAT does not support POSIX permission bits.

## Workarounds
Well, it's possible to run them like

    $ /lib64/ld-linux-x86-64.so.2 /media/fat_drive/binary.elf
    $ python3 /media/fat_drive/script.py

But that's verbose and inconvenient.

It's also possible to remount the drive with either `exec` or `showexec` option.
But `exec` is an overkill that makes everything executable, which is unfriendly to tab completions.
The `showexec` option is more thoughtful, as it works at file level; however, the executable bit is only based on file extensions - it's insane to rename `script.py` to `script.py.exe`, which would prevent the same script from running on Windows.

## Idea
To get the best of both worlds, [Cygwin provides a decent mount option named `cygexec`](https://cygwin.com/cygwin-ug-net/using.html#mount-table). It's based on magic bytes in file headers; thus it plays better with shebangs, and do not require extension names. To introduce the feature back to the Unix world, I modified [the pass-through example from `libfuse`](https://github.com/libfuse/libfuse/blob/fuse-2_9_bugfix/example/fusexmp_fh.c) a little bit to add proper permissions for executables in their `stat()` results.

## Get started

    $ gcc -Wall -Wextra -o cygexec cygexec.c `pkg-config fuse --cflags --libs` -lulockmgr
    $ ./cygexec /path/for/mount/point
