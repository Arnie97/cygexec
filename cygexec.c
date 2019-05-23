/*
  CygExec: Cygwin-style magic executable bits for FUSE

  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>
  Copyright (C) 2019       Arnie97 <arnie97@gmail.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#define FUSE_USE_VERSION 29

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <fuse.h>
#include <ulockmgr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#include <sys/file.h> /* flock(2) */

#define S(char_array) {sizeof(char_array) - 1, (char_array)}
static const struct str {
    size_t len;
    const char *buf;
} exec_magic[] = {
    S("\x7F" "ELF"),        /* Execute and Link Format */
    S("#!"),                /* Shebang line */
    S("MZ"),                /* DOS Executable / Windows PE */
    S("\xFE\xED\xFA\xCE"),  /* Mach-O 32-bit */
    S("\xCE\xFA\xED\xFE"),  /* Mach-O 32-bit swapped */
    S("\xFE\xED\xFA\xCF"),  /* Mach-O 64-bit */
    S("\xCF\xFA\xED\xFE"),  /* Mach-O 64-bit swapped */
};

static int is_executable(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd == -1)
        return 0;

    char buf[exec_magic->len + 1];
    buf[exec_magic->len] = 0;
    int res = pread(fd, buf, exec_magic->len, 0);
    close(fd);

    size_t i = sizeof exec_magic / sizeof *exec_magic;
    if (res != -1)
        while (i--)
            if (memcmp(buf, exec_magic[i].buf, exec_magic[i].len) == 0)
                return 1;
    return 0;
}

static int xmp_fgetattr(const char *path, struct stat *stbuf,
            struct fuse_file_info *fi)
{
    int res = fi? fstat(fi->fh, stbuf): lstat(path, stbuf);
    if (res == -1)
        return -errno;
    if (is_executable(path))
        stbuf->st_mode |= S_IXUSR | S_IXGRP | S_IXOTH;
    return 0;
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    return xmp_fgetattr(path, stbuf, NULL);
}

static int xmp_access(const char *path, int mask)
{
    int res;

    if (mask & X_OK && is_executable(path))
        mask &= ~X_OK;
    res = access(path, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
    int res;

    res = readlink(path, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

struct xmp_dirp {
    DIR *dp;
    struct dirent *entry;
    off_t offset;
};

static int xmp_opendir(const char *path, struct fuse_file_info *fi)
{
    int res;
    struct xmp_dirp *d = malloc(sizeof(struct xmp_dirp));
    if (d == NULL)
        return -ENOMEM;

    d->dp = opendir(path);
    if (d->dp == NULL) {
        res = -errno;
        free(d);
        return res;
    }
    d->offset = 0;
    d->entry = NULL;

    fi->fh = (unsigned long) d;
    return 0;
}

static struct xmp_dirp *get_dirp(struct fuse_file_info *fi)
{
    return (struct xmp_dirp *) (uintptr_t) fi->fh;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
               off_t offset, struct fuse_file_info *fi)
{
    struct xmp_dirp *d = get_dirp(fi);

    (void) path;
    if (offset != d->offset) {
        seekdir(d->dp, offset);
        d->entry = NULL;
        d->offset = offset;
    }
    while (1) {
        struct stat st;
        off_t nextoff;

        if (!d->entry) {
            d->entry = readdir(d->dp);
            if (!d->entry)
                break;
        }

        memset(&st, 0, sizeof(st));
        st.st_ino = d->entry->d_ino;
        st.st_mode = d->entry->d_type << 12;
        nextoff = telldir(d->dp);
        if (filler(buf, d->entry->d_name, &st, nextoff))
            break;

        d->entry = NULL;
        d->offset = nextoff;
    }

    return 0;
}

static int xmp_releasedir(const char *path, struct fuse_file_info *fi)
{
    struct xmp_dirp *d = get_dirp(fi);
    (void) path;
    closedir(d->dp);
    free(d);
    return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;

    if (S_ISFIFO(mode))
        res = mkfifo(path, mode);
    else
        res = mknod(path, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
    int res;

    res = mkdir(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_unlink(const char *path)
{
    int res;

    res = unlink(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rmdir(const char *path)
{
    int res;

    res = rmdir(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
    int res;

    res = symlink(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rename(const char *from, const char *to)
{
    int res;

    res = rename(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_link(const char *from, const char *to)
{
    int res;

    res = link(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
    int res;

    res = chmod(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;

    res = lchown(path, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
    int res;

    res = truncate(path, size);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_ftruncate(const char *path, off_t size,
             struct fuse_file_info *fi)
{
    int res;

    (void) path;

    res = ftruncate(fi->fh, size);
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2])
{
    int res;

    /* don't use utime/utimes since they follow symlinks */
    res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;

    return 0;
}
#endif

static int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int fd;

    fd = open(path, fi->flags, mode);
    if (fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
    int fd;

    fd = open(path, fi->flags);
    if (fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
            struct fuse_file_info *fi)
{
    int res;

    (void) path;
    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int xmp_read_buf(const char *path, struct fuse_bufvec **bufp,
            size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct fuse_bufvec *src;

    (void) path;

    src = malloc(sizeof(struct fuse_bufvec));
    if (src == NULL)
        return -ENOMEM;

    *src = FUSE_BUFVEC_INIT(size);

    src->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    src->buf[0].fd = fi->fh;
    src->buf[0].pos = offset;

    *bufp = src;

    return 0;
}

static int xmp_write(const char *path, const char *buf, size_t size,
             off_t offset, struct fuse_file_info *fi)
{
    int res;

    (void) path;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int xmp_write_buf(const char *path, struct fuse_bufvec *buf,
             off_t offset, struct fuse_file_info *fi)
{
    struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));

    (void) path;

    dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    dst.buf[0].fd = fi->fh;
    dst.buf[0].pos = offset;

    return fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
    int res;

    res = statvfs(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_flush(const char *path, struct fuse_file_info *fi)
{
    int res;

    (void) path;
    /* This is called from every close on an open file, so call the
       close on the underlying filesystem.  But since flush may be
       called multiple times for an open file, this must not really
       close the file.  This is important if used on a network
       filesystem like NFS which flush the data/metadata on close() */
    res = close(dup(fi->fh));
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    close(fi->fh);

    return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
             struct fuse_file_info *fi)
{
    int res;
    (void) path;

#ifndef HAVE_FDATASYNC
    (void) isdatasync;
#else
    if (isdatasync)
        res = fdatasync(fi->fh);
    else
#endif
        res = fsync(fi->fh);
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
static int xmp_fallocate(const char *path, int mode,
            off_t offset, off_t length, struct fuse_file_info *fi)
{
    (void) path;

    if (mode)
        return -EOPNOTSUPP;

    return -posix_fallocate(fi->fh, offset, length);
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
            size_t size, int flags)
{
    int res = lsetxattr(path, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
            size_t size)
{
    int res = lgetxattr(path, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
    int res = llistxattr(path, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
    int res = lremovexattr(path, name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

static int xmp_lock(const char *path, struct fuse_file_info *fi, int cmd,
            struct flock *lock)
{
    (void) path;

    return ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner,
               sizeof(fi->lock_owner));
}

static int xmp_flock(const char *path, struct fuse_file_info *fi, int op)
{
    int res;
    (void) path;

    res = flock(fi->fh, op);
    if (res == -1)
        return -errno;

    return 0;
}

static struct fuse_operations xmp_oper = {
    .getattr    = xmp_getattr,
    .fgetattr   = xmp_fgetattr,
    .access     = xmp_access,
    .readlink   = xmp_readlink,
    .opendir    = xmp_opendir,
    .readdir    = xmp_readdir,
    .releasedir = xmp_releasedir,
    .mknod      = xmp_mknod,
    .mkdir      = xmp_mkdir,
    .symlink    = xmp_symlink,
    .unlink     = xmp_unlink,
    .rmdir      = xmp_rmdir,
    .rename     = xmp_rename,
    .link       = xmp_link,
    .chmod      = xmp_chmod,
    .chown      = xmp_chown,
    .truncate   = xmp_truncate,
    .ftruncate  = xmp_ftruncate,
#ifdef HAVE_UTIMENSAT
    .utimens    = xmp_utimens,
#endif
    .create     = xmp_create,
    .open       = xmp_open,
    .read       = xmp_read,
    .read_buf   = xmp_read_buf,
    .write      = xmp_write,
    .write_buf  = xmp_write_buf,
    .statfs     = xmp_statfs,
    .flush      = xmp_flush,
    .release    = xmp_release,
    .fsync      = xmp_fsync,
#ifdef HAVE_POSIX_FALLOCATE
    .fallocate  = xmp_fallocate,
#endif
#ifdef HAVE_SETXATTR
    .setxattr   = xmp_setxattr,
    .getxattr   = xmp_getxattr,
    .listxattr  = xmp_listxattr,
    .removexattr    = xmp_removexattr,
#endif
    .lock       = xmp_lock,
    .flock      = xmp_flock,

    .flag_nullpath_ok = 1,
#if HAVE_UTIMENSAT
    .flag_utime_omit_ok = 1,
#endif
};

int main(int argc, char *argv[])
{
    if ((getuid() == 0) || (geteuid() == 0)) {
        fputs("Do not run FUSE in privileged mode!", stderr);
        return 1;
    }
    umask(0);
    return fuse_main(argc, argv, &xmp_oper, NULL);
}
