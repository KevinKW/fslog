/* vim: set expandtab ts=4 sw=4:                               */

/*-===========================================================-*/
/*  FSLOG: log the operations of given fs type                 */
/*                                                             */
/*  Author:                                                    */
/*        KevinKW                                              */
/*-===========================================================-*/

#include <linux/init.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/in.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/mount.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/backing-dev.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/statfs.h>
#include <linux/writeback.h>
#include <linux/mpage.h>
#include <linux/pagevec.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/nfs_fs.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");

MODULE_DESCRIPTION("Log FS operations of given fs type.");
MODULE_AUTHOR("Ckelviny@gmail.com");
MODULE_VERSION("1.0");

//#define FSLOG_DEBUG

/* Define log functions */
#define msg(logLevel, ...) printk(__VA_ARGS__)

#ifdef FSLOG_DEBUG
#ifndef PRINT_FUNCTION
#define PRINT_FUNCTION
#endif
#endif

#ifdef PRINT_FUNCTION
#define kerr(fmt, args...) msg(3, KERN_ERR "FSLOG: (%s) " fmt, __FUNCTION__, ## args)
#define kwarn(fmt, args...) msg(4, KERN_WARNING "FSLOG: (%s) " fmt, __FUNCTION__, ## args)
#define kinfo(fmt, args...) msg(6, KERN_INFO "FSLOG: (%s) " fmt, __FUNCTION__, ## args)
#else
#define kerr(fmt, args...) msg(3, KERN_ERR "FSLOG: " fmt, ## args)
#define kwarn(fmt, args...) msg(4, KERN_WARNING "FSLOG: " fmt, ## args)
#define kinfo(fmt, args...) msg(6, KERN_INFO "FSLOG: " fmt, ## args)
#endif

#ifdef FSLOG_DEBUG
#define kdebug(fmt, args...) msg(7, KERN_DEBUG "FSLOG: (%lu:%s) " fmt, jiffies, __FUNCTION__, ## args)
#else
#define kdebug(fmt, args...)
#endif

#define LOG_LOOKUP     0x00000001
#define LOG_CREATE     0x00000002
#define LOG_LINK       0x00000004
#define LOG_UNLINK     0x00000008
#define LOG_SYMLINK    0x00000010
#define LOG_MKDIR      0x00000020
#define LOG_RMDIR      0x00000040
#define LOG_RENAME     0x00000080
#define LOG_GETATTR    0x00000100
#define LOG_SETATTR    0x00000200
#define LOG_OPEN       0x00000400
#define LOG_READ       0x00000800
#define LOG_WRITE      0x00001000
#define LOG_CLOSE      0x00004000
#define LOG_SEEK       0x00008000
#define LOG_FSYNC      0x00010000
#define LOG_FLUSH      0x00020000
#define LOG_READDIR    0x00040000
#define LOG_LOCK       0x00080000
#define LOG_FLOCK      0x00100000
#define LOG_MMAP       0x00200000
#define LOG_READLINK   0x00400000
#define LOG_FOLLOWLINK 0x00800000
#define LOG_PUTLINK    0x01000000
#define LOG_MOUNT      0x02000000
#define LOG_UMOUNT     0x04000000
#define log_ops_default \
    LOG_CREATE|LOG_LINK|LOG_UNLINK|LOG_SYMLINK \
    |LOG_MKDIR|LOG_RMDIR|LOG_RENAME|LOG_SETATTR \
    |LOG_OPEN|LOG_WRITE|LOG_READDIR|LOG_READLINK \
    |LOG_MOUNT|LOG_UMOUNT

static const char* op2str(unsigned long op)
{
    switch(op) {
        case LOG_LOOKUP:
            return "lookup";
        case LOG_CREATE:
            return "create";
        case LOG_LINK:
            return "link";
        case LOG_UNLINK:
            return "unlink";
        case LOG_SYMLINK:
            return "symlink";
        case LOG_MKDIR:
            return "mkdir";
        case LOG_RMDIR:
            return "rmdir";
        case LOG_RENAME:
            return "rename";
        case LOG_GETATTR:
            return "getattr";
        case LOG_SETATTR:
            return "setattr";
        case LOG_OPEN:
            return "open";
        case LOG_READ:
            return "read";
        case LOG_WRITE:
            return "write";
        case LOG_CLOSE:
            return "close";
        case LOG_SEEK:
            return "seek";
        case LOG_FSYNC:
            return "fsync";
        case LOG_FLUSH:
            return "flush";
        case LOG_READDIR:
            return "readdir";
        case LOG_LOCK:
            return "lock";
        case LOG_FLOCK:
            return "flock";
        case LOG_MMAP:
            return "mmap";
        case LOG_READLINK:
            return "readlink";
        case LOG_FOLLOWLINK:
            return "followlink";
        case LOG_PUTLINK:
            return "putlink";
        case LOG_MOUNT:
            return "mount";
        case LOG_UMOUNT:
            return "umount";
        default:
            return "unknown";
    }
    return "unknown";
}

static char *fstype = "nfs";
module_param(fstype, charp, S_IRUGO);
static char *logpath = "/var/log/fslog_nfs.log";
module_param(logpath, charp, S_IRUGO);
static unsigned long ops = log_ops_default;
module_param(ops, ulong, S_IRUGO);

static const struct inode_operations *orig_file_iop;
static const struct inode_operations *orig_dir_iop;
static const struct inode_operations *orig_slink_iop;
static struct inode_operations log_file_iop;
static struct inode_operations log_dir_iop;
static struct inode_operations log_slink_iop;

static const struct file_operations *orig_file_fop;
static const struct file_operations *orig_dir_fop;
static struct file_operations log_file_fop;
static struct file_operations log_dir_fop;

static int (*orig_get_sb)(struct file_system_type *, int, const char *, void *, struct vfsmount *);
static void (*orig_killsb)(struct super_block *);
static void log_patch_dir_ops(struct inode *inode);
static void log_patch_file_ops(struct inode *inode);
static void log_patch_slink_ops(struct inode *inode);
struct file_system_type *orig_fs_type;

static bool do_log = true;

#define log_buflen 12288 //4096 * 3
static char log_buffer[log_buflen];
static char log_path[4096];

// This function puts the dentry name into buf until get root or no buf available
static char *__get_path(struct dentry *dentry, char *buf, int len)
{
    char *end = buf+len;
    char *path;
    int namelen;

    end--;
    *end = '\0';
    len--;

    if (len < 1)
        goto toolong;

    path = end - 1;
    *path = '/';

    while (1) {
        struct dentry *parent;

        if (IS_ROOT(dentry))
            break;

        parent = dentry->d_parent;

        prefetch(parent);
        namelen = dentry->d_name.len;
        len -= namelen + 1;
        if (len < 0)
            goto toolong;
        end -= namelen;
        memcpy(end, dentry->d_name.name, namelen);
        *--end = '/';
        path = end;
        dentry = parent;
    }

    return path;
toolong:
    //return ERR_PTR(-ENAMETOOLONG);
    return "NAME_TOO_LONG";
}

static void gen_fix_log(unsigned long op, struct dentry *dentry, struct dentry *dentry2)
{
    int len;

    len = snprintf(log_buffer, log_buflen, "%lu|%u|%s|",
                   jiffies, current_fsuid(), op2str(op));
    if (dentry) {
        len += snprintf(log_buffer+len, log_buflen-len, "%s|", __get_path(dentry, log_path, 4096));
    }
    if (dentry2) {
        len += snprintf(log_buffer+len, log_buflen-len, "%s|", __get_path(dentry2, log_path, 4096));
    }
}

#define BUF_SIZE        (32<<10)
#define BUF_THRESHOLD   512
struct log_buf {
    char *buf;
    int buflen;
    int len;
};

static DEFINE_SPINLOCK(buflock);
static struct log_buf *working_buf = NULL;
static struct log_buf *standby_buf = NULL;
static struct log_buf *writing_buf = NULL;
static DECLARE_WAIT_QUEUE_HEAD(buf_waitq);
static DECLARE_WAIT_QUEUE_HEAD(buf_writeq);
static unsigned long next_write;

static void write_buf(struct work_struct *work)
{
    struct file *filp;
    loff_t pos = 0;
    mm_segment_t oldfs;
    int nwrite;

    filp = filp_open(logpath, O_CREAT|O_APPEND|O_WRONLY|O_LARGEFILE|O_SYNC, 0644);
    if (!filp) {
        kerr("Open file %s failed\n", logpath);
        goto out;
    }
    oldfs = get_fs();
    set_fs(get_ds());
    nwrite = vfs_write(filp, writing_buf->buf, writing_buf->buflen - writing_buf->len, &pos);
    set_fs(oldfs);
    if (nwrite < 0) {
        kerr("Write to file %s failed\n", logpath);
        goto out;
    }
    kdebug("Write to file %s nwrite %d\n", logpath, nwrite);

  out:
    spin_lock(&buflock);
    BUG_ON(standby_buf);
    writing_buf->len = writing_buf->buflen;
    standby_buf = writing_buf;
    writing_buf = NULL;
    spin_unlock(&buflock);
    wake_up(&buf_writeq);
}

static DECLARE_WORK(bufwork, write_buf);

static int log_alloc_bufs(void)
{
    struct log_buf *buf = NULL;
    buf = kmalloc(sizeof(*buf), GFP_KERNEL);
    if (!buf) {
        goto err;
    }

    buf->buf = kmalloc(BUF_SIZE, GFP_KERNEL);
    if (!buf->buf) {
        goto err;
    }
    buf->buflen = buf->len = BUF_SIZE;
    working_buf = buf;

    buf = kmalloc(sizeof(*buf), GFP_KERNEL);
    if (!buf) {
        goto err;
    }

    buf->buf = kmalloc(BUF_SIZE, GFP_KERNEL);
    if (!buf->buf) {
        goto err;
    }
    buf->buflen = buf->len = BUF_SIZE;
    standby_buf = buf;
    next_write = jiffies;
    return 0;

  err:
    if (buf) {
        if (buf->buf) {
            kfree(buf->buf);
        }
        kfree(buf);
    }
    if (working_buf) {
        if (working_buf->buf) {
            kfree(working_buf->buf);
        }
        kfree(working_buf);
    }
    kerr("Alloc log buf failed\n");
    return -ENOMEM;
}

static void log_free_bufs(void)
{
    if (working_buf) {
        if (working_buf->buf) {
            kfree(working_buf->buf);
        }
        kfree(working_buf);
    }
    if (standby_buf) {
        if (standby_buf->buf) {
            kfree(standby_buf->buf);
        }
        kfree(standby_buf);
    }
    if (writing_buf) {
        if (writing_buf->buf) {
            kfree(writing_buf->buf);
        }
        kfree(writing_buf);
    }
}

static struct log_buf *log_get_buf(void)
{
    struct log_buf *buf = ERR_PTR(-EBUSY);
    int ret;

    for (;;) {
        spin_lock(&buflock);
        if (working_buf) {
            buf = working_buf;
            working_buf = NULL;
            spin_unlock(&buflock);
            break;
        }
        spin_unlock(&buflock);

        ret = wait_event_interruptible(buf_waitq, working_buf);
        if (ret) {
            break;
        }
    }

    return buf;
}

static void log_issue_write(struct log_buf *buf)
{
  retry:
    next_write = jiffies + HZ;
    spin_lock(&buflock);
    if (!writing_buf) {
        BUG_ON(!standby_buf);
        BUG_ON(working_buf);
        writing_buf = buf;
        working_buf = standby_buf;
        standby_buf = NULL;
        spin_unlock(&buflock);
        wake_up(&buf_waitq);
        schedule_work(&bufwork);
    } else {
        BUG_ON(standby_buf);
        spin_unlock(&buflock);
        wait_event_interruptible(buf_writeq, !writing_buf);
        goto retry;
    }
}

static void log_put_buf(struct log_buf *buf)
{
    if ((buf->len <= BUF_THRESHOLD) ||
            (time_after(jiffies, next_write))) {
        log_issue_write(buf);
    } else {
        spin_lock(&buflock);
        BUG_ON(working_buf);
        working_buf = buf;
        spin_unlock(&buflock);
        wake_up(&buf_waitq);
    }
}


/* The function is protected by working_buf is null */
static void log_op_internal(unsigned long op, struct dentry *dentry, struct dentry *dentry2, const char *fmt, va_list args)
{
    struct log_buf *buf;
    char *start;
    int len;

    if (!(op&ops)) {
        return;
    }

    buf = log_get_buf();
    if (IS_ERR(buf)) {
        kerr("Get log_buf failed\n");
        return;
    }

    gen_fix_log(op, dentry, dentry2);
    start = buf->buf + buf->buflen - buf->len;
    len = snprintf(start, buf->len, "%s", log_buffer);

    if (buf->len > len) {
        len += vsnprintf(start+len, buf->len-len, fmt, args);
    }
    start[len] = '\0';

    kdebug("%s", start);
    if (do_log) {
        buf->len -= len;
    }

    log_put_buf(buf);
}

static void log_op(unsigned long op, struct dentry *dentry, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_op_internal(op, dentry, NULL, fmt, args);
    va_end(args);
}

static void log_op2(unsigned long op, struct dentry *dentry, struct dentry *dentry2, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_op_internal(op, dentry, dentry2, fmt, args);
    va_end(args);
}

static inline const struct inode_operations *get_orig_iop(struct inode *inode)
{
    if (S_ISDIR(inode->i_mode)) {
        return orig_dir_iop;
    } else if (S_ISREG(inode->i_mode)) {
        return orig_file_iop;
    } else if (S_ISLNK(inode->i_mode)) {
        return orig_slink_iop;
    }

    return NULL;
}

static inline const struct file_operations *get_orig_fop(struct file *filp)
{
    if (S_ISDIR(filp->f_dentry->d_inode->i_mode)) {
        return orig_dir_fop;
    } else if (S_ISREG(filp->f_dentry->d_inode->i_mode)) {
        return orig_file_fop;
    }

    return NULL;
}

static inline void log_do_patch(struct inode *inode)
{
    if (S_ISDIR(inode->i_mode)) {
        log_patch_dir_ops(inode);
    } else if (S_ISREG(inode->i_mode)) {
        log_patch_file_ops(inode);
    } else if (S_ISLNK(inode->i_mode)) {
        log_patch_slink_ops(inode);
    }
}

static inline const unsigned char *get_dentry_name(struct dentry *dentry)
{
    if (IS_ROOT(dentry)) {
        return "/";
    }
    return dentry->d_name.name;
}

static struct dentry *log_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd)
{
    struct dentry *d;
    d = orig_dir_iop->lookup(dir, dentry, nd);

    if (IS_ERR(d)) {
        //log_op(LOG_LOOKUP, dentry, "Doing lookup name \"%s\" in dir %p(ino:%lu) ret %ld\n", get_dentry_name(dentry), dir, dir->i_ino, PTR_ERR(d));
        log_op(LOG_LOOKUP, dentry, "(%ld)\n", PTR_ERR(d));
        goto out;
    }

    if (dentry->d_inode) {
        //log_op(LOG_LOOKUP, dentry, "Doing lookup name \"%s\" in dir %p(ino:%lu) found\n", get_dentry_name(dentry), dir, dir->i_ino);
        log_op(LOG_LOOKUP, dentry, "found (ino:%lu)\n", dentry->d_inode->i_ino);
        log_do_patch(dentry->d_inode);
    } else {
        log_op(LOG_LOOKUP, dentry, "not found\n");
    }

  out:
    return d;
}

static void *log_follow_link(struct dentry *dentry, struct nameidata *nd)
{
    void *p;

    p = orig_slink_iop->follow_link(dentry, nd);

    log_op(LOG_FOLLOWLINK, dentry, "(%d)\n", IS_ERR(p)?PTR_ERR(p):0);

    return p;
}

static int log_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
    int ret;

    ret = orig_slink_iop->readlink(dentry, buffer, buflen);

    //log_op(LOG_READLINK, dentry, "Doing readlink for dentry name %s|(%d)\n", get_dentry_name(dentry), ret);
    log_op(LOG_READLINK, dentry, "%s||(%d)\n", ret?"error":buffer, ret);

    return ret;
}

static void log_put_link(struct dentry *dentry, struct nameidata *nd, void *cookie)
{
    //log_op(LOG_PUTLINK, dentry, "Doing put link for dentry name %s\n", get_dentry_name(dentry));
    log_op(LOG_PUTLINK, dentry, "\n");

    return orig_slink_iop->put_link(dentry, nd, cookie);
}

static int log_create(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd)
{
    int ret;

    ret = orig_dir_iop->create(dir, dentry, mode, nd);

    if (!ret && dentry->d_inode) {
        log_do_patch(dentry->d_inode);
        log_op(LOG_CREATE, dentry, "success (ino:%lu)\n", dentry->d_inode->i_ino);
    } else {
        log_op(LOG_CREATE, dentry, "(%d)\n", ret);
    }

    //log_op(LOG_CREATE, dentry, "Doing create name %s in dir %p(ino:%lu)|(%d)\n", get_dentry_name(dentry), dir, dir->i_ino, ret);

    return ret;
}

static int log_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
    int ret;

    ret = orig_dir_iop->link(old_dentry, dir, new_dentry);
    if (!ret && new_dentry->d_inode) {
        log_do_patch(new_dentry->d_inode);
    }

    log_op2(LOG_LINK, old_dentry, new_dentry, "Doing link from %s to %s in dir %p(ino:%lu)|(%d)\n",
            get_dentry_name(old_dentry), get_dentry_name(new_dentry),
            dir, dir->i_ino, ret);

    return ret;
}

static int log_unlink(struct inode *dir, struct dentry *dentry)
{
    int ret;

    ret = orig_dir_iop->unlink(dir, dentry);

    //log_op(LOG_UNLINK, dentry, "Doing unlink name %s in dir %p(ino:%lu)|(%d)\n", get_dentry_name(dentry), dir, dir->i_ino, ret);
    log_op(LOG_UNLINK, dentry, "(%d)\n", ret);

    return ret;
}

static int log_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
    int ret;

    ret = orig_dir_iop->symlink(dir, dentry, symname);

    //log_op(LOG_SYMLINK, dentry, "Doing soft link from %s to %s in dir %p(ino:%lu)|(%d)\n", get_dentry_name(dentry), symname, dir, dir->i_ino, ret);
    log_op(LOG_SYMLINK, dentry, "link to %s|(%d)\n", symname, ret);

    if (!ret && dentry->d_inode) {
        log_patch_slink_ops(dentry->d_inode);
    }

    return ret;
}

static int log_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
    int ret;

    ret = orig_dir_iop->mkdir(dir, dentry, mode);

    //log_op(LOG_MKDIR, dentry, "Doing mkdir name %s in dir %p(ino:%lu)|(%d)\n", get_dentry_name(dentry), dir, dir->i_ino, ret);
    log_op(LOG_MKDIR, dentry, "(%d)\n", ret);

    if (!ret && dentry->d_inode) {
        log_patch_dir_ops(dentry->d_inode);
    }

    return ret;
}

static int log_rmdir(struct inode *dir, struct dentry *dentry)
{
    int ret;

    ret = orig_dir_iop->rmdir(dir, dentry);

    //log_op(LOG_RMDIR, dentry, "Doing rmdir name %s in dir %p(ino:%lu)|(%d)\n", get_dentry_name(dentry), dir, dir->i_ino, ret);
    log_op(LOG_RMDIR, dentry, "(%d)\n", ret);

    return ret;
}

static int log_rename(struct inode *old_dir, struct dentry *old_dentry,
        struct inode *new_dir, struct dentry *new_dentry)
{
    int ret;

    ret = orig_dir_iop->rename(old_dir, old_dentry, new_dir, new_dentry);

#if 0
    log_op2(LOG_RENAME, old_dentry, new_dentry,
            "Doing rename from %s in dir %p(ino:%lu) to %s in dir %p(ino:%lu)|(%d)\n",
            get_dentry_name(old_dentry), old_dir, old_dir->i_ino,
            get_dentry_name(new_dentry), new_dir, new_dir->i_ino,
            ret);
#endif
    log_op2(LOG_RENAME, old_dentry, new_dentry, "(%d)\n", ret);

    return ret;
}

static int log_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
    int ret;

    ret = get_orig_iop(dentry->d_inode)->getattr(mnt, dentry, stat);

    //log_op(LOG_GETATTR, dentry, "Doing getattr from name %s|(%d)\n", get_dentry_name(dentry), ret);
    log_op(LOG_GETATTR, dentry, "(%d)\n", ret);

    return ret;
}

static int log_setattr(struct dentry *dentry, struct iattr *attr)
{
    int ret;

    ret = get_orig_iop(dentry->d_inode)->setattr(dentry, attr);

    //log_op(LOG_SETATTR, dentry, "Doing setattr to file name %s|(%d)\n", get_dentry_name(dentry), ret);
    log_op(LOG_SETATTR, dentry, "ia_valid %u|(%d)\n", attr->ia_valid, ret);

    return ret;
}

static loff_t log_llseek(struct file *filp, loff_t offset, int origin)
{
    loff_t ret;

    ret = get_orig_fop(filp)->llseek(filp, offset, origin);

    //log_op(LOG_SEEK, filp->f_dentry, "llseek file %s to offset %llu, origion %d ret %llu\n", get_dentry_name(filp->f_dentry), offset, origin, ret);
    log_op(LOG_SEEK, filp->f_dentry, "offset %llu, origion %d|(%llu)\n", offset, origin, ret);

    return ret;
}

static int log_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
    int ret;

    ret = orig_dir_fop->readdir(filp, dirent, filldir);

    //log_op(LOG_READDIR, filp->f_dentry, "Doing readdir for filp %p name %s|(%d)\n", filp, get_dentry_name(filp->f_dentry), ret);
    log_op(LOG_READDIR, filp->f_dentry, "(%d)\n", ret);

    return ret;
}

static ssize_t log_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
    ssize_t ret;

    ret = get_orig_fop(filp)->read(filp, buf, count, ppos);

    //log_op(LOG_READ, filp->f_dentry, "Read file %s buf %p, size %zd offset %llu ret %zd\n", get_dentry_name(filp->f_dentry), buf, count, *ppos, ret);
    log_op(LOG_READ, filp->f_dentry, "size %zd offset %llu|(%zd)\n", count, *ppos-count, ret);

    return ret;
}

static ssize_t log_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)
{
    ssize_t ret;

    ret = get_orig_fop(filp)->write(filp, buf, count, ppos);

    //log_op(LOG_WRITE, filp->f_dentry, "Write file %s buf %p, size %zd offset %llu ret %zd\n", get_dentry_name(filp->f_dentry), buf, count, *ppos, ret);
    log_op(LOG_WRITE, filp->f_dentry, "size %zd offset %llu|(%zd)\n", count, *ppos-count, ret);

    return ret;
}

static ssize_t log_aio_read(struct kiocb *iocb, const struct iovec *iov,
        unsigned long nr_segs, loff_t pos)
{
    ssize_t ret;

    ret = get_orig_fop(iocb->ki_filp)->aio_read(iocb, iov, nr_segs, pos);

#if 0
    log_op(LOG_READ, iocb->ki_filp->f_dentry, "AIO Read file %s iov %p, nr_segs %lu offset %llu, kiocb %p ret %zd\n",
            get_dentry_name(iocb->ki_filp->f_dentry),
            iov, nr_segs, pos, iocb, ret);
#endif
    log_op(LOG_READ, iocb->ki_filp->f_dentry, "offset %llu|(%zd)\n", pos, ret);

    return ret;
}

static ssize_t log_aio_write(struct kiocb *iocb, const struct iovec *iov,
        unsigned long nr_segs, loff_t pos)
{
    ssize_t ret;

    ret = get_orig_fop(iocb->ki_filp)->aio_write(iocb, iov, nr_segs, pos);

#if 0
    log_op(LOG_WRITE, iocb->ki_filp->f_dentry, "AIO Write file %s iov %p, nr_segs %lu offset %llu, kiocb %p ret %zd\n",
            get_dentry_name(iocb->ki_filp->f_dentry),
            iov, nr_segs, pos, iocb, ret);
#endif
    log_op(LOG_WRITE, iocb->ki_filp->f_dentry, "offset %llu|(%zd)\n", pos, ret);

    return ret;
}

static int log_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret;

    ret = get_orig_fop(filp)->mmap(filp, vma);

    //log_op(LOG_MMAP, filp->f_dentry, "MMAP file %s vma %p|(%d)\n", get_dentry_name(filp->f_dentry), vma, ret);
    log_op(LOG_MMAP, filp->f_dentry, "(%d)\n", ret);

    return ret;
}

static int log_open(struct inode *inode, struct file *filp)
{
    int ret;

    ret = get_orig_fop(filp)->open(inode, filp);
    //log_op(LOG_OPEN, filp->f_dentry, "Open file %s inode %p ino %lu|(%d)\n", get_dentry_name(filp->f_dentry), inode, inode->i_ino, ret);
    log_op(LOG_OPEN, filp->f_dentry, "(%d)\n", ret);

    return ret;
}

static int log_release(struct inode *inode, struct file *filp)
{
    int ret;

    ret = get_orig_fop(filp)->release(inode, filp);

    //log_op(LOG_CLOSE, filp->f_dentry, "Release file %s inode %p ino %lu|(%d)\n", get_dentry_name(filp->f_dentry), inode, inode->i_ino, ret);
    log_op(LOG_CLOSE, filp->f_dentry, "(%d)\n", ret);
    return ret;
}

static int log_flush(struct file *filp, fl_owner_t id)
{
    int ret;

    ret = get_orig_fop(filp)->flush(filp, id);
    //log_op(LOG_FLUSH, filp->f_dentry, "Flush file %s owner %p|(%d)\n", get_dentry_name(filp->f_dentry), id, ret);
    log_op(LOG_FLUSH, filp->f_dentry, "(%d)\n", ret);

    return ret;
}

static int log_fsync(struct file *filp, struct dentry *dentry, int datasync)
{
    int ret;

    ret = get_orig_fop(filp)->fsync(filp, dentry, datasync);

    //log_op(LOG_FSYNC, filp->f_dentry, "Fsync file %s datasync %d|(%d)\n", get_dentry_name(filp->f_dentry), datasync, ret);
    log_op(LOG_FSYNC, filp->f_dentry, "(%d)\n", ret);

    return ret;
}

static int log_lock(struct file *filp, int cmd, struct file_lock *fl)
{
    int ret = 0;

    ret = get_orig_fop(filp)->lock(filp, cmd, fl);

    //log_op(LOG_LOCK, filp->f_dentry, "Trying to lock file %s cmd %d range (%llu-%llu) type %d|(%d)\n", get_dentry_name(filp->f_dentry), cmd, fl->fl_start, fl->fl_end, fl->fl_type, ret);
    log_op(LOG_LOCK, filp->f_dentry, "range (%llu-%llu) type %d|(%d)\n", fl->fl_start, fl->fl_end, fl->fl_type, ret);

    return ret;
}

static int log_flock(struct file *filp, int cmd, struct file_lock *fl)
{
    int ret;

    ret = get_orig_fop(filp)->flock(filp, cmd, fl);

    //log_op(LOG_FLOCK, filp->f_dentry, "Trying to lock file %s cmd %d range (%llu-%llu) type %d|(%d)\n", get_dentry_name(filp->f_dentry), cmd, fl->fl_start, fl->fl_end, fl->fl_type, ret);
    log_op(LOG_FLOCK, filp->f_dentry, "range (%llu-%llu) type %d|(%d)\n", fl->fl_start, fl->fl_end, fl->fl_type, ret);

    return ret;
}

static void log_patch_dir_ops(struct inode *inode)
{
    BUG_ON(!S_ISDIR(inode->i_mode));
    if (unlikely(!orig_dir_iop)) {
        kdebug("Patch the dir inode_operations\n");
        orig_dir_iop = inode->i_op;
        memcpy(&log_dir_iop, orig_dir_iop, sizeof(log_dir_iop));
        if (orig_dir_iop->lookup)
            log_dir_iop.lookup = log_lookup;
        if (orig_dir_iop->create)
            log_dir_iop.create = log_create;
        if (orig_dir_iop->link)
            log_dir_iop.link = log_link;
        if (orig_dir_iop->unlink)
            log_dir_iop.unlink = log_unlink;
        if (orig_dir_iop->symlink)
            log_dir_iop.symlink = log_symlink;
        if (orig_dir_iop->mkdir)
            log_dir_iop.mkdir = log_mkdir;
        if (orig_dir_iop->rmdir)
            log_dir_iop.rmdir = log_rmdir;
        if (orig_dir_iop->rename)
            log_dir_iop.rename = log_rename;
#if 0
        if (orig_dir_iop->permission)
            log_dir_iop.permission = log_permission;
#endif
        if (orig_dir_iop->getattr)
            log_dir_iop.getattr = log_getattr;
        if (orig_dir_iop->setattr)
            log_dir_iop.setattr = log_setattr;
    }
    if (unlikely(!orig_dir_fop)) {
        kdebug("Patch the dir file_operations\n");
        orig_dir_fop = inode->i_fop;
        memcpy(&log_dir_fop, orig_dir_fop, sizeof(log_dir_fop));
        if (orig_dir_fop->llseek)
            log_dir_fop.llseek = log_llseek;
        if (orig_dir_fop->read)
            log_dir_fop.read = log_read;
        if (orig_dir_fop->readdir)
            log_dir_fop.readdir = log_readdir;
        if (orig_dir_fop->open)
            log_dir_fop.open = log_open;
        if (orig_dir_fop->release)
            log_dir_fop.release = log_release;
        if (orig_dir_fop->fsync)
            log_dir_fop.fsync = log_fsync;
    }

    inode->i_op = &log_dir_iop;
    inode->i_fop = &log_dir_fop;
}

static void log_patch_file_ops(struct inode *inode)
{
    BUG_ON(!S_ISREG(inode->i_mode));
    if (unlikely(!orig_file_iop)) {
        kdebug("Patch the file inode_operations\n");
        orig_file_iop = inode->i_op;
        memcpy(&log_file_iop, orig_file_iop, sizeof(log_file_iop));
#if 0
        if (orig_file_iop->permission)
            log_file_iop.permission = log_permission;
#endif
        if (orig_file_iop->getattr)
            log_file_iop.getattr = log_getattr;
        if (orig_file_iop->setattr)
            log_file_iop.setattr = log_setattr;
    }
    if (unlikely(!orig_file_fop)) {
        kdebug("Patch the file file_operations\n");
        orig_file_fop = inode->i_fop;
        memcpy(&log_file_fop, orig_file_fop, sizeof(log_file_fop));
        if (orig_file_fop->llseek)
            log_file_fop.llseek = log_llseek;
        if (orig_file_fop->read)
            log_file_fop.read = log_read;
        if (orig_file_fop->write)
            log_file_fop.write = log_write;
        if (orig_file_fop->aio_read)
            log_file_fop.aio_read = log_aio_read;
        if (orig_file_fop->aio_write)
            log_file_fop.aio_write = log_aio_write;
        if (orig_file_fop->readdir)
            log_file_fop.readdir = log_readdir;
        if (orig_file_fop->open)
            log_file_fop.open = log_open;
        if (orig_file_fop->release)
            log_file_fop.release = log_release;
        if (orig_file_fop->fsync)
            log_file_fop.fsync = log_fsync;
        if (orig_file_fop->flush)
            log_file_fop.flush = log_flush;
        if (orig_file_fop->lock)
            log_file_fop.lock = log_lock;
        if (orig_file_fop->flock)
            log_file_fop.flock = log_flock;
        if (orig_file_fop->mmap)
            log_file_fop.mmap = log_mmap;
    }

    inode->i_op = &log_file_iop;
    inode->i_fop = &log_file_fop;
}

static void log_patch_slink_ops(struct inode *inode)
{
    BUG_ON(!S_ISLNK(inode->i_mode));
    if (unlikely(!orig_slink_iop)) {
        kdebug("Patch the slink inode_operations\n");
        orig_slink_iop = inode->i_op;
        memcpy(&log_slink_iop, orig_slink_iop, sizeof(log_slink_iop));
        if (orig_slink_iop->setattr)
            log_slink_iop.setattr = log_setattr;
        if (orig_slink_iop->readlink)
            log_slink_iop.readlink = log_readlink;
        if (orig_slink_iop->follow_link)
            log_slink_iop.follow_link = log_follow_link;
        if (orig_slink_iop->put_link)
            log_slink_iop.put_link = log_put_link;
        if (orig_slink_iop->getattr)
            log_slink_iop.getattr = log_getattr;
    }
    inode->i_op = &log_slink_iop;
}

static int log_mount(struct file_system_type *type, int flags,
        const char *dev_name, void *raw_data, struct vfsmount *mnt)
{
    struct dentry *dentry;
    int ret;

    kdebug("Trying to do mount on %s\n", dev_name);
    if (!try_module_get(THIS_MODULE)) {
        kerr("Can't get reference of fslog\n");
        return -EACCES;
    }

    ret = orig_get_sb(type, flags, dev_name, raw_data, mnt);

    if (ret < 0) {
        kinfo("Orig mount failed %d\n", ret);
        module_put(THIS_MODULE);
        return ret;
    }

    dentry = mnt->mnt_root;

    BUG_ON(!dentry->d_inode);
    if ((strlen(fstype) == 3) && (strncmp(fstype, "nfs", 3) == 0)) {
        // Check nfs v3 since it's possible nfs v3 mount nfs v4
        kdebug("NFS version %d\n", NFS_PROTO(dentry->d_inode)->version);
        if (NFS_PROTO(dentry->d_inode)->version != 3) {
            kdebug("Ignore NFSv4 mount\n");
            module_put(THIS_MODULE);
            return ret;
        }
    }

    log_op(LOG_MOUNT, mnt->mnt_mountpoint, "Mount %s\n", dev_name);

    log_patch_dir_ops(dentry->d_inode);

    return ret;
}

static void log_killsb(struct super_block *sb)
{
    struct log_buf *buf;
    if ((strlen(fstype) == 3) && (strncmp(fstype, "nfs", 3) == 0)) {
        log_op(LOG_UMOUNT, sb->s_root, "%s\n", NFS_SB(sb)->client->cl_server);
    } else {
        log_op(LOG_UMOUNT, NULL, "Try to umount sb %p\n", sb);
    }
    orig_killsb(sb);

    // flush the buf to log file
    buf = log_get_buf();
    if (!IS_ERR(buf)) {
        log_issue_write(buf);
    }
    module_put(THIS_MODULE);
}

static struct proc_dir_entry *log_proc_file = NULL;
static int log_read_proc(char *buf, char **start, off_t offset,
        int count, int *eof, void *data)
{
    int len = 0;
    if (do_log) {
        len += sprintf(buf, "fslog started\n");
    } else {
        len += sprintf(buf, "fslog stopped\n");
    }
    len += sprintf(buf+len, "logpath=%s\n", logpath);
    len += sprintf(buf+len, "log_ops=%lu\n", ops);
    *eof = 1;
    return len;
}

static int log_write_proc(struct file *file, const char *buffer,
        unsigned long count, void *data)
{
    char cmd[32];

    if (count >= 32) {
        kerr("Invalid command\n");
        return -EINVAL;
    }

    if (copy_from_user(cmd, buffer, count)) {
        kerr("Get command failed\n");
        return -EFAULT;
    }
    cmd[count] = '\0';

    if ((count == 6) && (strncmp(cmd, "start", 5) == 0)) {
        kinfo("Start fslog\n");
        do_log = true;
        return count;
    }

    if ((count == 5) && (strncmp(cmd, "stop", 4) == 0)) {
        kinfo("Stop fslog\n");
        do_log = false;
        return count;
    }

    if ((count > 4) && (strncmp(cmd, "ops=", 4) == 0)) {
        char *p = cmd+4;
        char *endptr;
        unsigned long op;
        if (p[strlen(p)-1] == '\n') {
            p[strlen(p)-1] = '\0';
        }
        op = simple_strtoul(p, &endptr, 10);
        if ((endptr - p) != strlen(p)) {
            kerr("Invalid ops command: %s\n", cmd);
            return -EINVAL;
        }
        ops = op;
        return count;
    }

    return -EINVAL;
}

static int __init fslog_init(void)
{
    if (log_alloc_bufs()) {
        return -ENOMEM;
    }
    log_proc_file = create_proc_entry("fslog", 0644, NULL);
    if (!log_proc_file) {
        kerr("Create log proc file failed\n");
        return -ENOMEM;
    }
    log_proc_file->read_proc = log_read_proc;
    log_proc_file->write_proc = log_write_proc;

    orig_fs_type = get_fs_type(fstype);
    if (!orig_fs_type) {
        kinfo("init fslog of fs %s to path %s failed\n",
                fstype, logpath);
        return -ENODEV;
    }

    orig_get_sb = orig_fs_type->get_sb;
    orig_killsb = orig_fs_type->kill_sb;
    kinfo("get orig_get_sb = %p, orig_killsb = %p\n", orig_get_sb, orig_killsb);
    orig_fs_type->get_sb = log_mount;
    orig_fs_type->kill_sb = log_killsb;
    kinfo("init fslog of fs %s to path %s succeed\n",
            fstype, logpath);

    return 0;
}

static void __exit fslog_exit(void)
{
    // The put_filesystem is not exported
    //put_filesystem(orig_fs_type);
    module_put(orig_fs_type->owner);
    orig_fs_type->get_sb = orig_get_sb;
    orig_fs_type->kill_sb = orig_killsb;
    remove_proc_entry("fslog", NULL);
    log_free_bufs();
    kinfo("exit fslog\n");
}

module_init(fslog_init);
module_exit(fslog_exit);
