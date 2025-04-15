
/*
 * random42.c - A Linux Kernel Module to override /dev/random read_iter
 *
 * This kernel module intercepts the read_iter function of /dev/random
 * and replaces it to always return a buffer filled with the value 42.
 *
 * Author: Wasim
 * License: GPL
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/preempt.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <asm/io.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Hook /dev/random to return only 42");

static struct file_operations *random_fops = NULL;
static ssize_t (*original_read_iter)(struct kiocb *, struct iov_iter *) = NULL;

/*
 * Custom read_iter that fills the buffer with value 42.
 */
asmlinkage ssize_t hacked_read_iter(struct kiocb *iocb, struct iov_iter *iter) {
    size_t len = iter->count;
    char *buf;
    ssize_t ret;

    buf = kmalloc(len, GFP_KERNEL);
    if (!buf) return -ENOMEM;

    memset(buf, 42, len);  // Fill the buffer with ASCII 42 ('*')

    ret = copy_to_iter(buf, len, iter);
    kfree(buf);

    return ret < 0 ? ret : len;
}

/*
 * Inline assembly to modify cr0 register to disable write protection.
 */
static void write_cr0_forced(unsigned long val) {
    asm volatile("mov %0, %%cr0" : : "r" (val) : "memory");
}

static void disable_write_protection(void) {
    preempt_disable();
    barrier();
    write_cr0_forced(read_cr0() & ~0x00010000);
}

static void enable_write_protection(void) {
    write_cr0_forced(read_cr0() | 0x00010000);
    barrier();
    preempt_enable();
}

/*
 * Module Initialization
 */
static int __init random42_init(void) {
    struct file *filp;

    filp = filp_open("/dev/random", O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_err("[random42] Failed to open /dev/random\n");
        return PTR_ERR(filp);
    }

    random_fops = (struct file_operations *)filp->f_op;
    filp_close(filp, NULL);

    if (!random_fops || !random_fops->read_iter) {
        pr_err("[random42] Failed to access read_iter\n");
        return -ENODEV;
    }

    disable_write_protection();
    original_read_iter = random_fops->read_iter;
    random_fops->read_iter = hacked_read_iter;
    enable_write_protection();

    pr_info("[random42] /dev/random is now hooked to return 42\n");
    return 0;
}

/*
 * Module Cleanup
 */
static void __exit random42_exit(void) {
    if (random_fops && original_read_iter) {
        disable_write_protection();
        random_fops->read_iter = original_read_iter;
        enable_write_protection();
        pr_info("[random42] /dev/random hook restored\n");
    }
}

module_init(random42_init);
module_exit(random42_exit);
