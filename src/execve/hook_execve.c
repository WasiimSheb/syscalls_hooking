/*
 * hook_execve.c
 * 
 * Kernel module that overrides the execve() syscall.
 * It intercepts calls to execve and logs or manipulates the arguments.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wasim");
MODULE_DESCRIPTION("Override execve syscall to log or modify behavior");

typedef asmlinkage long (*sys_execve_t)(const struct pt_regs *);

static sys_execve_t original_execve;
static unsigned long **sys_call_table;

static unsigned long cr0;

// Disable write protection
static void disable_write_protection(void) {
    preempt_disable();
    barrier();
    cr0 = read_cr0();
    write_cr0(cr0 & ~0x00010000);
    barrier();
}

// Restore write protection
static void enable_write_protection(void) {
    write_cr0(cr0);
    barrier();
    preempt_enable();
}

static asmlinkage long hooked_execve(const struct pt_regs *regs) {
    char __user *filename = (char __user *)regs->di;
    char fname[256];

    if (strncpy_from_user(fname, filename, sizeof(fname)) > 0) {
        if (strstr(fname, "bash") || strstr(fname, "sh")) {
            printk(KERN_INFO "[hook_execve] Blocking shell execution: %s\n", fname);
            return -EPERM; // Block execution
        }
        printk(KERN_INFO "[hook_execve] execve called: %s\n", fname);
    }

    return original_execve(regs);
}

static int __init hook_execve_init(void) {
    sys_call_table = (unsigned long **)kallsyms_lookup_name("sys_call_table");

    if (!sys_call_table) {
        pr_alert("[hook_execve] Failed to locate sys_call_table\n");
        return -1;
    }

    original_execve = (void *)sys_call_table[__NR_execve];

    disable_write_protection();
    sys_call_table[__NR_execve] = (unsigned long *)hooked_execve;
    enable_write_protection();

    pr_info("[hook_execve] Loaded successfully\n");
    return 0;
}

static void __exit hook_execve_exit(void) {
    if (sys_call_table && original_execve) {
        disable_write_protection();
        sys_call_table[__NR_execve] = (unsigned long *)original_execve;
        enable_write_protection();
        pr_info("[hook_execve] Restored original execve\n");
    }
}

module_init(hook_execve_init);
module_exit(hook_execve_exit);
