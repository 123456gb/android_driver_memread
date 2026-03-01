#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

// ARM64 系统调用号
#define __NR_read 63

// 这里要换成你内核的 sys_call_table 地址
unsigned long *sys_call_table = (unsigned long *)0xFFFFFFC010000000;

// 原始 sys_read
asmlinkage long (*original_sys_read)(int fd, char __user *buf, size_t count);

// 自己的 hook 函数
asmlinkage long hook_sys_read(int fd, char __user *buf, size_t count)
{
    long ret = original_sys_read(fd, buf, count);

    // 打印进程名、PID、读取长度
    pr_info("HOOK ARM64_read: %s pid:%d fd:%d count:%zu ret:%ld\n",
        current->comm, current->pid, fd, count, ret);

    return ret;
}

// ARM64 关闭/开启 MMU 写保护
static void disable_write_protect(void)
{
    asm volatile(
        "msr daifset, #2\n"
        "mrs x0, sctlr_el1\n"
        "bic x0, x0, #(1 << 1)\n"
        "msr sctlr_el1, x0\n"
        "isb\n"
        :::"x0");
}

static void enable_write_protect(void)
{
    asm volatile(
        "mrs x0, sctlr_el1\n"
        "orr x0, x0, #(1 << 1)\n"
        "msr sctlr_el1, x0\n"
        "isb\n"
        "msr daifclr, #2\n"
        :::"x0");
}

static int __init hook_init(void)
{
    pr_info("hook arm64 read init\n");

    disable_write_protect();
    original_sys_read = (void *)sys_call_table[__NR_read];
    sys_call_table[__NR_read] = (unsigned long)hook_sys_read;
    enable_write_protect();

    return 0;
}

static void __exit hook_exit(void)
{
    disable_write_protect();
    sys_call_table[__NR_read] = (unsigned long)original_sys_read;
    enable_write_protect();

    pr_info("hook arm64 read exit\n");
}

module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ARM64 Hook sys_read for fread");
