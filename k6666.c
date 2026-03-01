#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <asm/tlbflush.h>

#define __NR_read    63

unsigned long *sys_call_table = NULL;
asmlinkage long (*original_sys_read)(int fd, char __user *buf, size_t count);

// 保存原本的页表属性
static unsigned long original_pgprot;

// 把 sys_call_table 所在页设为可写
static void unset_syscall_wp(void)
{
    pte_t *pte;
    unsigned long addr = (unsigned long)sys_call_table;

    pte = lookup_address(addr, &original_pgprot);
    if (pte) {
        set_pte(pte, __pte(original_pgprot & ~PTE_RDONLY));
        flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
    }
}

// 恢复只读保护
static void set_syscall_ro(void)
{
    pte_t *pte;
    unsigned long addr = (unsigned long)sys_call_table;

    pte = lookup_address(addr, NULL);
    if (pte) {
        set_pte(pte, __pte(original_pgprot));
        flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
    }
}

asmlinkage long hook_sys_read(int fd, char __user *buf, size_t count)
{
    long ret;

    // 这里先不打印，避免递归导致死机
    ret = original_sys_read(fd, buf, count);

    return ret;
}

static int __init hook_init(void)
{
    // 从内核符号表获取 sys_call_table
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        pr_err("sys_call_table 未找到\n");
        return -ENOENT;
    }

    pr_info("sys_call_table = %px\n", sys_call_table);

    unset_syscall_wp();

    original_sys_read = (void *)sys_call_table[__NR_read];
    sys_call_table[__NR_read] = (unsigned long)hook_sys_read;

    set_syscall_ro();

    pr_info("HOOK 初始化成功\n");
    return 0;
}

static void __exit hook_exit(void)
{
    if (!sys_call_table)
        return;

    unset_syscall_wp();
    sys_call_table[__NR_read] = (unsigned long)original_sys_read;
    set_syscall_ro();

    pr_info("HOOK 已卸载\n");
}

module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ARM64 sys_read hook safe");
