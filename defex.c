// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>

static ulong user_exec_addr;
module_param(user_exec_addr, ulong, 0444);
MODULE_PARM_DESC(user_exec_addr, "Address of task_defex_user_exec");

static ulong check_creds_addr;
module_param(check_creds_addr, ulong, 0444);
MODULE_PARM_DESC(check_creds_addr, "Address of task_defex_check_creds");

static ulong creds_ready_addr;
module_param(creds_ready_addr, ulong, 0444);
MODULE_PARM_DESC(creds_ready_addr, "Address of is_task_creds_ready");

static ulong dc_path_addr;
module_param(dc_path_addr, ulong, 0444);
MODULE_PARM_DESC(dc_path_addr, "Address of get_dc_target_dpath");

/*
static int defex_ret_handler(struct kretprobe_instance *ri,
                             struct pt_regs *regs)
{
    // Force the return value to 0
    regs->regs[0] = 0;
    return 0;
}
*/

static int defex_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    regs->regs[0] = 0;

    regs->pc = regs->regs[30];

    return 1;
}

static struct kprobe krp_user_exec = {
    .pre_handler    = defex_pre_handler,
};

static struct kprobe krp_check_creds = {
    .pre_handler    = defex_pre_handler,
};

static struct kprobe krp_creds_ready = {
    .pre_handler    = defex_pre_handler,
};

static struct kprobe krp_dc_path = {
    .pre_handler    = defex_pre_handler,
};

static int __init defex_bypass_init(void)
{
    int ret;

    if (!user_exec_addr || !check_creds_addr)
        return -EINVAL;

    krp_user_exec.addr = (kprobe_opcode_t *)user_exec_addr;
    krp_check_creds.addr = (kprobe_opcode_t *)check_creds_addr;
    krp_creds_ready.addr = (kprobe_opcode_t *)creds_ready_addr;
    krp_dc_path.addr = (kprobe_opcode_t *)dc_path_addr;

    ret = register_kprobe(&krp_user_exec);
    if (ret) {
	pr_err("kprobe: unable to probe user_exec\n");
        return ret;
    }

    ret = register_kprobe(&krp_check_creds);
    if (ret) {
        pr_err("kprobe: unable to probe creds\n");
        unregister_kprobe(&krp_user_exec);
        return ret;
    }

    ret = register_kprobe(&krp_creds_ready);
    if (ret) {
        pr_err("kprobe: unable to is_task_creds_ready\n");
        unregister_kprobe(&krp_check_creds);
        return ret;
    }

    ret = register_kprobe(&krp_dc_path);
    if (ret) {
        pr_err("kprobe: unable to get_dc_target_dpath\n");
        unregister_kprobe(&krp_creds_ready);
        return ret;
    }

    pr_err("kprobe: successful!\n");

    return 0;
}

static void __exit defex_bypass_exit(void)
{
    unregister_kprobe(&krp_dc_path);
    unregister_kprobe(&krp_creds_ready);
    unregister_kprobe(&krp_check_creds);
    unregister_kprobe(&krp_user_exec);

    pr_info("DEFEX kprobes removed\n");
}

module_init(defex_bypass_init);
module_exit(defex_bypass_exit);

MODULE_LICENSE("GPL");
