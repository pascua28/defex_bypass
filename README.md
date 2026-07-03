# Introduction
This LKM is tested on Samsung S23 Galaxy running Linux 5.15.153 kernel based on OneUI 7 (April 2025 security patch level).

# Instructions
This uses kprobes to dynamically patch those defex functions that block running binaries. 
To load the module, run these:

`echo 0 > /proc/sys/kernel/kptr_restrict`

`EXEC_ADDR=$(awk '$3=="task_defex_user_exec" {print "0x"$1}' /proc/kallsyms)`
`CREDS_ADDR=$(awk '$3=="task_defex_check_creds" {print "0x"$1}' /proc/kallsyms)`
`CREDS_READY_ADDR=$(awk '$3=="is_task_creds_ready" {print "0x"$1}' /proc/kallsyms)`
`DC_PATH_ADDR=$(awk '$3=="get_dc_target_dpath" {print "0x"$1}' /proc/kallsyms)`

`insmod defex.ko user_exec_addr=$EXEC_ADDR check_creds_addr=$CREDS_ADDR creds_ready_addr=$CREDS_READY_ADDR dc_path_addr=$DC_PATH_ADDR`

The prebuilt module is built against my device's kernel (will work on similar 8 gen 2 devices). If you have a different device or a different kernel, you will need to build this module against your device's kernel source.
