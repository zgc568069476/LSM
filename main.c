#define pr_fmt(fmt) "[%s]: " fmt, KBUILD_MODNAME

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/stop_machine.h>
#include <linux/security.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
#include <linux/lsm_hooks.h>
#else
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fsnotify.h>
#endif
#include "symbol.h"
#include "setpage.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
static const struct lsm_id my_lsmid = {
	.name = "lsmhook",
	.id = 113,
};
#define TMP_LSM_CONFIG_COUNT ( \
	(IS_ENABLED(CONFIG_SECURITY) ? 1 : 0) + \
	(IS_ENABLED(CONFIG_SECURITY_SELINUX) ? 1 : 0) + \
	(IS_ENABLED(CONFIG_SECURITY_SMACK) ? 1 : 0) + \
	(IS_ENABLED(CONFIG_SECURITY_TOMOYO) ? 1 : 0) + \
	(IS_ENABLED(CONFIG_SECURITY_APPARMOR) ? 1 : 0) + \
	(IS_ENABLED(CONFIG_SECURITY_YAMA) ? 1 : 0) + \
	(IS_ENABLED(CONFIG_SECURITY_LOADPIN) ? 1 : 0) + \
	(IS_ENABLED(CONFIG_SECURITY_SAFESETID) ? 1 : 0) + \
	(IS_ENABLED(CONFIG_SECURITY_LOCKDOWN_LSM) ? 1 : 0) + \
	(IS_ENABLED(CONFIG_BPF_LSM) ? 1 : 0) + \
	(IS_ENABLED(CONFIG_SECURITY_LANDLOCK) ? 1 : 0) + \
	(IS_ENABLED(CONFIG_IMA) ? 1 : 0) + \
	(IS_ENABLED(CONFIG_EVM) ? 1 : 0))

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
static int my_file_open(struct file *file)
#else
static int my_file_open(struct file *file, const struct cred *cred)
#endif
{
    pr_info("file open: %s\n", file->f_path.dentry->d_iname);
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
#define MY_LSM_HOOK_INIT(HEAD, HOOK) \
    { .head = &((struct security_hook_heads *)0)->HEAD, .hook = { .HEAD = HOOK } }

static struct security_hook_heads *heads_symbol;
struct security_hook_list hooks[] = {
    MY_LSM_HOOK_INIT(file_open, my_file_open),
};
#else
static struct security_operations **ops_symbol;
static struct security_operations *ops_addr;
static struct security_operations bak_ops;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
static u32 * lsm_active_cnt_addr = NULL;
struct lsm_id ** lsm_id_addr;
struct lsm_id *old_lsm_id;
struct lsm_id *new_lsm_id[TMP_LSM_CONFIG_COUNT+1];
#endif

static int hook_lsm(void *arg) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
    int i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)   
    new_lsm_id[*lsm_active_cnt_addr] = &my_lsmid;
    set_addr_rw(lsm_active_cnt_addr);
    *lsm_active_cnt_addr=*lsm_active_cnt_addr+1;
    set_addr_ro(lsm_active_cnt_addr);
#endif

  for (i = 0; i < ARRAY_SIZE(hooks); i++) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)    
     hooks[i].lsmid = &my_lsmid;
#else
     hooks[i].lsm = "lsmhook";
#endif
    hooks[i].head = (struct hlist_head *) ((unsigned long)hooks[i].head + (unsigned long)heads_symbol);
    hlist_add_tail_rcu(&hooks[i].list, hooks[i].head);
  }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    ops_addr->file_open = my_file_open;
#else
    ops_addr->dentry_open = my_file_open;
#endif  
  return 0;
}


static int unhook_lsm(void *arg) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
    int i;
    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        hlist_del_rcu(&hooks[i].list);
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0) 
    set_addr_rw(lsm_active_cnt_addr);
    *lsm_active_cnt_addr = *lsm_active_cnt_addr-1;
    set_addr_ro(lsm_active_cnt_addr);
#endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    ops_addr->file_open = bak_ops.file_open;
#else 
    ops_addr->dentry_open = bak_ops.dentry_open;
#endif
  return 0;
}

static int lsm_info_get(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0) 
    int i = 0;
#endif
    heads_symbol = (struct security_hook_heads *) lookup_name("security_hook_heads");
    if (heads_symbol == NULL) {

        pr_err("symbol security_hook_heads not found\n");
        return -1;
    }
    pr_info("symbol security_hook_heads: 0x%lx\n", (unsigned long)heads_symbol);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0) 
    lsm_id_addr = (struct lsm_id **) lookup_name("lsm_idlist");
    lsm_active_cnt_addr = (u32*) lookup_name("lsm_active_cnt");
    for (i=0;i<(*lsm_active_cnt_addr);i++){
        new_lsm_id[i] = lsm_id_addr[i];
    }
    old_lsm_id = *lsm_id_addr;
    *lsm_id_addr = *new_lsm_id;
#endif
#else
    ops_symbol = (struct security_operations **) lookup_name("security_ops");
    if (ops_symbol == NULL) {
        pr_err("symbol security_ops not found\n");
        return -1;
    }
    ops_addr = *ops_symbol;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    bak_ops.file_open = ops_addr->file_open;
#else 
    bak_ops.dentry_open = ops_addr->dentry_open;
#endif
   

#endif
  return 0;
}

static int __init lsmhook_init(void) {
  pr_info("lsm hook module init\n");
  if (lsm_info_get() != 0) {
    pr_err("get LSM information failed\n");
    return -1;
  }
  pr_info("start hook LSM\n");
  stop_machine(hook_lsm, NULL, NULL);
  return 0;
}

static void __exit lsmhook_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)   
    *lsm_id_addr = old_lsm_id;
#endif
    stop_machine(unhook_lsm, NULL, NULL);
    pr_info("exit\n");
}

module_init(lsmhook_init);
module_exit(lsmhook_exit);
MODULE_LICENSE("GPL");