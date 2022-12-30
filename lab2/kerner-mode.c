#include <linux/cpufeature.h>
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/mutex.h> 
#include <linux/types.h> 
#include <linux/proc_fs.h> 
#include <linux/uaccess.h> 
#include <linux/version.h> 
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>

#include "common.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Natalia Nikonova");
MODULE_DESCRIPTION("My kernel module that read some struct from process");
MODULE_VERSION("1.1");

#define LOG_TAG "[os-lab2] "

/* Процесс для которого будет доставаться структура */
static int pid = 0;
/* Идентификатор структуры. 1 - fpu, 2 - task_struct*/
static int struct_id = 0;
/* Мьютекс */
static DEFINE_MUTEX(file_mutex); 

static ssize_t copy_to_answer_fpu(char *answer, struct task_struct *task_struct) {
    ssize_t answer_size = 0;

    struct thread_struct thread_struct = task_struct->thread;

    struct fpu fpu = thread_struct.fpu;

    struct dto_fpu dto_fpu;

    dto_fpu.last_cpu = fpu.last_cpu;
    dto_fpu.avx512_timestamp = fpu.avx512_timestamp;

    dto_fpu.state_perm = fpu.perm.__state_perm;
    dto_fpu.state_size = fpu.perm.__state_size;
    dto_fpu.user_state_size = fpu.perm.__user_state_size;

    if (!static_cpu_has(X86_FEATURE_FPU)) {
        /* Программная эмуляция FPU, совпадает с х87*/
        dto_fpu.cwd = fpu.__fpstate.regs.soft.cwd;
        dto_fpu.swd = fpu.__fpstate.regs.soft.swd;
        dto_fpu.twd = fpu.__fpstate.regs.soft.twd;
        dto_fpu.fip = fpu.__fpstate.regs.soft.fip;
        dto_fpu.fcs = fpu.__fpstate.regs.soft.fcs;
        dto_fpu.foo = fpu.__fpstate.regs.soft.foo;
        dto_fpu.fos = fpu.__fpstate.regs.soft.fos;
        memcpy(dto_fpu.stack, fpu.__fpstate.regs.soft.st_space, 80);
        pr_info(LOG_TAG "choose struct swregs_state");
    } else if (static_cpu_has(X86_FEATURE_XSAVE)) {
        /* самый новый вариант - устаревший fxregs + свой заголовок xstate. XSAVE XRSTOR*/
        dto_fpu.cwd = fpu.__fpstate.regs.xsave.i387.cwd;
        dto_fpu.swd = fpu.__fpstate.regs.xsave.i387.swd;
        dto_fpu.twd = fpu.__fpstate.regs.xsave.i387.twd;
        dto_fpu.fip = fpu.__fpstate.regs.xsave.i387.fip;
        dto_fpu.fcs = fpu.__fpstate.regs.xsave.i387.fcs;
        dto_fpu.foo = fpu.__fpstate.regs.xsave.i387.foo;
        dto_fpu.fos = fpu.__fpstate.regs.xsave.i387.fos;
        memcpy(dto_fpu.stack, fpu.__fpstate.regs.xsave.i387.st_space, 80);
        pr_info(LOG_TAG "choose struct xregs_state");
    } else if (static_cpu_has(X86_FEATURE_FXSR)) {
        /* устаревший формат для SSE/MMX, в отличие от fsave снапример охраняет конец xmm регистров. FXSAVE FXRSTOR*/
        dto_fpu.cwd = fpu.__fpstate.regs.fxsave.cwd;
        dto_fpu.swd = fpu.__fpstate.regs.fxsave.swd;
        dto_fpu.twd = fpu.__fpstate.regs.fxsave.twd;
        dto_fpu.fip = fpu.__fpstate.regs.fxsave.fip;
        dto_fpu.fcs = fpu.__fpstate.regs.fxsave.fcs;
        dto_fpu.foo = fpu.__fpstate.regs.fxsave.foo;
        dto_fpu.fos = fpu.__fpstate.regs.fxsave.fos;
        memcpy(dto_fpu.stack, fpu.__fpstate.regs.fxsave.st_space, 80);
        pr_info(LOG_TAG "choose struct fxregs_state");
    } else {
        /* устаревший варинат для х87, FSAVE FRSTOR*/
        dto_fpu.cwd = fpu.__fpstate.regs.fsave.cwd;
        dto_fpu.swd = fpu.__fpstate.regs.fsave.swd;
        dto_fpu.twd = fpu.__fpstate.regs.fsave.twd;
        dto_fpu.fip = fpu.__fpstate.regs.fsave.fip;
        dto_fpu.fcs = fpu.__fpstate.regs.fsave.fcs;
        dto_fpu.foo = fpu.__fpstate.regs.fsave.foo;
        dto_fpu.fos = fpu.__fpstate.regs.fsave.fos;
        memcpy(dto_fpu.stack, fpu.__fpstate.regs.fsave.st_space, 80);
        pr_info(LOG_TAG "choose struct fregs_state");
    }

    pr_info(LOG_TAG "dto_fpu: last_cpu=%u, avx512_timestamp=%lu, state_perm=%llu, state_size=%u, user_state_size=%u\n", 
            dto_fpu.last_cpu, 
            dto_fpu.avx512_timestamp,
            dto_fpu.state_perm,
            dto_fpu.state_size,
            dto_fpu.user_state_size
    );
    pr_info(LOG_TAG "dto_fpu: cwd=%u, swd=%u, twd=%u, fip=%u, fcs=%u, foo=%u, fos=%u\n", 
            dto_fpu.cwd,
            dto_fpu.swd,
            dto_fpu.twd,
            dto_fpu.fip,
            dto_fpu.fcs,
            dto_fpu.foo,
            dto_fpu.fos
    );
    memcpy(answer, &dto_fpu, sizeof(dto_fpu));
    pr_info(LOG_TAG "dto_fpu copy to answer, size %zu\n", sizeof(struct dto_fpu));
    return sizeof(dto_fpu);
}

static ssize_t copy_to_answer_task_struct(char *answer, struct task_struct *task_struct) {
    struct dto_task_struct dto;

    dto.state = task_struct->__state;
    dto.flags = task_struct->flags;
    dto.ptrace = task_struct->ptrace;
    dto.on_rq = task_struct->on_rq;
    dto.on_cpu = task_struct->on_cpu;
    dto.prio = task_struct->prio;
    dto.static_prio = task_struct->static_prio;
    dto.normal_prio = task_struct->normal_prio;
    dto.rt_priority = task_struct->rt_priority;
    dto.policy = task_struct->policy;
    dto.nr_cpus_allowed = task_struct->nr_cpus_allowed;
    dto.migration_flags= task_struct->migration_flags;
    dto.exit_state = task_struct->exit_state;
    dto.exit_code = task_struct->exit_code;
    dto.exit_signal = task_struct->exit_signal;
    dto.pdeath_signal = task_struct->pdeath_signal;
    dto.atomic_flags = task_struct->atomic_flags;

    dto.pid = task_struct->pid;
    dto.tgid = task_struct->tgid;
    dto.real_parent_pid = task_struct->real_parent->pid;
    dto.parent_pid = task_struct->parent->pid;

    dto.start_time = task_struct->start_time;

    pr_info(LOG_TAG "task_struct: state=%u, flags=%zu, ptrace=%zu, on_cpu=%u, on_rq=%u, prio=%u, static_prio=%u, normal_prio=%u, rt_priority%u, policy=%u, nr_cpus_allowed=%u\n", 
            dto.state,
            dto.flags,
            dto.ptrace,
            dto.on_cpu,
            dto.on_rq,
            dto.prio,
            dto.static_prio,
            dto.normal_prio,
            dto.rt_priority,
            dto.policy,
            dto.nr_cpus_allowed
    );
    pr_info(LOG_TAG "task_struct: migration_flags=%u, exit_state=%u, exit_code=%u, exit_signal=%u, pdeath_signal=%u, atomic_flags=%lu, pid=%u, tgid=%u, real_parent_pid=%u, parent_pid=%u, start_time=%llu\n",
            dto.migration_flags,
            dto.exit_state,
            dto.exit_code,
            dto.exit_signal,
            dto.pdeath_signal,
            dto.atomic_flags,
            dto.pid,
            dto.tgid,
            dto.real_parent_pid,
            dto.parent_pid,
            dto.start_time
    );

    memcpy(answer, &dto, sizeof(dto));
    pr_info(LOG_TAG "dto_task_struct copy to answer, dto_task_struct size %zu\n", sizeof(struct dto_task_struct));
    return sizeof(dto);
}
 
/* Эта функция вызывается при считывании файла /proc. */ 
static ssize_t procfile_read(struct file *filePointer, char __user *buffer, 
                             size_t buffer_length, loff_t *offset) 
{ 
    char *answer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    char answer_code = 0;
    ssize_t answer_size = 0;

    struct pid *pid_struct = find_get_pid(pid);
    if (NULL == pid_struct) {
        pr_info(LOG_TAG "Can't found process with pid = %d\n", pid);
        answer_code = 1;
        copy_to_user(buffer, &answer_code, 1);
        answer_size = sprintf(answer, "Can't found process with pid = %d\n", pid);
        copy_to_user(buffer + 1, answer, answer_size);
        kfree(answer);
        *offset += (answer_size + 1);
        mutex_unlock(&file_mutex); 
        pr_info(LOG_TAG "file freed");
        return answer_size + 1;
    }

    struct task_struct *task_struct = pid_task(pid_struct, PIDTYPE_PID);
    if (NULL == task_struct) {
        pr_info(LOG_TAG "Failed to get task_struct from process with pid = %d\n", pid);
        answer_code = 1;
        copy_to_user(buffer, &answer_code, 1);
        answer_size = sprintf(answer, "Failed to get task_struct from process with pid = %d\n", pid);
        copy_to_user(buffer + 1, answer, answer_size);
        kfree(answer);
        *offset += (answer_size + 1);
        mutex_unlock(&file_mutex); 
        pr_info(LOG_TAG "file freed");
        return answer_size + 1;
    }

    if (FPU_IND == struct_id) {
        answer_size = copy_to_answer_fpu(answer, task_struct);
    } else if (TASK_STRUCT_IND == struct_id) {
        answer_size = copy_to_answer_task_struct(answer, task_struct);
    } else {
        pr_info(LOG_TAG "Struct is not defined = %d\n", struct_id);
        answer_code = 1;
        answer_size = sprintf(answer, "Struct is not defined = %d\n", struct_id);
    }

    pr_info(LOG_TAG "start answer copy to user, answer size %d, answer_code=%d\n", answer_size, answer_code);
    copy_to_user(buffer, &answer_code, 1);
    copy_to_user(buffer + 1, answer, answer_size);
    pr_info(LOG_TAG "answer copy to user\n");

    kfree(answer);
    *offset += (answer_size + 1);
    mutex_unlock(&file_mutex); 
    pr_info(LOG_TAG "file freed");
    return answer_size + 1;
} 
 
/* Эта функция вызывается при записи файла /proc. */ 
static ssize_t procfile_write(struct file *file, const char __user *buff, 
                              size_t len, loff_t *off) 
{
    pr_info(LOG_TAG "procfile_write: open");
    mutex_lock(&file_mutex);
    pr_info(LOG_TAG "mutex locked");

    unsigned long user_input_size = len; 
    if (user_input_size > BUFFER_SIZE) {
        user_input_size = BUFFER_SIZE; 
    }
    
    char *user_input = kmalloc(user_input_size, GFP_KERNEL);
    unsigned long lost_bytes = copy_from_user(user_input, buff, user_input_size);
    if (lost_bytes) {
        pr_info(LOG_TAG "copy_from_user can't copy %lu bytes\n", lost_bytes);
        kfree(user_input);
        mutex_unlock(&file_mutex); 
        return 0; 
    }
    pr_info(LOG_TAG "proc_write write %zu bytes\n", len);

    int arg1, arg2, args_num;
    args_num = sscanf(user_input, "%d %d", &arg1, &arg2);
    if (2 == args_num) {
        pr_info(LOG_TAG "read two arguments: arg1=%d, arg3=%d\n", arg1, arg2);
        pid = arg1;
        struct_id = arg2;
    } else {
        pr_info(LOG_TAG "sscanf found %d arguments - not two", args_num);
        mutex_unlock(&file_mutex); 
    }
 
    kfree(user_input);
    return user_input_size; 
} 

/* Эта структура содержит информацию о файле /proc. */ 
static struct proc_dir_entry *proc_file_info; 

/* Для версии ядра > 5.6.0, иначе надо использовать  file_operations*/
static const struct proc_ops proc_file_fops = { 
    .proc_read = procfile_read, 
    .proc_write = procfile_write, 
}; 
 
static int __init procfs_init(void) 
{ 
    proc_file_info = proc_create(PROCFS_NAME, 0644, NULL, &proc_file_fops); 
    if (NULL == proc_file_info) { 
        proc_remove(proc_file_info); 
        pr_alert(LOG_TAG "Error:Could not initialize /proc/%s\n", PROCFS_NAME); 
        return -ENOMEM; 
    } 
 
    pr_info(LOG_TAG "/proc/%s created\n", PROCFS_NAME); 
    return 0; 
} 
 
static void __exit procfs_exit(void) 
{ 
    proc_remove(proc_file_info); 
    pr_info(LOG_TAG "/proc/%s removed\n", PROCFS_NAME); 
} 
 
module_init(procfs_init); 
module_exit(procfs_exit); 
