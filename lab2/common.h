#ifndef LAB2_OS_COMMON
#define LAB2_OS_COMMON

#define BUFFER_SIZE 2048 
#define PROCFS_NAME "lab2_os_module" 

#define FPU_IND 1
#define TASK_STRUCT_IND 2

struct dto_task_struct {
    unsigned int state;
    unsigned long flags;
    unsigned long ptrace;
    int on_cpu;
    int on_rq;
    int prio;
    int static_prio;
    int normal_prio;
    unsigned int rt_priority;
    unsigned int policy;
    int nr_cpus_allowed;
    unsigned short migration_flags;

    int exit_state;
    int exit_code;
    int exit_signal;
    int	pdeath_signal; /* when parent died */

    unsigned long atomic_flags;

    int pid;
    int tgid; /* thread group id */
    int real_parent_pid;
    int parent_pid; /* Recipient of SIGCHLD, wait4() reports: */

    unsigned long long start_time;
};

struct dto_fpu {
    unsigned int last_cpu; /* Last cpu in which regs this context load. -1 is mean what context in this struct more new than regs */
    unsigned long avx512_timestamp; /* timestamp then AVX512 used to switch context*/

    unsigned long long state_perm;
    unsigned int state_size;
    unsigned int user_state_size;

    unsigned int cwd; /* Control word - управление режимами работы сопроцессора - управление точностью, округлением, маски переполнения, недействительно операции и тюпю*/
    unsigned int swd; /* Status word - текущее состояние сопроцессора - флаги деления на 0, неточного результата, условий, переполнения, занятости и т.п.*/
    unsigned int twd; /* Tag word - описание содержимого стека (16/32 бит - по 2/4 на каждый регистр) 00- действ. не нуль, 01 - истинный нуль, 10 - спец.числа, 11 - отсут. данных*/
    unsigned int fip; /* IP Offset */
    unsigned int fcs; /* IP selector */
    unsigned int foo; /* Operand Pointer offset */
    unsigned int fos; /* Operand Pointer selector */

    unsigned int stack[20]; /* r0..r7 - стек сопроцессора - 8 регистров по 80 бит (8 * 4 * 20)*/
};

#endif
