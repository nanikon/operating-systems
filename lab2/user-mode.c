#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>

#include "common.h"

int main(int argc, char *argv[]) 
{
    if (argc == 2) {
        if (argv[1] == "-h") {
            printf("Two argument required: first is a pid of process, second is name of struct - fpu or task_struct\n");
            return 0;
        } else {
            fprintf(stderr, "Unknow flag %s\n", argv[1]);
            return 1;
        }
    } else if (argc != 3) {
        fprintf(stderr, "Wrong count arguments - %d\n", argc);
        return 1;
    }

    int pid = atoi(argv[1]);
    if (0 == pid && !isdigit(argv[1][0])) {
        fprintf(stderr, "First argument should be a number, found %s\n", argv[1]);
        return 1;
    }

    char *struct_name = argv[2];
    int struct_id;
    if (strcmp(struct_name, "fpu") == 0) {
        struct_id = FPU_IND;
    } else if(strcmp(struct_name, "task_struct") == 0) {
        struct_id = TASK_STRUCT_IND;
    } else {
        fprintf(stderr, "Second argument should be \"fpu\" or \"task_struct\", found %s\n", struct_name);
        return 1;
    }

    int fd = open("/proc/" PROCFS_NAME, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "can't open /proc/" PROCFS_NAME "\n");
        close(fd);
        return 1;
    }

    char buf[BUFFER_SIZE];
    sprintf(buf, "%d %d", pid, struct_id);

    if (write(fd, buf, strlen(buf)) == -1) {
		fprintf(stderr, "Writing buffer=\"%s\" to fd=%d failed\n", buf, fd);
		close(fd);
		return 1;
	}

    sleep(10);

	if (read(fd, buf, BUFFER_SIZE) == -1) {
		fprintf(stderr, "Reading from fd=%d failed\n", fd);
		close(fd);
		return 1;
	}

    char *start_info = buf + 1;
    printf("kernel exit code %d\n", buf[0]);

    if (buf[0] == 1) {
        printf("catch some error from kernel: %s\n", start_info);
        return 1;
    }

	printf("--- PID=%d STRUCT=%s ---\n\n", pid, struct_name);

	if (FPU_IND == struct_id) {
        struct dto_fpu dto_fpu;
		memcpy(&dto_fpu, start_info, sizeof(dto_fpu));
		printf("last_cpu=%u, avx512_timestamp=%lu, state_perm=%llu, state_size=%u, user_state_size=%u\n", 
            dto_fpu.last_cpu, 
            dto_fpu.avx512_timestamp,
            dto_fpu.state_perm,
            dto_fpu.state_size,
            dto_fpu.user_state_size
        );
        printf("cwd=%u, swd=%u, twd=%u, fip=%u, fcs=%u, foo=%u, fos=%u\n", 
            dto_fpu.cwd,
            dto_fpu.swd,
            dto_fpu.twd,
            dto_fpu.fip,
            dto_fpu.fcs,
            dto_fpu.foo,
            dto_fpu.fos
        );
        unsigned char *split_stack = (unsigned char *) dto_fpu.stack;
        printf("stack:\n");
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 10; j++) {
                printf("%u", split_stack[ i * 10 + j]);
            }
            printf("\n");
        }
	}
	else if (TASK_STRUCT_IND == struct_id) {
        struct dto_task_struct dto_task_struct;
		memcpy(&dto_task_struct, start_info, sizeof(dto_task_struct));
		printf("state=%u, flags=%zu, ptrace=%zu, on_cpu=%u, on_rq=%u, prio=%u, static_prio=%u, normal_prio=%u, rt_priority%u, policy=%u, nr_cpus_allowed=%u\n", 
            dto_task_struct.state,
            dto_task_struct.flags,
            dto_task_struct.ptrace,
            dto_task_struct.on_cpu,
            dto_task_struct.on_rq,
            dto_task_struct.prio,
            dto_task_struct.static_prio,
            dto_task_struct.normal_prio,
            dto_task_struct.rt_priority,
            dto_task_struct.policy,
            dto_task_struct.nr_cpus_allowed
        );
        printf("migration_flags=%u, exit_state=%u, exit_code=%u, exit_signal=%u, pdeath_signal=%u, atomic_flags=%lu, pid=%u, tgid=%u, real_parent_pid=%u, parent_pid=%u, start_time=%llu\n",
            dto_task_struct.migration_flags,
            dto_task_struct.exit_state,
            dto_task_struct.exit_code,
            dto_task_struct.exit_signal,
            dto_task_struct.pdeath_signal,
            dto_task_struct.atomic_flags,
            dto_task_struct.pid,
            dto_task_struct.tgid,
            dto_task_struct.real_parent_pid,
            dto_task_struct.parent_pid,
            dto_task_struct.start_time
        );
	} else {
        fprintf(stderr, "Unknow struct_id %d", struct_id);
    }

	close(fd);
	return 0;
}
