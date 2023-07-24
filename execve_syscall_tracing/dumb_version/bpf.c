#include <linux/bpf.h>

/**
    SYNOPSIS
       #include <unistd.h>
       int execve(const char *pathname, char *const _Nullable argv[],
                  char *const _Nullable envp[]);
    DESCRIPTION
    execve() executes the program referred to by pathname. This
       causes the program that is currently being run by the calling
       process to be replaced with a new program, with newly initialized
       stack, heap, and (initialized and uninitialized) data segments.
       Notice: it does not create a new process from scratch, because
       it replaces the existing one!
*/

BPF_HASH(counter_table, __u64, __u64, 1024);

int execve_monitor(void *ctx) {

    __u32 USER_ID_MASK = 0xFFFFFFFF;
    __u64  user_id;
    __u64 *counter;

    // bpf_get_current_uid_gid() returns a 64-bit value
    // The 32 most significant bits are the user_id
    user_id = bpf_get_current_uid_gid() & USER_ID_MASK;
    counter = counter_table.lookup(&user_id);
    if (counter == NULL) {
        __u64 new_value = 1;
        counter_table.insert(&user_id, &new_value);
    }
    else {
        __u64 new_value = *counter + 1;
        counter_table.update(&user_id, &new_value);
    }

    return 0;
}