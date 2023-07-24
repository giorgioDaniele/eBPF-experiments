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

    BPF_PERF_OUTPUT(output);
    struct data_t {
        int pid;
        int uid;
        char command[16];
        char message[100];
    };

int execve_monitor(void *ctx) {

    __u32 USER_ID_MASK = 0xFFFFFFFF;

    struct data_t data = {};
    __u8 message[100] = "This a message";
    // bpf_get_current_uid_gid() returns a 64-bit value
    // The 32 most significant bits are the process ID, which
    // has triggered the eBPF routine, while the 32 least
    // significatn bits are the thread ID
    data.pid = bpf_get_current_pid_tgid() >> 32;
    // bpf_get_current_uid_gid() returns a 64-bit value
    // The 32 most significant bits are the user_id
    data.uid = bpf_get_current_uid_gid() & USER_ID_MASK;

    // Use this to get the command name, that is the process
    // which has triggered the execve, and therefore the eBPF program
    // Notice that it is a string!
    bpf_get_current_comm(&data.command, sizeof(data.command));
    // According to the documentation, this is the signature:
    // int bpf_probe_read_kernel(void *dst, int size, const void *src)
    // This copies size bytes from kernel address space to the BPF stack,
    // so that BPF can later operate on it
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
    // At this point the data structure is populated with the process ID, command
    // name, and message. This call to output.perf_submit() puts that data into the
    // map
    output.perf_submit(ctx, &data, sizeof(data));

    return 0;
}