#ifndef HIJACK_H
#define HIJACK_H

struct syscall_request {
    size_t sysall_num;
    size_t arg[8];
    size_t hash;
    size_t is_need_hijack;
    size_t operation_list_length;
    size_t have_ret;
    size_t ret;
    size_t pid;
    size_t request_id;
    char *operation_list;
    // 添加寄存器信息字段
    size_t registers[32];  // 足够大的数组来存储所有寄存器
    char arch_name[16];       // 架构名称 (x86, arm, etc.)
};

extern FILE *ss_log_file;
extern pthread_mutex_t ss_mutex;
extern char * socket_path;
extern size_t now_pid;
extern int qemu_fd;
extern int handler_fd;
// 声明你要实现的函数
void test(void);
void lock_list(void);
void unlock_list(void);
void init_logger(void);
void log_debug(const char *format, ...);
void close_logger(void);
size_t gen_hash(void);
// void get_cpu_registers(CPUState *cpu, void *cpu_env, struct syscall_request *request);
void update_pid(void);
void clean_socket(void);
void send_data(struct syscall_request * data, int current_id);
void recv_data(struct syscall_request * ans);

#endif /* MY_SYSCALLS_H */