#include "qemu/osdep.h"
#include "hijack.h"
// 包含其他必要的头文件

// 实现你的函数
FILE *ss_log_file = NULL;
pthread_mutex_t ss_mutex;

char * socket_path = NULL;
int qemu_fd = 0;
int handler_fd = 0;
size_t now_pid = 0;

void test(void) {
    printf("haha\n");
    return;
}

void lock_list(void) {
    pthread_mutex_lock(&ss_mutex);
    return;
}

void unlock_list(void) {
    pthread_mutex_unlock(&ss_mutex);
    return;
}

void init_logger(void) {
    ss_log_file = fopen("debug.log", "a");
    if (ss_log_file == NULL) {
        printf("无法打开日志文件!\n");
    }
}
void log_debug(const char *format, ...) {
    if (ss_log_file == NULL) return;
    
    va_list args;
    va_start(args, format);
    
    // 添加时间戳
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(ss_log_file, "[%04d-%02d-%02d %02d:%02d:%02d] ",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec);
    
    vfprintf(ss_log_file, format, args);
    fprintf(ss_log_file, "\n");
    fflush(ss_log_file); // 确保立即写入文件
    
    va_end(args);
}

void close_logger(void) {
    if (ss_log_file != NULL) {
        fclose(ss_log_file);
        ss_log_file = NULL;
    }
}

size_t gen_hash(void) {
    size_t random_num = 0;
    random_num = (unsigned long long)rand();
    random_num = (random_num << 31) | (unsigned long long)rand();
    random_num = (random_num << 31) | (unsigned long long)rand();
    random_num = random_num & 0xFFFFFFFFFFFFFFFF;
    return random_num;
}





void update_pid(void) {
    now_pid = getpid();
    // free(socket_path);
    if (socket_path == NULL)
        socket_path = (char*)malloc(0x100);
    snprintf(socket_path, 0x80, "./socket_dir/SFE_%d.socket\x00", (int)now_pid);
    log_debug("[update_pid] new pid is %llx", now_pid);
    struct sockaddr_un server_addr, client_addr;
    socklen_t client_len;

    if ((qemu_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        log_debug("[update_pid] socket error");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, socket_path, sizeof(server_addr.sun_path) - 1);

    // Remove socket file if it already exists
    unlink(socket_path);
    // Create socket directory if it doesn't exist
    char dir_path[0x80] = "./socket_dir";
    struct stat st = {0};
    if (stat(dir_path, &st) == -1) {
        mkdir(dir_path, 0700);
    }
    // create socket file
    if (bind(qemu_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        log_debug("[update_pid] bind error: %s", strerror(errno));
        close(qemu_fd);
        exit(EXIT_FAILURE);
    }
    if (listen(qemu_fd, 5) == -1) {
        log_debug("[update_pid] listen error");
        close(qemu_fd);
        exit(EXIT_FAILURE);
    }
    client_len = sizeof(client_addr);
    if ((handler_fd = accept(qemu_fd, (struct sockaddr*)&client_addr, &client_len)) == -1) {
        log_debug("[update_pid] accept error");
        close(qemu_fd);
        exit(EXIT_FAILURE);
    }
    return;
}


void send_data(struct syscall_request * data, int current_id) {
    data->request_id = current_id;
    log_debug("[send_data] send syscall 0x%llx, is_need_hijack is 0x%llx", data->sysall_num, data->is_need_hijack);
    if (write(handler_fd, data, sizeof(struct syscall_request)) == -1) {
        log_debug("[send_data] send failed.");
        close(qemu_fd);
        close(handler_fd);
        exit(EXIT_FAILURE);
    }
    return;
}

void recv_data(struct syscall_request * ans) {
    size_t recv_cnt = read(handler_fd, ans, sizeof(struct syscall_request));
    log_debug("[recv_data] recv syscall 0x%llx, is_need_hijack is 0x%llx", ans->sysall_num, ans->is_need_hijack);
    if (recv_cnt <= 0) {
        log_debug("[recv_data] recv failed.");
        close(qemu_fd);
        close(handler_fd);
        exit(EXIT_FAILURE);
    }
    return;
}

void clean_socket(void) {
    unlink(socket_path);
    return;
}


