#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <limits.h>

FILE *logger_fp;

int history_cnt = 0;
int *history_fd = NULL;
int *history_sz = NULL;
char **history = NULL;
int get_history_idx(int fd) {
    for (int i = 0; i < history_cnt; i++)
        if (fd == history_fd[i])
            return i;
    return -1;
}
int update_history(int fd, const char *buf, size_t sz) {
    int history_idx = get_history_idx(fd);
    if (history_idx == -1) {
        history_idx = history_cnt;
        history_cnt++;
        history_fd = realloc(history_fd, history_cnt * sizeof(int));
        history_fd[history_idx] = fd;
        history_sz = realloc(history_sz, history_cnt * sizeof(int));
        history_sz[history_idx] = 0;
        history = realloc(history, history_cnt * sizeof(char *));
        history[history_idx] = malloc(1);
        history[history_idx][0] = '\0';
    }
    history[history_idx] = realloc(history[history_idx], history_sz[history_idx] + sz + 1);
    for (int i = 0; i < sz; i++)
        history[history_idx][history_sz[history_idx] + i] = buf[i];
    history[history_idx][history_sz[history_idx] + sz] = '\0';
    history_sz[history_idx] += (int)sz;
    return history_idx;
}

int open_bl_cnt = 0;
char **open_bl = NULL;
int open_hook(const char *pathname, int flags, mode_t mode) {
    bool blocked = false;
    bool file_exist = false;
    char fullpath[PATH_MAX];
    if (realpath(pathname, fullpath) != NULL) {
        file_exist = true;
        for (int i = 0; i < open_bl_cnt; i++) {
            char bl_fullpath[PATH_MAX];
            if (realpath(open_bl[i], bl_fullpath) != NULL) {
                if (strcmp(fullpath, bl_fullpath) == 0) {
                    blocked = true;
                }
            }
        }
    }
    int ret = blocked ? -1 : open(pathname, flags, mode);
    if ((flags & (O_CREAT | O_TMPFILE)) == 0)
        mode = 0;
    fprintf(logger_fp, "[logger] open(\"%s\", %d, %u) = %d\n", file_exist ? fullpath : pathname, flags, mode, ret);
    if (blocked)
        errno = EACCES;
    return ret;
}

int close_hook(int fd) {
    int history_idx = get_history_idx(fd);
    if (history_idx != -1)
        history_fd[history_idx] = -1;
    return close(fd);
}

bool read_bl_enabled = false;
char *read_bl = NULL;
ssize_t read_hook(int fd, void *buf, size_t count) {
    ssize_t ret = read(fd, buf, count);
    bool blocked = false;
    if (read_bl_enabled && ret > 0) {
        int history_idx = update_history(fd, buf, ret);
        if (strstr(history[history_idx], read_bl) != NULL) {
            blocked = true;
            history_fd[history_idx] = -1;
            close(fd);
            ret = -1;
        }
    }
    if (!blocked) {
        char log_path[PATH_MAX];
        sprintf(log_path, "%d-%d-read.log", getpid(), fd);
        FILE *log_fp = fopen(log_path, "a");
        if (ret > 0)
            fwrite(buf, ret, 1, log_fp);
        fclose(log_fp);
    }
    fprintf(logger_fp, "[logger] read(%d, %p, %lu) = %ld\n", fd, buf, count, ret);
    if (blocked)
        errno = EIO;
    return ret;
}

ssize_t write_hook(int fd, const void *buf, size_t count) {
    ssize_t ret = write(fd, buf, count);
    char log_path[PATH_MAX];
    sprintf(log_path, "%d-%d-write.log", getpid(), fd);
    FILE *log_fp = fopen(log_path, "a");
    if (ret > 0)
        fwrite(buf, ret, 1, log_fp);
    fclose(log_fp);
    fprintf(logger_fp, "[logger] write(%d, %p, %lu) = %ld\n", fd, buf, count, ret);
    return ret;
}

int connect_bl_cnt = 0;
char **connect_bl = NULL;
int connect_hook(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    char addrstr[128] = "\0";
    int port = 0;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &(addr_in->sin_addr), addrstr, 128);
        port = ntohs(addr_in->sin_port);
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), addrstr, 128);
        port = ntohs(addr_in6->sin6_port);
    }
    bool blocked = false;
    for (int i = 0; i < connect_bl_cnt; i++) {
        char bl_hostname[128];
        int bl_port;
        strcpy(bl_hostname, connect_bl[i]);
        for (int j = 0; j < strlen(connect_bl[i]); j++) {
            if (connect_bl[i][j] == ':') {
                bl_hostname[j] = '\0';
                bl_port = atoi(&connect_bl[i][j + 1]);
                break;
            }
        }
        struct addrinfo *ai_res;
        if (getaddrinfo(bl_hostname, NULL, NULL, &ai_res) == 0) {
            for (struct addrinfo *rp = ai_res; rp != NULL; rp = rp->ai_next) {
                char bl_addrstr[128];
                if (rp->ai_family == AF_INET) {
                    struct sockaddr_in *ai_addr_in = (struct sockaddr_in *)rp->ai_addr;
                    inet_ntop(AF_INET, &(ai_addr_in->sin_addr), bl_addrstr, 128);
                } else if (rp->ai_family == AF_INET6) {
                    struct sockaddr_in6 *ai_addr_in6 = (struct sockaddr_in6 *)rp->ai_addr;
                    inet_ntop(AF_INET6, &(ai_addr_in6->sin6_addr), bl_addrstr, 128);
                }
                if (strcmp(addrstr, bl_addrstr) == 0 && port == bl_port)
                    blocked = true;
            }
            freeaddrinfo(ai_res);
        }
    }
    int ret = blocked ? -1 : connect(sockfd, addr, addrlen);
    fprintf(logger_fp, "[logger] connect(%d, \"%s\", %u) = %d\n", sockfd, addrstr, addrlen, ret);
    if (blocked)
        errno = ECONNREFUSED;
    return ret;
}

int getaddrinfo_bl_cnt = 0;
char **getaddrinfo_bl = NULL;
int getaddrinfo_hook(const char *restrict node,
                     const char *restrict service,
                     const struct addrinfo *restrict hints,
                     struct addrinfo **restrict res) {
    bool blocked = false;
    for (int i = 0; i < getaddrinfo_bl_cnt; i++)
        if (strcmp(node, getaddrinfo_bl[i]) == 0)
            blocked = true;
    int ret = blocked ? EAI_NONAME : getaddrinfo(node, service, hints, res);
    fprintf(logger_fp, "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n", node, service, hints, res, ret);
    return ret;
}

int system_hook(const char *command) {
    fprintf(logger_fp, "[logger] system(\"%s\")\n", command);
    return system(command);
}

void parse_multiline(FILE *config_fp, const char *end_str, int *api_bl_cnt, char ***api_bl) {
    char line[8192];
    while (fgets(line, 8192, config_fp) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if (strstr(line, end_str) == line)
            break;
        *api_bl = realloc(*api_bl, (*api_bl_cnt + 1) * sizeof(char *));
        (*api_bl)[*api_bl_cnt] = strdup(line);
        (*api_bl_cnt)++;
    }
}

void parse_config(FILE *config_fp) {
    char line[8192];
    while (fgets(line, 8192, config_fp) != NULL) {
        if (strstr(line, "BEGIN open-blacklist") == line) {
            parse_multiline(config_fp, "END open-blacklist", &open_bl_cnt, &open_bl);
        } else if (strstr(line, "BEGIN read-blacklist") == line) {
            while (fgets(line, 8192, config_fp) != NULL) {
                line[strcspn(line, "\n")] = '\0';
                if (strstr(line, "END read-blacklist") == line)
                    break;
                read_bl_enabled = true;
                read_bl = strdup(line);
            }
        } else if (strstr(line, "BEGIN connect-blacklist") == line) {
            parse_multiline(config_fp, "END connect-blacklist", &connect_bl_cnt, &connect_bl);
        } else if (strstr(line, "BEGIN getaddrinfo-blacklist") == line) {
            parse_multiline(config_fp, "END getaddrinfo-blacklist", &getaddrinfo_bl_cnt, &getaddrinfo_bl);
        }
    }
}

void print_multiline(int api_bl_cnt, char **api_bl) {
    printf("contains %d lines\n", api_bl_cnt);
    for (int i = 0; i < api_bl_cnt; i++)
        printf("[%s]\n", api_bl[i]);
}

void print_config() {
    printf("open: ");
    print_multiline(open_bl_cnt, open_bl);
    printf("read: ");
    printf("[%s]\n", read_bl_enabled ? read_bl : "not found");
    printf("connect: ");
    print_multiline(connect_bl_cnt, connect_bl);
    printf("getaddrinfo: ");
    print_multiline(getaddrinfo_bl_cnt, getaddrinfo_bl);
}

void modify_got(uint64_t lowest_addr, uint64_t got_rel_addr, uint64_t target) {
    uint64_t got_addr = lowest_addr + got_rel_addr;
    int page_size = getpagesize();
    uint64_t page_start_addr = got_addr - (got_addr % page_size);
    if (mprotect((void*)page_start_addr, page_size, PROT_READ | PROT_WRITE) != 0)
        exit(EXIT_FAILURE);
    *(uint64_t *)(got_addr) = target;
}

int (*main_orig)(int, char **, char **);
int main_hook(int argc, char **argv, char **envp) {
    {
        char *sandbox_config = getenv("SANDBOX_CONFIG");
        char *logger_fd = getenv("LOGGER_FD");
        if (sandbox_config == NULL || logger_fd == NULL)
            exit(EXIT_FAILURE);
        logger_fp = fdopen(atoi(logger_fd), "w");
        FILE *f = fopen(sandbox_config, "r");
        if (f == NULL)
            exit(EXIT_FAILURE);
        parse_config(f);
        fclose(f);
    }

    uint64_t lowest_addr;
    {
        char lowest[17];
        char *lowest_curr = lowest;
        FILE *f = fopen("/proc/self/maps", "r");
        for (char c; (c = (char)fgetc(f)) != '-'; lowest_curr++)
            *lowest_curr = c;
        *lowest_curr = '\0';
        fclose(f);
        lowest_addr = strtoull(lowest, NULL, 16);
    }

    {
        FILE *f = fopen("/proc/self/exe", "r");
        Elf64_Ehdr eh;
        fread(&eh, sizeof(Elf64_Ehdr), 1, f);
        Elf64_Off e_shoff = eh.e_shoff;
        uint16_t e_shnum = eh.e_shnum;
        fseek(f, (long)e_shoff, SEEK_SET);
        Elf64_Shdr sh[e_shnum];
        fread(sh, sizeof(Elf64_Shdr), e_shnum, f);
        for (int i = 0; i < e_shnum; i++) {
            if (sh[i].sh_type == SHT_REL || sh[i].sh_type == SHT_RELA) {
                uint32_t dynsym_idx = sh[i].sh_link;
                Elf64_Off dynsym_off = sh[dynsym_idx].sh_offset;
                Elf64_Off dynsym_size = sh[dynsym_idx].sh_size / sh[dynsym_idx].sh_entsize;

                uint32_t dynstr_idx = sh[dynsym_idx].sh_link;
                Elf64_Off dynstr_off = sh[dynstr_idx].sh_offset;
                Elf64_Off dynstr_size = sh[dynstr_idx].sh_size;

                Elf64_Sym dynsym[dynsym_size];
                fseek(f, (long)dynsym_off, SEEK_SET);
                fread(dynsym, sizeof(Elf64_Sym), dynsym_size, f);

                char dynstr[dynstr_size];
                fseek(f, (long)dynstr_off, SEEK_SET);
                fread(dynstr, sizeof(char), dynstr_size, f);

                Elf64_Off rela_off = sh[i].sh_offset;
                uint64_t rela_size = sh[i].sh_size / sh[i].sh_entsize;
                Elf64_Rela rela[rela_size];
                fseek(f, (long)rela_off, SEEK_SET);
                if (sh[i].sh_type == SHT_REL) {
                    Elf64_Rel rel[rela_size];
                    fread(rel, sizeof(Elf64_Rel), rela_size, f);
                    for (int j = 0; j < rela_size; j++) {
                        rela[j].r_info = rel[j].r_info;
                        rela[j].r_offset = rel[j].r_offset;
                        rela[j].r_addend = 0;
                    }
                } else {
                    fread(rela, sizeof(Elf64_Rela), rela_size, f);
                }

                for (int j = 0; j < rela_size; j++) {
                    Elf64_Off off = rela[j].r_offset;
                    uint64_t type = ELF64_R_TYPE(rela[j].r_info);
                    uint64_t sym = ELF64_R_SYM(rela[j].r_info);
                    if (type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT) {
                        char *sym_str = &dynstr[dynsym[sym].st_name];
                        if (strcmp(sym_str, "open") == 0)
                            modify_got(lowest_addr, off, (uint64_t)&open_hook);
                        else if (strcmp(sym_str, "close") == 0)
                            modify_got(lowest_addr, off, (uint64_t)&close_hook);
                        else if (strcmp(sym_str, "read") == 0)
                            modify_got(lowest_addr, off, (uint64_t)&read_hook);
                        else if (strcmp(sym_str, "write") == 0)
                            modify_got(lowest_addr, off, (uint64_t)&write_hook);
                        else if (strcmp(sym_str, "connect") == 0)
                            modify_got(lowest_addr, off, (uint64_t)&connect_hook);
                        else if (strcmp(sym_str, "getaddrinfo") == 0)
                            modify_got(lowest_addr, off, (uint64_t)&getaddrinfo_hook);
                        else if (strcmp(sym_str, "system") == 0)
                            modify_got(lowest_addr, off, (uint64_t)&system_hook);
                    }
                }
            }
        }
        fclose(f);
    }

    int ret = main_orig(argc, argv, envp);
    fclose(logger_fp);
    return ret;
}

int __libc_start_main(
        int (*main)(int, char **, char **),
        int argc,
        char **argv,
        void (*init)(void),
        void (*fini)(void),
        void (*rtld_fini)(void),
        void *stack_end) {
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    typeof(&__libc_start_main) libc_start_main_orig = dlsym(handle, "__libc_start_main");
    main_orig = main;
    return libc_start_main_orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}
