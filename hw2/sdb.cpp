#include <algorithm>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <cerrno>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <capstone/capstone.h>

long peektext(pid_t pid, unsigned long long addr) {
    errno = 0;
    long ret = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
    if (ret == -1 && errno != 0)
        assert(false);
    return ret;
}

struct user_regs_struct get_regs(pid_t pid) {
    struct user_regs_struct regs{};
    assert(ptrace(PTRACE_GETREGS, pid, 0, &regs) != -1);
    return regs;
}

int main(int argc, char *argv[]) {
    assert(argc >= 2);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(ptrace(PTRACE_TRACEME, 0, 0, 0) != -1);
        assert(execvp(argv[1], &argv[1]) != -1);
    } else {
        int status;
        unsigned long long start;
        {
            assert(waitpid(child, &status, 0) != -1);
            assert(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK) != -1);
            struct user_regs_struct regs = get_regs(child);
            start = regs.rip;
            printf("** program '%s' loaded. entry point 0x%llx\n", argv[1], start);
        }

        char buf[4096];
        auto lbuf = (long *)buf;

        unsigned long long end;
        {
            sprintf(buf, "readelf -S /proc/%d/exe", child);
            FILE *fp = popen(buf, "r");
            assert(fp != nullptr);
            unsigned long long size = 0;
            while (fgets(buf, sizeof(buf), fp) != nullptr) {
                if (strstr(buf, " .text ") != nullptr) {
                    fgets(buf, sizeof(buf), fp);
                    size = strtoull(buf, nullptr, 16);
                    break;
                }
            }
            pclose(fp);
            assert(size != 0);
            end = start + size;
        }

        csh handle;
        assert(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK);

        bool print_hit_brkpt = true;
        bool print_insn = true;
        unsigned long anchor_child = -1;
        std::unordered_map<unsigned long long, char> breakpoint;
        while (WIFSTOPPED(status)) {
            {
                struct user_regs_struct regs = get_regs(child);
                if (WSTOPSIG(status) == SIGTRAP) {
                    siginfo_t info;
                    assert(ptrace(PTRACE_GETSIGINFO, child, 0, &info) != -1);
                    if ((info.si_code != TRAP_TRACE) && breakpoint.count(regs.rip - 1) != 0) {
                        regs.rip -= 1;
                        assert(ptrace(PTRACE_SETREGS, child, 0, &regs) != -1);
                    }
                }

                if (print_hit_brkpt)
                    if (breakpoint.count(regs.rip) != 0)
                        printf("** hit a breakpoint at 0x%llx\n", regs.rip);

                if (print_insn) {
                    // get instructions
                    for (int i = 0; i < 10; i++) {
                        unsigned long long curr_addr = regs.rip + i * 8;
                        if (curr_addr >= end)
                            break;
                        lbuf[i] = peektext(child, curr_addr);
                    }
                    unsigned long long bufsz = std::min(end, regs.rip + 80) - regs.rip;
                    for (unsigned long long i = 0; i < bufsz; i++) {
                        auto it = breakpoint.find(regs.rip + i);
                        if (it != breakpoint.end())
                            buf[i] = it->second;
                    }

                    // disassemble
                    cs_insn *insn;
                    size_t count = cs_disasm(handle, (uint8_t *)buf, bufsz, regs.rip, 5, &insn);
                    for (size_t i = 0; i < count; i++) {
                        printf("%12lx: ", insn[i].address);
                        for (int j = 0; j < 15; j++) {
                            if (j >= insn[i].size)
                                printf("   ");
                            else
                                printf("%02x ", insn[i].bytes[j]);
                        }
                        printf("%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
                    }
                    if (count < 5)
                        puts("** the address is out of the range of the text segment.");
                    cs_free(insn, count);
                }
            }

            std::string line;
            printf("(sdb) ");
            if (!getline(std::cin, line))
                return 0;

            std::stringstream ss(line);
            ss >> buf;

            enum { SI, CONT, BREAK, ANCHOR, TIMETRAVEL, UNKNOWN } command;
            if (strcmp(buf, "si") == 0)
                command = SI;
            else if (strcmp(buf, "cont") == 0)
                command = CONT;
            else if (strcmp(buf, "break") == 0)
                command = BREAK;
            else if (strcmp(buf, "anchor") == 0)
                command = ANCHOR;
            else if (strcmp(buf, "timetravel") == 0)
                command = TIMETRAVEL;
            else
                command = UNKNOWN;

            print_hit_brkpt = false;
            print_insn = false;
            if (command == SI || command == CONT) {
                print_hit_brkpt = true;
                print_insn = true;
                struct user_regs_struct regs = get_regs(child);
                if (breakpoint.count(regs.rip) != 0) {
                    unsigned long long int3_addr = regs.rip;
                    long int3_code = peektext(child, regs.rip);
                    // restore
                    long code = int3_code;
                    *(char *)(&code) = breakpoint[regs.rip];
                    assert(ptrace(PTRACE_POKETEXT, child, regs.rip, code) != -1);
                    // single-step
                    assert(ptrace(PTRACE_SINGLESTEP, child, 0, 0) != -1);
                    assert(waitpid(child, &status, 0) != -1);
                    // put int3 back
                    assert(ptrace(PTRACE_POKETEXT, child, int3_addr, int3_code) != -1);
                } else {
                    assert(ptrace(PTRACE_SINGLESTEP, child, 0, 0) != -1);
                    assert(waitpid(child, &status, 0) != -1);
                }
                if (command == CONT) {
                    assert(ptrace(PTRACE_CONT, child, 0, 0) != -1);
                    assert(waitpid(child, &status, 0) != -1);
                }
            } else if (command == BREAK) {
                ss >> buf;
                unsigned long long target = strtoull(buf, nullptr, 16);
                printf("** set a breakpoint at 0x%llx\n", target);
                long code = peektext(child, target);
                breakpoint[target] = *(char *)(&code);
                *(char *)(&code) = '\xcc';
                assert(ptrace(PTRACE_POKETEXT, child, target, code) != -1);
            } else if (command == ANCHOR || command == TIMETRAVEL) {
                if (command == ANCHOR) {
                    puts("** dropped an anchor");
                } else {
                    print_insn = true;
                    puts("** go back to the anchor point");
                    child = (pid_t)anchor_child;
                    // patch breakpoint
                    for (auto b : breakpoint) {
                        long code = peektext(child, b.first);
                        *(char *)(&code) = '\xcc';
                        assert(ptrace(PTRACE_POKETEXT, child, b.first, code) != -1);
                    }
                }

                struct user_regs_struct regs = get_regs(child);
                long code = peektext(child, regs.rip);
                struct user_regs_struct new_regs = regs;
                new_regs.rax = 57;
                assert(ptrace(PTRACE_SETREGS, child, 0, &new_regs) != -1);
                assert(ptrace(PTRACE_POKETEXT, child, regs.rip, 0xcc050f) != -1);  // patch syscall + int3
                assert(ptrace(PTRACE_CONT, child, 0, 0) != -1);
                assert(waitpid(child, &status, 0) != -1);
                assert(ptrace(PTRACE_GETEVENTMSG, child, 0, &anchor_child) != -1);
                assert(waitpid(anchor_child, nullptr, 0) != -1);
                assert(ptrace(PTRACE_CONT, child, 0, 0) != -1);  // stop at int3
                assert(ptrace(PTRACE_CONT, anchor_child, 0, 0) != -1);  // stop at int3
                assert(waitpid(child, &status, 0) != -1);
                assert(waitpid(anchor_child, nullptr, 0) != -1);
                // revert patch
                assert(ptrace(PTRACE_SETREGS, child, 0, &regs) != -1);
                assert(ptrace(PTRACE_POKETEXT, child, regs.rip, code) != -1);
                assert(ptrace(PTRACE_SETREGS, anchor_child, 0, &regs) != -1);
                assert(ptrace(PTRACE_POKETEXT, anchor_child, regs.rip, code) != -1);
            }
        }

        puts("** the target program terminated.");
        cs_close(&handle);
    }
    return 0;
}
