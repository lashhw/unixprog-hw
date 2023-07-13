# unixprog-hw
NYCU 2023 Spring "Advanced Programming in the UNIX Environment" Homework

## HW1: Secured API Call ([spec](hw1/spec.pdf))
* library injection (by hijacking `__libc_start_main()`)
* API hijacking (including `open()`, `read()`, `write()`, `connect()`, `getaddrinfo()`, `system()`)
* GOT hijacking
* ELF parsing
* `open()`, `read()`, `connect()`, `getaddrinfo()` blacklist
## HW2: Simple Instruction Level Debugger ([spec](hw2/spec.pdf))
* instruction disassemble
* implement common gdb command such as `si`, `cont`, `break`
* set breakpoint by `int3` software interrupt 
* implement `timetravel` via `fork()`
