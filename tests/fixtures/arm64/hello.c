/* Freestanding ARM64 guest that writes to stdout and exit_group(0). */
void _start(void) {
    const char msg[] = "hello from rnidbg\n";
    register long x0 asm("x0") = 1;
    register long x1 asm("x1") = (long)msg;
    register long x2 asm("x2") = sizeof(msg) - 1;
    register long x8 asm("x8") = 64; /* write */
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    x0 = 0;
    x8 = 94; /* exit_group */
    asm volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    __builtin_unreachable();
}
