/* Libc-linked ARM64 PIE. Runs through bionic crt (`__libc_init` + `main`)
 * and prints a fixed phrase via libc `write`. Runtime libc is the API 36
 * image under android/sdk36, not the NDK stub.
 *
 * Build:
 *   aarch64-linux-android35-clang -fPIE -pie -fno-builtin -O1 \
 *     -o tests/fixtures/arm64/printf tests/fixtures/arm64/printf.c
 */
#include <unistd.h>

int main(void) {
    const char msg[] = "complete pie from rnidbg\n";
    write(1, msg, sizeof(msg) - 1);
    return 0;
}
