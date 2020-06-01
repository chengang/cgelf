#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "cgelf.h"

int main(int argc, char *argv[]) {
    struct cgelf * elf = cgelf_alloc();
    if (cgelf_read(elf, argv[1]) == false) {
        printf("not valied elf file.\n");
    } else {
        cgelf_dump(elf);
    }

    cgelf_free(elf);
    return EXIT_SUCCESS;
}
