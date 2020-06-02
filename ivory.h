#ifndef __CGELF_IVORY_H__
#define __CGELF_IVORY_H__

#include "cgelf.h"

#define IVORY_MAX_SYMBOL_COUNT 64
#define IVORY_MAX_SYMBOL_NAME_SIZE 64

#if defined(__LP64__)
#define ELFW(what) ELF64_ ## what
#else
#define ELFW(what) ELF32_ ## what
#endif

#define ELF32_R_SYM(val)		    ((val) >> 8)
#define ELF32_R_TYPE(val)		    ((val) & 0xff)
#define ELF32_R_INFO(sym, type)		(((sym) << 8) + ((type) & 0xff))

#define ELF64_R_SYM(i)			    ((i) >> 32)
#define ELF64_R_TYPE(i)			    ((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type)		((((Elf64_Xword) (sym)) << 32) + (type))


struct ivoryHandle {
    void * mmap_start;
    uint64_t load_size;
    uint64_t load_bias;

    int32_t symbol_count;
    char symbol_name[IVORY_MAX_SYMBOL_COUNT][IVORY_MAX_SYMBOL_NAME_SIZE];
    uint64_t symbol_value[IVORY_MAX_SYMBOL_COUNT];
};

void * ivory_open(char * sopath, char * pincode);
void ivory_ls(void * handle);
void * ivory_sym(void * handle, const char * symbol);
int ivory_close(void *handle);

#endif
