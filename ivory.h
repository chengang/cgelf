#ifndef __CGELF_IVORY_H__
#define __CGELF_IVORY_H__

#include "cgelf.h"

#define IVORY_MAX_SYMBOL_COUNT 64
#define IVORY_MAX_SYMBOL_NAME_SIZE 64

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
