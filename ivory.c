#include "ivory.h"

struct ivoryHandle * ivh_alloc(void) {
    struct ivoryHandle * handle = (struct ivoryHandle *) calloc(1, sizeof(struct ivoryHandle));
    return handle;
}

void ivh_free(struct ivoryHandle * handle) {
    munmap(handle->mmap_start, handle->load_size);
    free(handle);
    return;
}

bool ivh_load(struct ivoryHandle *handle, const struct cgelf *cgelf) {
    uint8_t * elf_content = cgelf->fileContent;
    // ReserveAddressSpace
    uint64_t min_vaddr = 18446744073709551615UL; //UINTPTR_MAX
    uint64_t max_vaddr = 0;
    for (int i=0; i < cgelf->hdr.e_phnum; i++) {
        if (cgelf->segments[i].p_type != PT_LOAD) {
            continue;
        }

        if (min_vaddr > cgelf->segments[i].p_vaddr) {
            min_vaddr = cgelf->segments[i].p_vaddr;
        }

        if (max_vaddr < cgelf->segments[i].p_vaddr + cgelf->segments[i].p_memsz) {
            max_vaddr = cgelf->segments[i].p_vaddr + cgelf->segments[i].p_memsz;
        }

        min_vaddr = PAGE_START(min_vaddr);
        max_vaddr = PAGE_END(max_vaddr);
    }
    uint64_t load_size = max_vaddr - min_vaddr;
    size_t start = (size_t) mmap((void *)min_vaddr, load_size, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (start == -1) {
        fprintf(stderr, "mmap failed\n");
        return false;
    }
    memset((void *)start, 0, load_size);
    if ( 0 != mprotect((void *)start, load_size, PROT_READ) ) {
        fprintf(stderr, "mprotect failed\n");
        return false;
    }
    uint64_t load_bias = (uint64_t) start - min_vaddr;
    handle->mmap_start = (void *) start;

    //printf("min_vaddr:[%llx], max_vaddr:[%llx], load_size:[%llx], start:[%zx], load_bias:[%llx]\n", min_vaddr, max_vaddr, load_size, start, load_bias);

    // LoadSegments
    for (int i=0; i < cgelf->hdr.e_phnum; i++) {
        if (cgelf->segments[i].p_type != PT_LOAD) {
            continue;
        }

        uint64_t seg_start       = load_bias + cgelf->segments[i].p_vaddr;
        uint64_t seg_end         = seg_start + cgelf->segments[i].p_memsz;
        uint64_t seg_page_start  = PAGE_START(seg_start);
        uint64_t seg_page_end    = PAGE_END(seg_end);
        uint64_t seg_file_end    = seg_start + cgelf->segments[i].p_filesz;

        uint64_t file_start      = cgelf->segments[i].p_offset;
        uint64_t file_end        = file_start + cgelf->segments[i].p_filesz;
        uint64_t file_page_start = PAGE_START(file_start);
        uint64_t file_length     = file_end - file_page_start;

        int prot = PFLAGS_TO_PROT(cgelf->segments[i].p_flags);
        // W + E PT_LOAD segments are not allowed.
        if ((prot & (PROT_EXEC | PROT_WRITE)) == (PROT_EXEC | PROT_WRITE)) {
            printf("pror invaild\n");
            return false;
        }

        if ( 0 != mprotect((void *)seg_page_start, file_length, PROT_WRITE) ) {
            fprintf(stderr, "mprotect failed\n");
            return false;
        }
        //fprintf(stderr, "memcpy: %p, %p, %x, end: %p\n", (void *)seg_page_start, elf_content + file_start, file_length, (void*) seg_page_start + file_length);
        if ( NULL == memcpy((void *)seg_page_start, elf_content + file_start, file_length)) {
            fprintf(stderr, "memcpy failed\n");
            return false;
        }
        if ( 0 != mprotect((void *)seg_page_start, file_length, prot) ) {
            fprintf(stderr, "mprotect failed\n");
            return false;
        }
        
        seg_file_end = PAGE_END(seg_file_end);
        //printf(".bss if [0x%x, 0x%x]\n", seg_page_end, seg_file_end);
        if (seg_page_end > seg_file_end) {
            printf(".bss start\n");
            size_t zeromap_size = seg_page_end - seg_file_end;
            void* zeromap = mmap((void*)seg_file_end,
                    zeromap_size,
                    PROT_READ | PROT_WRITE,
                    MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,
                    -1,
                    0);
            if (zeromap == MAP_FAILED) {
                return false;
            }

            prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, zeromap, zeromap_size, ".bss");
        }
    }

    // FindPhdr
    // Todo... force phdr is the first loadable segment now.

    handle->load_bias = load_bias;
    handle->load_size = load_size;

    //printf("elf load ok\n");
    return true;
}

bool ivh_relocate(struct ivoryHandle *handle, struct cgelf *cgelf, uintptr_t rel_start, uintptr_t rel_count, int8_t rel_entsz) {
    //printf("%x, %d, %d\n", rel_start, rel_count, rel_entsz);
    //void * rel_ptr = (void *) rel_start;
    for(int i=0; i<rel_count; i++) {
        size_t *p = (size_t *) (handle->load_bias + rel_start + i * rel_entsz);
        //fprintf(stderr, "[%p][%d]\n", p, cgelf->dynamic.pltrel);
        size_t offset = *p; p++;
        size_t info = *p;
        size_t type = ELFW(R_TYPE)(info);
        size_t sym  = ELFW(R_SYM)(info);
        char sym_name[IVORY_MAX_SYMBOL_NAME_SIZE];
        memset(sym_name, 0, IVORY_MAX_SYMBOL_NAME_SIZE);
        if (sym != 0) {
            strncpy(sym_name, cgelf->dynsym.ents[sym].name, IVORY_MAX_SYMBOL_NAME_SIZE);
        }

        size_t addend = 0;
        size_t reloc = handle->load_bias + offset;
        if (cgelf->dynamic.pltrel == DT_REL) { // rel
            addend = *(size_t *)reloc;
        } else if (cgelf->dynamic.pltrel == DT_RELA) { //rela
            p++;
            addend = *p;
        } else {
            return false;
        }

        //fprintf(stderr, "0rel offset: 0x%x, info: 0x%x, type: 0x%x, sym: %d, reloc: 0x%x, reloc-value: 0x%x, load_bias: 0x%llx\n", offset, info, type, sym, reloc, *(uint32_t *)reloc, d->load_bias);
        switch(type) {
            case R_ARM_GLOB_DAT:
                //*(uintptr_t *)reloc = &__sF;
                break;
            case R_ARM_RELATIVE:
                *(uintptr_t *)reloc = *(uintptr_t *) reloc + handle->load_bias;
                break;
            case R_ARM_JUMP_SLOT:
                if (0 == strcmp("printf", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) printf;
                //} else if (0 == strcmp("__cxa_finalize", sym_name)) {
                //    *(uint32_t *)reloc = (uint32_t) __cxa_finalize;
                } else if (0 == strcmp("strlen", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) strlen;
                } else if (0 == strcmp("putchar", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) putchar;
                } else if (0 == strcmp("fopen", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) fopen;
                } else if (0 == strcmp("fseek", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) fseek;
                } else if (0 == strcmp("ftell", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) ftell;
                } else if (0 == strcmp("fclose", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) fclose;
                } else if (0 == strcmp("fread", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) fread;
                } else if (0 == strcmp("fwrite", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) fwrite;
                } else if (0 == strcmp("calloc", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) calloc;
                } else if (0 == strcmp("free", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) free;
                } else if (0 == strcmp("memcmp", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) memcmp;
                } else if (0 == strcmp("strcpy", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) strcpy;
                } else if (0 == strcmp("atoi", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) atoi;
                } else if (0 == strcmp("strcmp", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) strcmp;
                } else if (0 == strcmp("strchr", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) strchr;
                } else if (0 == strcmp("malloc", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) malloc;
                } else if (0 == strcmp("memset", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) memset;
                } else if (0 == strcmp("strncpy", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) strncpy;
                } else if (0 == strcmp("fprintf", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) fprintf;
                } else if (0 == strcmp("fputc", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) fputc;
                } else if (0 == strcmp("realloc", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) realloc;
                } else if (0 == strcmp("rewind", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) rewind;
                } else if (0 == strcmp("fputs", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) fputs;
                } else if (0 == strcmp("time", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) time;
                } else if (0 == strcmp("clock", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) clock;
                } else if (0 == strcmp("getenv", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) getenv;
                } else if (0 == strcmp("remove", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) remove;
                } else if (0 == strcmp("lrand48", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) lrand48;
                } else if (0 == strcmp("puts", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) puts;
                } else if (0 == strcmp("raise", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) raise;
                } else if (0 == strcmp("abort", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) abort;
                } else if (0 == strcmp("memcpy", sym_name)) {
                    *(uintptr_t *)reloc = (uintptr_t) memcpy;
                }
                break;
            default:
                break;
        }
        //fprintf(stderr, "1rel offset: 0x%x, info: 0x%x, type: 0x%x, sym: %d, reloc: 0x%x, reloc-value: 0x%x, load_bias: 0x%llx\n" , offset, info, type, sym, reloc, *(uint32_t *)reloc, d->load_bias);
    }
    return true;
}

bool ivh_link(struct ivoryHandle *handle, struct cgelf *cgelf) {
    int32_t relentsz = 0;
    if (cgelf->dynamic.rel != 0) {
        //printf("have rel.dyn.\n");
        relentsz = cgelf->dynamic.relent;
        int32_t rel_count = cgelf->dynamic.relsz / relentsz;
        ivh_relocate(handle, cgelf, cgelf->dynamic.rel, rel_count, relentsz);
    } else if (cgelf->dynamic.rela != 0) {
        //printf("have rela.dyn.\n");
        relentsz = cgelf->dynamic.relaent;
        int32_t rela_count = cgelf->dynamic.relasz / relentsz;
        ivh_relocate(handle, cgelf, cgelf->dynamic.rela, rela_count, relentsz);
    } else {
        return false;
    }

    if (cgelf->dynamic.jmprel != 0) {
        //printf("have rel.plt.\n");
        int32_t jmprel_count = cgelf->dynamic.pltrelsz / relentsz;
        ivh_relocate(handle, cgelf, cgelf->dynamic.jmprel, jmprel_count, relentsz);
    }

    struct cgelfSymbolTable * st = &cgelf->dynsym;
    handle->symbol_count = 0;
    for (int i=0; i<st->entCount; i++) {
        if (st->ents[i].st_size == 0) {
            continue;
        }
        strncpy( handle->symbol_name[handle->symbol_count], st->ents[i].name, IVORY_MAX_SYMBOL_NAME_SIZE);
        handle->symbol_value[handle->symbol_count] = st->ents[i].st_value;
        handle->symbol_count++;
        //printf("%d: %s\n", h->symbol_count, h->symbol_name[h->symbol_count]);
    }

    return true;
}

void * ivory_open(char * sopath, char * pincode) {
    struct cgelf * elf = cgelf_alloc();
    if (cgelf_read(elf, sopath) == false) {
        return NULL;
    }

    struct ivoryHandle * handle = ivh_alloc();
    ivh_load(handle, elf);
    ivh_link(handle, elf);

    cgelf_free(elf);
    return handle;
}

void ivory_ls(void * h) {
    struct ivoryHandle *handle = (struct ivoryHandle *) h;
    printf("load_bias: 0x%llx, load_size: 0x%llx\n", handle->load_bias, handle->load_size);
    for (int i=0; i<handle->symbol_count; i++) {
        printf("%d: %s \t %p\n", i, handle->symbol_name[i], (void *)(handle->load_bias + handle->symbol_value[i]));
    }
}

void *ivory_sym(void * h, const char * symbol) {
    struct ivoryHandle *handle = (struct ivoryHandle *) h;
    for (int i=0; i<handle->symbol_count; i++) {
        //printf("found symbol: [%s]-[%s]\n", handle->symbol_name[i], symbol);
        if (strncmp(handle->symbol_name[i], symbol, IVORY_MAX_SYMBOL_NAME_SIZE) == 0 ) {
            return (void *) (handle->load_bias + handle->symbol_value[i]);
        }
    }
    return NULL;
}

int ivory_close(void * handle) {
    ivh_free((struct ivoryHandle *) handle);
    return 0;
}
