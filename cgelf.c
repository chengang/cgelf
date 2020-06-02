#include "cgelf.h"

uint64_t endian_int(int8_t endian, uint8_t * ptr, int8_t len) {
    uint64_t ret = 0;
    if (endian == 'l') {
        for (int i=0; i<len; i++) {
            ret += (*(ptr+i)) << (i*8);
        }
        return ret;
    } else if (endian == 'b') {
        for (int i=0; i<len; i++) {
            ret += (*(ptr+i)) << ((len-i)*8);
        }
        return ret;
    }
    return 987654321098765432; // never get here.
}

struct cgelf * cgelf_alloc(void) {
    struct cgelf * ptr = (struct cgelf *) calloc(1, sizeof(struct cgelf));
    return ptr;
}

void cgelf_free(struct cgelf * ptr) {
    free(ptr->dynsym.ents);
    free(ptr->symtab.ents);
    free(ptr->relocDyn.ents);
    free(ptr->relocPlt.ents);
    free(ptr->sections);
    free(ptr->segments);
    free(ptr->fileContent);
    free(ptr);
    return;
}

bool cgelf_read(struct cgelf * cgelf, char * sopath) {
    FILE * fp = fopen(sopath, "rb");
    fseek(fp, 0, SEEK_END);
    int32_t filesz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    cgelf->fileContent = (uint8_t *) calloc(1, filesz);
    fread(cgelf->fileContent, 1, filesz, fp);
    fclose(fp);

    uint8_t * elf_file = cgelf->fileContent;

    // ELF file header
    if ( 
        ! (elf_file[0] == 0x7f && elf_file[1] == 'E'
        && elf_file[2] == 'L'  && elf_file[3] == 'F')
    ) {
        return false;
    }

    if (elf_file[4] == 1) {
        cgelf->byteWidths = 4;
    } else if (elf_file[4] == 2) {
        cgelf->byteWidths = 8;
    } else {
        return false;
    }

    if (elf_file[5] == 1) {
        cgelf->endian = 'l';
    } else if (elf_file[5] == 2) {
        cgelf->endian = 'b';
    }
    cgelf->version = elf_file[6];
    cgelf->osabi = elf_file[7];

    uint8_t * p = elf_file + EI_NIDENT_SIZE;
    cgelf->hdr.e_type      = endian_int(cgelf->endian, p, ELF32_HALF_SIZE); p += ELF32_HALF_SIZE;
    cgelf->hdr.e_machine   = endian_int(cgelf->endian, p, ELF32_HALF_SIZE); p += ELF32_HALF_SIZE;
    cgelf->hdr.e_version   = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p += ELF32_WORD_SIZE;
    cgelf->hdr.e_entry     = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
    cgelf->hdr.e_phoff     = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
    cgelf->hdr.e_shoff     = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
    cgelf->hdr.e_flags     = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p += ELF32_WORD_SIZE;
    cgelf->hdr.e_ehsize    = endian_int(cgelf->endian, p, ELF32_HALF_SIZE); p += ELF32_HALF_SIZE;
    cgelf->hdr.e_phentsize = endian_int(cgelf->endian, p, ELF32_HALF_SIZE); p += ELF32_HALF_SIZE;
    cgelf->hdr.e_phnum     = endian_int(cgelf->endian, p, ELF32_HALF_SIZE); p += ELF32_HALF_SIZE;
    cgelf->hdr.e_shentsize = endian_int(cgelf->endian, p, ELF32_HALF_SIZE); p += ELF32_HALF_SIZE;
    cgelf->hdr.e_shnum     = endian_int(cgelf->endian, p, ELF32_HALF_SIZE); p += ELF32_HALF_SIZE;
    cgelf->hdr.e_shstrndx  = endian_int(cgelf->endian, p, ELF32_HALF_SIZE); p += ELF32_HALF_SIZE;

    // Sections
    cgelf->sectionCount = cgelf->hdr.e_shnum;
    cgelf->sections = calloc(cgelf->sectionCount, sizeof(struct cgelfSection));
    p = elf_file + cgelf->hdr.e_shoff;
    for (int i=0; i < cgelf->sectionCount; i++) {
        cgelf->sections[i].sh_name       = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p += ELF32_WORD_SIZE;
        cgelf->sections[i].sh_type       = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p += ELF32_WORD_SIZE;
        cgelf->sections[i].sh_flags      = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
        cgelf->sections[i].sh_addr       = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
        cgelf->sections[i].sh_offset     = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
        cgelf->sections[i].sh_size       = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
        cgelf->sections[i].sh_link       = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p += ELF32_WORD_SIZE;
        cgelf->sections[i].sh_info       = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p += ELF32_WORD_SIZE;
        cgelf->sections[i].sh_addralign  = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
        cgelf->sections[i].sh_entsize    = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
        cgelf->sections[i].dataPtr       = elf_file + cgelf->sections[i].sh_offset;

        if (cgelf->sections[i].sh_type == SHT_DYNSYM) {
            cgelf->dynsym.type = SHT_DYNSYM;
            cgelf->dynsym.sectionIdx = i;
            cgelf->dynsym.sectionStrIdx = cgelf->sections[i].sh_link;
            cgelf->dynsym.entCount = cgelf->sections[i].sh_size / cgelf->sections[i].sh_entsize;
            cgelf->dynsym.ents = calloc(cgelf->dynsym.entCount, sizeof(struct cgelfSymbolEntry));
        } 
        else if (cgelf->sections[i].sh_type == SHT_SYMTAB) 
        {
            cgelf->symtab.type = SHT_SYMTAB;
            cgelf->symtab.sectionIdx = i;
            cgelf->symtab.sectionStrIdx = cgelf->sections[i].sh_link;
            cgelf->symtab.entCount = cgelf->sections[i].sh_size / cgelf->sections[i].sh_entsize;
            cgelf->symtab.ents = calloc(cgelf->symtab.entCount, sizeof(struct cgelfSymbolEntry));
        }
        else if (cgelf->sections[i].sh_type == SHT_DYNAMIC) 
        {
            int64_t dynamicEntryCount = cgelf->sections[i].sh_size / cgelf->sections[i].sh_entsize;
            uint8_t * p = cgelf->sections[i].dataPtr;
            for (int i=0; i < dynamicEntryCount; i++) {
                uint64_t d_tag = endian_int(cgelf->endian, p, cgelf->byteWidths); p+=cgelf->byteWidths;
                uint64_t d_val = endian_int(cgelf->endian, p, cgelf->byteWidths); p+=cgelf->byteWidths;
                for (int i=0; i < dynamicEntryCount; i++) {
                    switch (d_tag) {
                        case DT_STRTAB:
                            cgelf->dynamic.strtab = d_val;
                            break;
                        case DT_STRSZ:
                            cgelf->dynamic.strsz  = d_val;
                            break;
                        case DT_SYMTAB:
                            cgelf->dynamic.symtab = d_val;
                            break;
                        case DT_JMPREL:
                            cgelf->dynamic.jmprel = d_val;
                            break;
                        case DT_PLTREL:
                            cgelf->dynamic.pltrel = d_val;
                            break;
                        case DT_PLTRELSZ:
                            cgelf->dynamic.pltrelsz = d_val;
                            break;
                        case DT_RELA:
                            cgelf->dynamic.rela = d_val;
                            break;
                        case DT_RELASZ:
                            cgelf->dynamic.relasz = d_val;
                            break;
                        case DT_RELAENT:
                            cgelf->dynamic.relaent = d_val;
                            break;
                        case DT_REL:
                            cgelf->dynamic.rel = d_val;
                            break;
                        case DT_RELSZ:
                            cgelf->dynamic.relsz = d_val;
                            break;
                        case DT_RELENT:
                            cgelf->dynamic.relent = d_val;
                            break;
                        case DT_INIT:
                            cgelf->dynamic.init = d_val;
                            break;
                        case DT_FINI:
                            cgelf->dynamic.fini = d_val;
                            break;
                        case DT_INIT_ARRAY:
                            cgelf->dynamic.init_array = d_val;
                            break;
                        case DT_INIT_ARRAYSZ:
                            cgelf->dynamic.init_arraysz = d_val;
                            break;
                        case DT_FINI_ARRAY:
                            cgelf->dynamic.fini_array = d_val;
                            break;
                        case DT_FINI_ARRAYSZ:
                            cgelf->dynamic.fini_arraysz = d_val;
                            break;
                        case DT_TEXTREL:
                            cgelf->dynamic.textrel = 1;
                            break;
                        case DT_SYMBOLIC:
                            cgelf->dynamic.symbolic = 1;
                            break;
                        case DT_NEEDED:
                            cgelf->dynamic.needed++;
                            break;
                        case DT_FLAGS:
                            cgelf->dynamic.flags = d_val;
                            break;
                        case DT_VERSYM:
                            cgelf->dynamic.versym = d_val;
                            break;
                        case DT_VERDEF:
                            cgelf->dynamic.verdef = d_val;
                            break;
                        case DT_VERDEFNUM:
                            cgelf->dynamic.verdefnum = d_val;
                            break;
                        case DT_VERNEED:
                            cgelf->dynamic.verneed = d_val;
                            break;
                        case DT_VERNEEDNUM:
                            cgelf->dynamic.verneednum = d_val;
                            break;
                        default:
                            break;
                    }
                }
                if (d_tag == DT_NULL) {
                    break;
                }
            }
        }
        else if (cgelf->sections[i].sh_type == SHT_REL 
                || cgelf->sections[i].sh_type == SHT_RELA ) 
        {
            struct cgelfRelocTable * rt = NULL;
            if (cgelf->sections[i].sh_flags == ( SHF_INFO_LINK | SHF_SHF_ALLOC )
                    && cgelf->sections[i].sh_info != 0 ) {
                rt = &cgelf->relocPlt;
            } else {
                rt = &cgelf->relocDyn;
            }

            rt->type = cgelf->sections[i].sh_type;
            rt->sectionIdx = i;
            rt->sectionStrIdx = 0;
            rt->entCount = cgelf->sections[i].sh_size / cgelf->sections[i].sh_entsize;
            rt->ents = calloc(rt->entCount, sizeof(struct cgelfRelocEntry));
            uint8_t * p = cgelf->sections[i].dataPtr;
            for (int i=0; i< rt->entCount; i++) {
                if (rt->type == SHT_RELA) {
                    rt->ents[i].r_offset = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
                    rt->ents[i].r_info   = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
                    rt->ents[i].r_addend = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
                } else if (SHT_REL == SHT_REL) {
                    rt->ents[i].r_offset = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
                    rt->ents[i].r_info   = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
                } else {
                    return false;  //never will be here.
                }
            }
        }
    }

    // Name sections
    if (0 != cgelf->hdr.e_shstrndx) {
        for (int i=0; i < cgelf->sectionCount; i++) {
            strncpy(cgelf->sections[i].name
                    , (char *) cgelf->sections[cgelf->hdr.e_shstrndx].dataPtr + cgelf->sections[i].sh_name
                    , ELF_MAX_NAME_LEN);
        }
    }

    // Symtabs
    for (int i=0; i<2; i++) {
        struct cgelfSymbolTable * st = NULL;
        if ( 0 == i ) {
            st = &cgelf->symtab;
        } else {
            st = &cgelf->dynsym;
        }
        uint8_t * p = cgelf->sections[st->sectionIdx].dataPtr;
        for (int i=0; i < st->entCount; i++) {
            if (4 == cgelf->byteWidths) {
                st->ents[i].st_name  = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p += ELF32_WORD_SIZE;
                st->ents[i].st_value = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
                st->ents[i].st_size  = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
                st->ents[i].st_info  = endian_int(cgelf->endian, p, sizeof(char)); p += sizeof(char);
                st->ents[i].st_other = endian_int(cgelf->endian, p, sizeof(char)); p += sizeof(char);
                st->ents[i].st_shndx = endian_int(cgelf->endian, p, ELF32_HALF_SIZE); p += ELF32_HALF_SIZE;
            } else if (8 == cgelf->byteWidths) {
                st->ents[i].st_name  = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p += ELF32_WORD_SIZE;
                st->ents[i].st_info  = endian_int(cgelf->endian, p, sizeof(char)); p += sizeof(char);
                st->ents[i].st_other = endian_int(cgelf->endian, p, sizeof(char)); p += sizeof(char);
                st->ents[i].st_shndx = endian_int(cgelf->endian, p, ELF32_HALF_SIZE); p += ELF32_HALF_SIZE;
                st->ents[i].st_value = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
                st->ents[i].st_size  = endian_int(cgelf->endian, p, cgelf->byteWidths); p += cgelf->byteWidths;
            } else {
                return false;
            }
            strncpy(st->ents[i].name
                    , (char *) (cgelf->sections[st->sectionStrIdx].dataPtr + st->ents[i].st_name)
                    , ELF_MAX_NAME_LEN);
        }
    }

    // Segments
    cgelf->segmentCount = cgelf->hdr.e_phnum;
    cgelf->segments = calloc(cgelf->segmentCount, sizeof(struct cgelfSegment));
    p = elf_file + cgelf->hdr.e_phoff;
    for (int i=0; i < cgelf->segmentCount; i++) {
        if (4 == cgelf->byteWidths) {
            cgelf->segments[i].p_type   = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p+=ELF32_WORD_SIZE;
            cgelf->segments[i].p_offset = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p+=ELF32_WORD_SIZE;
            cgelf->segments[i].p_vaddr  = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p+=ELF32_WORD_SIZE;
            cgelf->segments[i].p_paddr  = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p+=ELF32_WORD_SIZE;
            cgelf->segments[i].p_filesz = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p+=ELF32_WORD_SIZE;
            cgelf->segments[i].p_memsz  = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p+=ELF32_WORD_SIZE;
            cgelf->segments[i].p_flags  = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p+=ELF32_WORD_SIZE;
            cgelf->segments[i].p_align  = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p+=ELF32_WORD_SIZE;
        } else if (8 == cgelf->byteWidths) {
            cgelf->segments[i].p_type   = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p+=ELF32_WORD_SIZE;
            cgelf->segments[i].p_flags  = endian_int(cgelf->endian, p, ELF32_WORD_SIZE); p+=ELF32_WORD_SIZE;
            cgelf->segments[i].p_offset = endian_int(cgelf->endian, p, ELF64_WORD_SIZE); p+=ELF64_WORD_SIZE;
            cgelf->segments[i].p_vaddr  = endian_int(cgelf->endian, p, ELF64_WORD_SIZE); p+=ELF64_WORD_SIZE;
            cgelf->segments[i].p_paddr  = endian_int(cgelf->endian, p, ELF64_WORD_SIZE); p+=ELF64_WORD_SIZE;
            cgelf->segments[i].p_filesz = endian_int(cgelf->endian, p, ELF64_WORD_SIZE); p+=ELF64_WORD_SIZE;
            cgelf->segments[i].p_memsz  = endian_int(cgelf->endian, p, ELF64_WORD_SIZE); p+=ELF64_WORD_SIZE;
            cgelf->segments[i].p_align  = endian_int(cgelf->endian, p, ELF64_WORD_SIZE); p+=ELF64_WORD_SIZE;
        }

        cgelf->segments[i].dataPtr = elf_file + cgelf->segments[i].p_offset;
    }

    return true;
}

void cgelf_dump(struct cgelf * cgelf) {
    printf("\n");
    printf("ELF file Header:\n");
    printf("bitWidths:\t%d\n",    cgelf->byteWidths * 8);
    printf("endianness:\t%c\n",   cgelf->endian);
    printf("version:\t%d\n",      cgelf->version);
    printf("osabi:  \t%d\n",      cgelf->osabi);
    printf("e_type: \t%d\n",      cgelf->hdr.e_type);
    printf("e_machine:\t%d\n",    cgelf->hdr.e_machine);
    printf("e_version:\t%d\n",    cgelf->hdr.e_version);
    printf("e_entry:\t0x%02llx\n", cgelf->hdr.e_entry);
    printf("e_phoff:\t%llu\n",     cgelf->hdr.e_phoff);
    printf("e_shoff:\t%llu\n",     cgelf->hdr.e_shoff);
    printf("e_flags:\t%d\n",      cgelf->hdr.e_flags);
    printf("e_ehsize:\t%d\n",     cgelf->hdr.e_ehsize);
    printf("e_phentsize:\t%d\n",  cgelf->hdr.e_phentsize);
    printf("e_phnum:\t%d\n",      cgelf->hdr.e_phnum);
    printf("e_shentsize:\t%d\n",  cgelf->hdr.e_shentsize);
    printf("e_shnum:\t%d\n",      cgelf->hdr.e_shnum);
    printf("e_shstrndx:\t%d\n",   cgelf->hdr.e_shstrndx);

    printf("\n");
    printf("Section Headers:\n");
    printf(" No.                      name         type  flags   addr offset   size   link   info addralign entsize\t\n");
    for (int i=0; i < cgelf->hdr.e_shnum; i++) {
        printf("%3d %20s (%3d) %12d %6lld %6lld %6lld %6lld %6d %6d %6lld %6lld\n"
                , i
                , cgelf->sections[i].name
                , cgelf->sections[i].sh_name
                , cgelf->sections[i].sh_type
                , cgelf->sections[i].sh_flags
                , cgelf->sections[i].sh_addr
                , cgelf->sections[i].sh_offset
                , cgelf->sections[i].sh_size
                , cgelf->sections[i].sh_link
                , cgelf->sections[i].sh_info
                , cgelf->sections[i].sh_addralign
                , cgelf->sections[i].sh_entsize
                );
    }

    printf("\n");
    for (int i=0; i<2; i++) {
        struct cgelfSymbolTable * st = NULL;
        if ( 0 == i ) {
            st = &cgelf->symtab;
        } else {
            st = &cgelf->dynsym;
        }
        printf("Symbol Table (%d):\n", st->type);
        printf(" No.                                              name              value   size   info   type   bind  other  shndx\t\n");
        for (int i=0; i< st->entCount; i++) {
            printf("%3d %50s 0x%016llx %6lld %6d %6d %6d %6d %6d\n"
                    , i
                    , st->ents[i].name
                    , st->ents[i].st_value
                    , st->ents[i].st_size
                    , st->ents[i].st_info
                    , ELFn_ST_TYPE(st->ents[i].st_info)
                    , ELFn_ST_BIND(st->ents[i].st_info)
                    , st->ents[i].st_other
                    , st->ents[i].st_shndx
                  );
        }
    }

    printf("\n");
    for (int i=0; i< 2; i++) {
        struct cgelfRelocTable * rt = NULL;
        if ( 0 == i ) {
            rt = &cgelf->relocDyn;
        } else {
            rt = &cgelf->relocPlt;
        }
        printf("Relocation Etries (%d):\n", rt->type);
        printf(" No.  offset     info   addend\t\n");
        for (int i=0; i< rt->entCount; i++) {
            printf("%3d 0x%06llx 0x%06llx 0x%06llx\n"
                , i
                , rt->ents[i].r_offset
                , rt->ents[i].r_info
                , rt->ents[i].r_addend
                );
        }
    }

    printf("\n");
    printf("Segment Headers:\n");
    printf(" No.      type     offset      vaddr      paddr     filesz      memsz      flags      align\t\n");
    for (int i=0; i < cgelf->hdr.e_phnum; i++) {
        printf("%3d 0x%08x 0x%08llx 0x%08llx 0x%08llx 0x%08llx 0x%08llx 0x%08x 0x%08llx \n"
                , i
                , cgelf->segments[i].p_type
                , cgelf->segments[i].p_offset
                , cgelf->segments[i].p_vaddr
                , cgelf->segments[i].p_paddr
                , cgelf->segments[i].p_filesz
                , cgelf->segments[i].p_memsz
                , cgelf->segments[i].p_flags
                , cgelf->segments[i].p_align
                );
    }
    return;
}
