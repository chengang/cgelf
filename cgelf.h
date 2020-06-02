#ifndef __CGELF__H__
#define __CGELF__H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#define EI_NIDENT_SIZE      16
#define ELF32_HALF_SIZE     2
#define ELF32_WORD_SIZE     4
#define ELF64_WORD_SIZE     8
#define ELF_MAX_NAME_LEN    64

// below system macros

#define PR_SET_VMA   0x53564d41
#define PR_SET_VMA_ANON_NAME    0

#define R_ARM_GLOB_DAT      21
#define R_ARM_JUMP_SLOT     22
#define R_ARM_RELATIVE      23

#define PAGE_SIZE 4096
#define PAGE_MASK (~(PAGE_SIZE - 1))
// Returns the address of the page containing address 'x'.
#define PAGE_START(x) ((x) & PAGE_MASK)
// Returns the offset of address 'x' in its page.
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
// Returns the address of the next page after address 'x', unless 'x' is itself at the start of a page.
#define PAGE_END(x) PAGE_START((x) + (PAGE_SIZE-1))

#define PF_X        (1 << 0)    /* Segment is executable */
#define PF_W        (1 << 1)    /* Segment is writable */
#define PF_R        (1 << 2)    /* Segment is readable */
#define PROT_READ   0x1     /* Page can be read.  */
#define PROT_WRITE  0x2     /* Page can be written.  */
#define PROT_EXEC   0x4     /* Page can be executed.  */
#define PROT_NONE   0x0     /* Page can not be accessed.  */
#define PROT_GROWSDOWN  0x01000000  /* Extend change to start of growsdown vma (mprotect only).  */
#define PROT_GROWSUP 0x02000000  /* Extend change to start of growsup vma (mprotect only).  */
#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

#define ELFn_ST_BIND(i)             ((i) >> 4)
/*
  0 : LOCAL
  1 : GLOBAL
  2 : WEAK
 */
#define ELFn_ST_TYPE(i)             ((i) & 0xf)
/*
  0 : NOTYPE
  1 : OBJECT
  2 : FUNC
  3 : SECTION
  4 : FILE
 */
#define ELFn_ST_INFO(b, t)          (((b)<<4)+((t)&0xf))

#define SHT_SYMTAB          2
#define SHT_DYNAMIC         6
#define SHT_DYNSYM          11

#define SHT_RELA            4
#define SHT_REL             9

#define SHF_INFO_LINK   0x40
#define SHF_SHF_ALLOC   0x2

#define PT_NULL     0
#define PT_LOAD     1
#define PT_DYNAMIC  2
#define PT_INTERP   3
#define PT_NOTE     4
#define PT_SHLIB    5
#define PT_PHDR     6

#define DT_NULL     0
#define DT_NEEDED   1
#define DT_PLTRELSZ 2
#define DT_PLTGOT   3
#define DT_HASH     4
#define DT_STRTAB   5
#define DT_SYMTAB   6
#define DT_RELA     7
#define DT_RELASZ   8
#define DT_RELAENT  9
#define DT_STRSZ    10
#define DT_SYMENT   11
#define DT_INIT     12
#define DT_FINI     13
#define DT_SONAME   14
#define DT_RPATH    15
#define DT_SYMBOLIC 16
#define DT_REL      17
#define DT_RELSZ    18
#define DT_RELENT   19
#define DT_PLTREL   20
#define DT_DEBUG    21
#define DT_TEXTREL  22
#define DT_JMPREL   23
#define DT_BING_NOW 24
#define DT_INIT_ARRAY   25
#define DT_FINI_ARRAY   26
#define DT_INIT_ARRAYSZ 27
#define DT_FINI_ARRAYSZ 28
#define DT_RUNPATH      29
#define DT_FLAGS        30
#define DT_VERSYM       0x6ffffff0
#define DT_VERDEF       0x6ffffffc
#define DT_VERDEFNUM    0x6ffffffd
#define DT_VERNEED      0x6ffffffe
#define DT_VERNEEDNUM   0x6fffffff

struct cgelfDynamic {
    size_t strtab;
    size_t strsz;
    size_t symtab;
    size_t pltrel;
    size_t pltrelsz;
    size_t jmprel;
    size_t pltgot; // ignore always
    size_t rela;
    size_t relasz;
    size_t relaent;
    size_t rel;
    size_t relsz;
    size_t relent;
    size_t init;
    size_t fini;
    size_t init_array;
    size_t init_arraysz;
    size_t fini_array;
    size_t fini_arraysz;
    size_t preinit_array;
    size_t preinit_arraysz;
    size_t textrel;
    size_t symbolic;
    size_t needed;
    size_t flags;
    size_t versym;
    size_t verdef;
    size_t verdefnum;
    size_t verneed;
    size_t verneednum;
    size_t runpath;
};

struct cgelfRelocEntry {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
};

struct cgelfRelocTable {
    uint32_t type;  // 4:rela, 9:rel
    uint32_t sectionIdx;
    uint32_t sectionStrIdx;
    uint32_t link;
    uint32_t entCount;
    struct cgelfRelocEntry * ents;
};

struct cgelfSymbolEntry {
    char name[ELF_MAX_NAME_LEN];
    uint32_t st_name;
    uint64_t st_value;
    uint64_t st_size;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
};

struct cgelfSymbolTable {
    uint32_t type; // 2:symtab, 11:dynsym
    uint32_t sectionIdx;
    uint32_t sectionStrIdx;
    uint32_t entCount;
    struct cgelfSymbolEntry * ents;
};

struct cgelfSegment {
    uint32_t p_type;  // 1:load, 2:dynamic, 4:note, 6:phdr
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
    uint8_t * dataPtr;
};

struct cgelfSection {
    char name[ELF_MAX_NAME_LEN];
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
    uint8_t * dataPtr;
};

struct cgelfHeader {
    uint16_t e_type;    // 2:exec, 3:dyn, 4:core
    uint16_t e_machine; // 40:ARM, 62:AMD64
    uint32_t e_version;
    uint64_t e_entry;   // Elfn_Addr
    uint64_t e_phoff;   // Elfn_Off
    uint64_t e_shoff;   // Elfn_Off
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct cgelf {
    uint32_t fileSize;
    uint8_t * fileContent;

    uint8_t byteWidths;
    uint8_t endian; // 1: little-endian, 2: big-endian
    uint8_t version;
    uint8_t osabi;
    struct cgelfHeader hdr;

    uint32_t sectionCount;  // hdr.e_shnum
    struct cgelfSection * sections;
    uint32_t segmentCount;  // hdr.e_phnum
    struct cgelfSegment * segments;

    struct cgelfSymbolTable dynsym;
    struct cgelfSymbolTable symtab;

    struct cgelfRelocTable relocDyn;
    struct cgelfRelocTable relocPlt;

    struct cgelfDynamic dynamic;
};

uint64_t endian_int(int8_t endian, uint8_t * ptr, int8_t len);
struct cgelf * cgelf_alloc(void);
bool cgelf_read(struct cgelf * c, char * elfname);
void cgelf_dump(struct cgelf * c);
void cgelf_free(struct cgelf * c);

#endif
