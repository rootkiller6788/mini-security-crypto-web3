#ifndef ELF_ANALYSIS_H
#define ELF_ANALYSIS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ???????????????????????????????????????????????????????????????????
   ELF Binary Analysis ? Structures per ELF64 Specification
   Reference: System V ABI, ELF-64 Object File Format v1.0
   ??????????????????????????????????????????????????????????????????? */

/* ?? ELF Identification (e_ident[16]) ?? */
#define EI_NIDENT      16
#define EI_MAG0        0
#define EI_MAG1        1
#define EI_MAG2        2
#define EI_MAG3        3
#define EI_CLASS       4
#define EI_DATA        5
#define EI_VERSION     6
#define EI_OSABI       7
#define EI_ABIVERSION  8
#define EI_PAD         9

/* ?? ELF Class ?? */
typedef enum {
    ELFCLASSNONE = 0,
    ELFCLASS32   = 1,
    ELFCLASS64   = 2,
} elf_class_t;

/* ?? ELF Data Encoding ?? */
typedef enum {
    ELFDATANONE = 0,
    ELFDATA2LSB = 1,
    ELFDATA2MSB = 2,
} elf_data_t;

/* ?? ELF Object File Types ?? */
typedef enum {
    ET_NONE   = 0,
    ET_REL    = 1,
    ET_EXEC   = 2,
    ET_DYN    = 3,
    ET_CORE   = 4,
} elf_type_t;

/* ?? ELF Machine Architectures ?? */
typedef enum {
    EM_NONE    = 0,
    EM_X86_64  = 62,
    EM_AARCH64 = 183,
    EM_ARM     = 40,
    EM_RISCV   = 243,
} elf_machine_t;

/* ?? ELF64 Header (Ehdr) ?? */
typedef struct {
    uint8_t      e_ident[EI_NIDENT];
    uint16_t     e_type;
    uint16_t     e_machine;
    uint32_t     e_version;
    uint64_t     e_entry;
    uint64_t     e_phoff;
    uint64_t     e_shoff;
    uint32_t     e_flags;
    uint16_t     e_ehsize;
    uint16_t     e_phentsize;
    uint16_t     e_phnum;
    uint16_t     e_shentsize;
    uint16_t     e_shnum;
    uint16_t     e_shstrndx;
} elf64_ehdr_t;

/* ?? Segment Types (p_type) ?? */
typedef enum {
    PT_NULL         = 0,
    PT_LOAD         = 1,
    PT_DYNAMIC      = 2,
    PT_INTERP       = 3,
    PT_NOTE         = 4,
    PT_SHLIB        = 5,
    PT_PHDR         = 6,
    PT_TLS          = 7,
    PT_GNU_EH_FRAME = 0x6474E550,
    PT_GNU_STACK    = 0x6474E551,
    PT_GNU_RELRO    = 0x6474E552,
    PT_GNU_PROPERTY = 0x6474E553,
} elf_segment_type_t;

#define PF_X  0x1
#define PF_W  0x2
#define PF_R  0x4

/* ?? ELF64 Program Header (Phdr) ?? */
typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf64_phdr_t;

/* ?? Section Types ?? */
typedef enum {
    SHT_NULL           = 0,
    SHT_PROGBITS       = 1,
    SHT_SYMTAB         = 2,
    SHT_STRTAB         = 3,
    SHT_RELA           = 4,
    SHT_HASH           = 5,
    SHT_DYNAMIC        = 6,
    SHT_NOTE           = 7,
    SHT_NOBITS         = 8,
    SHT_REL            = 9,
    SHT_DYNSYM         = 11,
    SHT_INIT_ARRAY     = 14,
    SHT_FINI_ARRAY     = 15,
    SHT_GNU_HASH       = 0x6FFFFFF6,
    SHT_GNU_VERDEF     = 0x6FFFFFFD,
    SHT_GNU_VERNEED    = 0x6FFFFFFE,
    SHT_GNU_VERSYM     = 0x6FFFFFFF,
} elf_section_type_t;

#define SHF_WRITE     0x1
#define SHF_ALLOC     0x2
#define SHF_EXECINSTR 0x4

/* ?? ELF64 Section Header (Shdr) ?? */
typedef struct {
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
} elf64_shdr_t;

#define STB_LOCAL   0
#define STB_GLOBAL  1
#define STB_WEAK    2
#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3
#define STT_FILE    4

/* ?? ELF64 Symbol Entry ?? */
typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} elf64_sym_t;

/* ?? ELF64 Relocation Entry ?? */
typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} elf64_rela_t;

/* ?? Dynamic Array Entry ?? */
typedef enum {
    DT_NULL     = 0,
    DT_NEEDED   = 1,
    DT_PLTRELSZ = 2,
    DT_PLTGOT   = 3,
    DT_HASH     = 4,
    DT_STRTAB   = 5,
    DT_SYMTAB   = 6,
    DT_RELA     = 7,
    DT_RELASZ   = 8,
    DT_RELAENT  = 9,
    DT_STRSZ    = 10,
    DT_SYMENT   = 11,
    DT_INIT     = 12,
    DT_FINI     = 13,
    DT_SONAME   = 14,
    DT_RPATH    = 15,
    DT_SYMBOLIC = 16,
    DT_REL      = 17,
    DT_RELSZ    = 18,
    DT_RELENT   = 19,
    DT_PLTREL   = 20,
    DT_DEBUG    = 21,
    DT_TEXTREL  = 22,
    DT_JMPREL   = 23,
    DT_BIND_NOW = 24,
    DT_FLAGS_1  = 0x6FFFFFFB,
    DT_GNU_HASH = 0x6FFFFEF5,
} elf_dynamic_tag_t;

typedef struct {
    int64_t  d_tag;
    uint64_t d_val;
} elf64_dyn_t;

#define DF_1_NOW    0x00000001
#define DF_1_GLOBAL 0x00000002
#define DF_1_PIE    0x08000000

/* ?? Parsed ELF binary context ?? */
#define ELF_MAX_PHDRS     64
#define ELF_MAX_SHDRS     128
#define ELF_MAX_SYMBOLS   4096
#define ELF_MAX_DYNAMIC   256
#define ELF_MAX_NEEDED    32

typedef struct {
    elf64_ehdr_t     ehdr;
    bool             is_64bit;
    bool             is_little_endian;
    elf_class_t      elf_class;
    elf_data_t       elf_data;
    elf_type_t       elf_type;
    elf_machine_t    elf_machine;
    elf64_phdr_t     phdrs[ELF_MAX_PHDRS];
    uint16_t         phdr_count;
    elf64_shdr_t     shdrs[ELF_MAX_SHDRS];
    uint16_t         shdr_count;
    char            *shstrtab;
    size_t           shstrtab_size;
    elf64_dyn_t      dynamic[ELF_MAX_DYNAMIC];
    uint32_t         dynamic_count;
    char            *dynstr;
    size_t           dynstr_size;
    elf64_sym_t      dynsyms[ELF_MAX_SYMBOLS];
    uint32_t         dynsym_count;
    char             needed[ELF_MAX_NEEDED][128];
    uint32_t         needed_count;
    bool             has_gnu_stack;
    bool             gnu_stack_exec;
    bool             has_relro;
    bool             has_bind_now;
    bool             is_pie;
    uint64_t         got_plt_addr;
    uint64_t         got_plt_size;
    const uint8_t   *raw_data;
    size_t           raw_size;
} elf_binary_t;

typedef struct {
    const elf64_shdr_t *shdr;
    const char         *name;
    int                 index;
} elf_section_info_t;

#define ELF_MAX_GOT_ENTRIES 128
typedef struct {
    uint64_t    address;
    uint64_t    value;
    const char *symbol_name;
    bool        is_plt;
} elf_got_entry_t;

typedef struct {
    elf_got_entry_t entries[ELF_MAX_GOT_ENTRIES];
    uint32_t        count;
} elf_got_table_t;

typedef struct {
    uint64_t vaddr;
    uint64_t memsz;
    uint32_t flags;
    bool     is_load;
    bool     is_exec;
    bool     is_writable;
    bool     is_readable;
} elf_segment_summary_t;

/* ???????????????????????????????????????????????????????????????????
   API
   ??????????????????????????????????????????????????????????????????? */

void        elf_header_init(elf64_ehdr_t *h);
bool        elf_validate_magic(const uint8_t e_ident[EI_NIDENT]);
bool        elf_parse_ehdr(const uint8_t *data, size_t size, elf64_ehdr_t *h);
void        elf_print_ehdr(const elf64_ehdr_t *h);
const char *elf_type_name(uint16_t e_type);
const char *elf_machine_name(uint16_t e_machine);
const char *elf_osabi_name(uint8_t osabi);
const char *elf_data_name(uint8_t data);

bool        elf_parse_phdrs(const uint8_t *data, size_t size,
                            const elf64_ehdr_t *h, elf64_phdr_t *phdrs,
                            uint16_t *count);
void        elf_print_phdr(const elf64_phdr_t *p, int idx);
const char *elf_phdr_type_name(uint32_t p_type);
bool        elf_phdr_is_load(const elf64_phdr_t *p);
bool        elf_phdr_is_exec(const elf64_phdr_t *p);
bool        elf_phdr_is_writable(const elf64_phdr_t *p);

bool        elf_parse_shdrs(const uint8_t *data, size_t size,
                            const elf64_ehdr_t *h, elf64_shdr_t *shdrs,
                            uint16_t *count);
bool        elf_load_shstrtab(const uint8_t *data, size_t size,
                              const elf64_ehdr_t *h, const elf64_shdr_t *shdrs,
                              char **out, size_t *out_size);
void        elf_print_shdr(const elf64_shdr_t *s, const char *name, int idx);
const char *elf_shdr_type_name(uint32_t sh_type);
elf_section_info_t elf_find_section(const elf64_shdr_t *shdrs, uint16_t count,
                                     const char *shstrtab, const char *name);

bool        elf_parse_dynamic(const uint8_t *data, size_t size,
                              elf64_dyn_t *dyns, uint32_t *count,
                              const elf64_shdr_t *shdrs, uint16_t shdr_count,
                              const char *shstrtab);
bool        elf_parse_dynsym(const uint8_t *data, size_t size,
                             elf64_sym_t *syms, uint32_t *count,
                             const elf64_shdr_t *shdrs, uint16_t shdr_count,
                             const char *shstrtab);
void        elf_print_dynamic(const elf64_dyn_t *d, int idx);
const char *elf_dynamic_tag_name(int64_t tag);

bool        elf_locate_got_plt(const uint8_t *data, size_t size,
                               const elf64_shdr_t *shdrs, uint16_t shdr_count,
                               const char *shstrtab, uint64_t *addr,
                               uint64_t *out_size);
bool        elf_parse_got_table(const uint8_t *data, size_t size,
                                const elf64_shdr_t *shdrs, uint16_t shdr_count,
                                const char *shstrtab, elf_got_table_t *got);

const char *elf_symbol_name(uint32_t st_name, const char *strtab, size_t strtab_size);
bool        elf_find_symbol(const elf64_sym_t *syms, uint32_t count,
                            const char *strtab, size_t strtab_size,
                            const char *name, elf64_sym_t *out);
void        elf_print_symbol(const elf64_sym_t *sym, const char *strtab,
                             size_t strtab_size, int idx);

bool        elf_binary_init(elf_binary_t *bin, const uint8_t *data, size_t size);
void        elf_binary_free(elf_binary_t *bin);
bool        elf_binary_detect_security(const elf_binary_t *bin);
void        elf_binary_print_security(const elf_binary_t *bin);
void        elf_binary_print_summary(const elf_binary_t *bin);

bool        elf_get_executable_segments(const elf64_phdr_t *phdrs,
                                         uint16_t count,
                                         elf_segment_summary_t *segs,
                                         uint16_t *seg_count);
bool        elf_check_nx_compliance(const elf64_phdr_t *phdrs, uint16_t count);
bool        elf_check_relro_compliance(const elf_binary_t *bin);

bool        elf_patch_got_entry(const uint8_t *data, size_t size,
                                uint64_t got_addr, uint64_t new_value);

/* ── ELF Loader Simulation (L5) ── */
typedef struct {
    uint64_t base_addr;
    uint64_t entry_point;
    uint64_t load_segments[8][2];
    uint32_t num_load_segments;
    uint64_t stack_top;
    uint64_t brk_addr;
    uint64_t ld_so_base;
} elf_load_image_t;

bool        elf_simulate_load(const elf_binary_t *bin, uint64_t aslr_offset,
                               elf_load_image_t *image);

/* ── Fake ELF Generator (L6: test fixture) ── */
#define FAKE_ELF_MAX_SIZE 4096
typedef struct {
    uint8_t  data[FAKE_ELF_MAX_SIZE];
    size_t   size;
    bool     valid;
} fake_elf_t;

bool        elf_generate_fake_executable(fake_elf_t *fake);
bool        elf_generate_fake_shared_object(fake_elf_t *fake);

#define R_X86_64_GLOB_DAT  6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_RELATIVE  8

#ifdef __cplusplus
}
#endif

#endif /* ELF_ANALYSIS_H */
