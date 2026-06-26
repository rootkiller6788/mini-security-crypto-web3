#include "elf_analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
   ELF Header Parsing
   ═══════════════════════════════════════════════════════════════════ */

static const uint8_t ELF_MAGIC[4] = { 0x7F, 'E', 'L', 'F' };

void elf_header_init(elf64_ehdr_t *h) {
    memset(h, 0, sizeof(*h));
}

bool elf_validate_magic(const uint8_t e_ident[EI_NIDENT]) {
    return (e_ident[EI_MAG0] == ELF_MAGIC[0] &&
            e_ident[EI_MAG1] == ELF_MAGIC[1] &&
            e_ident[EI_MAG2] == ELF_MAGIC[2] &&
            e_ident[EI_MAG3] == ELF_MAGIC[3]);
}

bool elf_parse_ehdr(const uint8_t *data, size_t size, elf64_ehdr_t *h) {
    if (!data || !h || size < sizeof(elf64_ehdr_t)) return false;
    if (!elf_validate_magic(data)) return false;

    memcpy(h->e_ident, data, EI_NIDENT);

    size_t off = EI_NIDENT;
    memcpy(&h->e_type,      data + off, 2); off += 2;
    memcpy(&h->e_machine,   data + off, 2); off += 2;
    memcpy(&h->e_version,   data + off, 4); off += 4;
    memcpy(&h->e_entry,     data + off, 8); off += 8;
    memcpy(&h->e_phoff,     data + off, 8); off += 8;
    memcpy(&h->e_shoff,     data + off, 8); off += 8;
    memcpy(&h->e_flags,     data + off, 4); off += 4;
    memcpy(&h->e_ehsize,    data + off, 2); off += 2;
    memcpy(&h->e_phentsize, data + off, 2); off += 2;
    memcpy(&h->e_phnum,     data + off, 2); off += 2;
    memcpy(&h->e_shentsize, data + off, 2); off += 2;
    memcpy(&h->e_shnum,     data + off, 2); off += 2;
    memcpy(&h->e_shstrndx,  data + off, 2);
    return true;
}

void elf_print_ehdr(const elf64_ehdr_t *h) {
    printf("\n╔══ ELF64 Header ═══════════════════════════════╗\n");
    printf("║ Magic:        %02X %02X %02X %02X                       ║\n",
           h->e_ident[0], h->e_ident[1], h->e_ident[2], h->e_ident[3]);
    printf("║ Class:        %-36s║\n",
           h->e_ident[EI_CLASS] == 2 ? "ELF64" : "ELF32/Unknown");
    printf("║ Data:         %-36s║\n", elf_data_name(h->e_ident[EI_DATA]));
    printf("║ OS/ABI:       %-36s║\n", elf_osabi_name(h->e_ident[EI_OSABI]));
    printf("║ Type:         %-36s║\n", elf_type_name(h->e_type));
    printf("║ Machine:      %-36s║\n", elf_machine_name(h->e_machine));
    printf("║ Entry point:  0x%016llX            ║\n", (unsigned long long)h->e_entry);
    printf("║ PH offset:    0x%016llX            ║\n", (unsigned long long)h->e_phoff);
    printf("║ SH offset:    0x%016llX            ║\n", (unsigned long long)h->e_shoff);
    printf("║ PH count:     %-36u║\n", h->e_phnum);
    printf("║ SH count:     %-36u║\n", h->e_shnum);
    printf("║ SH strndx:    %-36u║\n", h->e_shstrndx);
    printf("╚══════════════════════════════════════════════╝\n");
}

const char *elf_type_name(uint16_t e_type) {
    switch (e_type) {
    case ET_NONE: return "NONE";
    case ET_REL:  return "REL (Relocatable)";
    case ET_EXEC: return "EXEC (Executable)";
    case ET_DYN:  return "DYN (Shared Object)";
    case ET_CORE: return "CORE (Core dump)";
    default:      return "UNKNOWN";
    }
}

const char *elf_machine_name(uint16_t e_machine) {
    switch (e_machine) {
    case EM_NONE:    return "None";
    case EM_X86_64:  return "x86_64 (AMD64)";
    case EM_AARCH64: return "AArch64 (ARM64)";
    case EM_ARM:     return "ARM";
    case EM_RISCV:   return "RISC-V";
    default:         return "Unknown";
    }
}

const char *elf_osabi_name(uint8_t osabi) {
    switch (osabi) {
    case 0:   return "ELFOSABI_NONE / SYSV";
    case 2:   return "ELFOSABI_NETBSD";
    case 3:   return "ELFOSABI_LINUX";
    case 6:   return "ELFOSABI_SOLARIS";
    case 9:   return "ELFOSABI_FREEBSD";
    default:  return "Unknown OS/ABI";
    }
}

const char *elf_data_name(uint8_t data) {
    switch (data) {
    case ELFDATA2LSB: return "Little-endian (LSB)";
    case ELFDATA2MSB: return "Big-endian (MSB)";
    default:          return "Invalid";
    }
}

/* ═══════════════════════════════════════════════════════════════════
   Program Header Parsing
   ═══════════════════════════════════════════════════════════════════ */

bool elf_parse_phdrs(const uint8_t *data, size_t size,
                     const elf64_ehdr_t *h, elf64_phdr_t *phdrs,
                     uint16_t *count) {
    if (!data || !h || !phdrs || !count) return false;
    if (h->e_phoff == 0 || h->e_phnum == 0) { *count = 0; return true; }
    if (h->e_phnum > ELF_MAX_PHDRS) return false;

    size_t phdr_size = sizeof(elf64_phdr_t);
    if (h->e_phoff + (size_t)h->e_phnum * phdr_size > size) return false;

    *count = h->e_phnum;
    for (uint16_t i = 0; i < h->e_phnum; i++) {
        size_t off = h->e_phoff + (size_t)i * phdr_size;
        memcpy(&phdrs[i].p_type,   data + off,      4); off += 4;
        memcpy(&phdrs[i].p_flags,  data + off,      4); off += 4;
        memcpy(&phdrs[i].p_offset, data + off,      8); off += 8;
        memcpy(&phdrs[i].p_vaddr,  data + off,      8); off += 8;
        memcpy(&phdrs[i].p_paddr,  data + off,      8); off += 8;
        memcpy(&phdrs[i].p_filesz, data + off,      8); off += 8;
        memcpy(&phdrs[i].p_memsz,  data + off,      8); off += 8;
        memcpy(&phdrs[i].p_align,  data + off,      8);
    }
    return true;
}

void elf_print_phdr(const elf64_phdr_t *p, int idx) {
    printf("  [%02d] %-20s  flags=%c%c%c  vaddr=0x%016llX\n",
           idx, elf_phdr_type_name(p->p_type),
           (p->p_flags & PF_R) ? 'R' : '-',
           (p->p_flags & PF_W) ? 'W' : '-',
           (p->p_flags & PF_X) ? 'X' : '-',
           (unsigned long long)p->p_vaddr);
    printf("        offset=0x%08llX  filesz=%llu  memsz=%llu  align=%llu\n",
           (unsigned long long)p->p_offset,
           (unsigned long long)p->p_filesz,
           (unsigned long long)p->p_memsz,
           (unsigned long long)p->p_align);
}

const char *elf_phdr_type_name(uint32_t p_type) {
    switch (p_type) {
    case PT_NULL:         return "NULL";
    case PT_LOAD:         return "LOAD";
    case PT_DYNAMIC:      return "DYNAMIC";
    case PT_INTERP:       return "INTERP";
    case PT_NOTE:         return "NOTE";
    case PT_PHDR:         return "PHDR";
    case PT_TLS:          return "TLS";
    case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
    case PT_GNU_STACK:    return "GNU_STACK";
    case PT_GNU_RELRO:    return "GNU_RELRO";
    case PT_GNU_PROPERTY: return "GNU_PROPERTY";
    default:              return "UNKNOWN";
    }
}

bool elf_phdr_is_load(const elf64_phdr_t *p) {
    return p->p_type == PT_LOAD;
}

bool elf_phdr_is_exec(const elf64_phdr_t *p) {
    return (p->p_flags & PF_X) != 0;
}

bool elf_phdr_is_writable(const elf64_phdr_t *p) {
    return (p->p_flags & PF_W) != 0;
}

/* ═══════════════════════════════════════════════════════════════════
   Section Header Parsing
   ═══════════════════════════════════════════════════════════════════ */

bool elf_parse_shdrs(const uint8_t *data, size_t size,
                     const elf64_ehdr_t *h, elf64_shdr_t *shdrs,
                     uint16_t *count) {
    if (!data || !h || !shdrs || !count) return false;
    if (h->e_shoff == 0 || h->e_shnum == 0) { *count = 0; return true; }
    if (h->e_shnum > ELF_MAX_SHDRS) return false;

    size_t shdr_size = sizeof(elf64_shdr_t);
    if (h->e_shoff + (size_t)h->e_shnum * shdr_size > size) return false;

    *count = h->e_shnum;
    for (uint16_t i = 0; i < h->e_shnum; i++) {
        size_t off = h->e_shoff + (size_t)i * shdr_size;
        memcpy(&shdrs[i].sh_name,      data + off, 4); off += 4;
        memcpy(&shdrs[i].sh_type,      data + off, 4); off += 4;
        memcpy(&shdrs[i].sh_flags,     data + off, 8); off += 8;
        memcpy(&shdrs[i].sh_addr,      data + off, 8); off += 8;
        memcpy(&shdrs[i].sh_offset,    data + off, 8); off += 8;
        memcpy(&shdrs[i].sh_size,      data + off, 8); off += 8;
        memcpy(&shdrs[i].sh_link,      data + off, 4); off += 4;
        memcpy(&shdrs[i].sh_info,      data + off, 4); off += 4;
        memcpy(&shdrs[i].sh_addralign, data + off, 8); off += 8;
        memcpy(&shdrs[i].sh_entsize,   data + off, 8);
    }
    return true;
}

bool elf_load_shstrtab(const uint8_t *data, size_t size,
                       const elf64_ehdr_t *h, const elf64_shdr_t *shdrs,
                       char **out, size_t *out_size) {
    if (!data || !h || !shdrs || !out || !out_size) return false;
    if (h->e_shstrndx == 0 || h->e_shstrndx >= h->e_shnum) return false;

    const elf64_shdr_t *sh = &shdrs[h->e_shstrndx];
    if (sh->sh_offset + sh->sh_size > size) return false;

    *out_size = sh->sh_size;
    *out = (char*)malloc(sh->sh_size + 1);
    if (!*out) return false;
    memcpy(*out, data + sh->sh_offset, sh->sh_size);
    (*out)[sh->sh_size] = '\0';
    return true;
}

void elf_print_shdr(const elf64_shdr_t *s, const char *name, int idx) {
    printf("  [%02d] %-20s  type=%-12s  flags=%c%c%c\n",
           idx, name ? name : "(unnamed)",
           elf_shdr_type_name(s->sh_type),
           (s->sh_flags & SHF_ALLOC) ? 'A' : '-',
           (s->sh_flags & SHF_WRITE) ? 'W' : '-',
           (s->sh_flags & SHF_EXECINSTR) ? 'X' : '-');
    printf("        addr=0x%016llX  offset=0x%08llX  size=%llu\n",
           (unsigned long long)s->sh_addr,
           (unsigned long long)s->sh_offset,
           (unsigned long long)s->sh_size);
}

const char *elf_shdr_type_name(uint32_t sh_type) {
    switch (sh_type) {
    case SHT_NULL:        return "NULL";
    case SHT_PROGBITS:    return "PROGBITS";
    case SHT_SYMTAB:      return "SYMTAB";
    case SHT_STRTAB:      return "STRTAB";
    case SHT_RELA:        return "RELA";
    case SHT_HASH:        return "HASH";
    case SHT_DYNAMIC:     return "DYNAMIC";
    case SHT_NOTE:        return "NOTE";
    case SHT_NOBITS:      return "NOBITS";
    case SHT_REL:         return "REL";
    case SHT_DYNSYM:      return "DYNSYM";
    case SHT_INIT_ARRAY:  return "INIT_ARRAY";
    case SHT_FINI_ARRAY:  return "FINI_ARRAY";
    case SHT_GNU_HASH:    return "GNU_HASH";
    default:              return "UNKNOWN";
    }
}

elf_section_info_t elf_find_section(const elf64_shdr_t *shdrs, uint16_t count,
                                     const char *shstrtab, const char *name) {
    elf_section_info_t result = { NULL, NULL, -1 };
    if (!shdrs || !shstrtab || !name) return result;
    for (uint16_t i = 0; i < count; i++) {
        const char *sname = shstrtab + shdrs[i].sh_name;
        if (strcmp(sname, name) == 0) {
            result.shdr  = &shdrs[i];
            result.name  = sname;
            result.index = i;
            return result;
        }
    }
    return result;
}

/* ═══════════════════════════════════════════════════════════════════
   Dynamic Section Parsing
   ═══════════════════════════════════════════════════════════════════ */

bool elf_parse_dynamic(const uint8_t *data, size_t size,
                       elf64_dyn_t *dyns, uint32_t *count,
                       const elf64_shdr_t *shdrs, uint16_t shdr_count,
                       const char *shstrtab) {
    if (!data || !dyns || !count) return false;
    elf_section_info_t dyn_sec = elf_find_section(shdrs, shdr_count, shstrtab, ".dynamic");
    if (!dyn_sec.shdr || dyn_sec.shdr->sh_type != SHT_DYNAMIC) { *count = 0; return false; }

    const elf64_shdr_t *sh = dyn_sec.shdr;
    if (sh->sh_offset + sh->sh_size > size) return false;

    size_t entry_size = sizeof(elf64_dyn_t);
    uint32_t num = (uint32_t)(sh->sh_size / entry_size);
    if (num > ELF_MAX_DYNAMIC) num = ELF_MAX_DYNAMIC;

    *count = num;
    for (uint32_t i = 0; i < num; i++) {
        size_t off = sh->sh_offset + i * entry_size;
        memcpy(&dyns[i].d_tag, data + off, 8);
        memcpy(&dyns[i].d_val, data + off + 8, 8);
    }
    return true;
}

bool elf_parse_dynsym(const uint8_t *data, size_t size,
                      elf64_sym_t *syms, uint32_t *count,
                      const elf64_shdr_t *shdrs, uint16_t shdr_count,
                      const char *shstrtab) {
    if (!data || !syms || !count) return false;
    elf_section_info_t sym_sec = elf_find_section(shdrs, shdr_count, shstrtab, ".dynsym");
    if (!sym_sec.shdr) { *count = 0; return false; }

    const elf64_shdr_t *sh = sym_sec.shdr;
    if (sh->sh_offset + sh->sh_size > size) return false;

    size_t entry_size = sizeof(elf64_sym_t);
    uint32_t num = (uint32_t)(sh->sh_size / entry_size);
    if (num > ELF_MAX_SYMBOLS) num = ELF_MAX_SYMBOLS;

    *count = num;
    for (uint32_t i = 0; i < num; i++) {
        size_t off = sh->sh_offset + i * entry_size;
        memcpy(&syms[i].st_name,  data + off, 4); off += 4;
        memcpy(&syms[i].st_info,  data + off, 1); off += 1;
        memcpy(&syms[i].st_other, data + off, 1); off += 1;
        memcpy(&syms[i].st_shndx, data + off, 2); off += 2;
        memcpy(&syms[i].st_value, data + off, 8); off += 8;
        memcpy(&syms[i].st_size,  data + off, 8);
    }
    return true;
}

void elf_print_dynamic(const elf64_dyn_t *d, int idx) {
    printf("  [%02d] %-16s = 0x%016llX\n", idx, elf_dynamic_tag_name(d->d_tag), (unsigned long long)d->d_val);
}

const char *elf_dynamic_tag_name(int64_t tag) {
    switch (tag) {
    case DT_NULL:     return "NULL";
    case DT_NEEDED:   return "NEEDED";
    case DT_PLTRELSZ: return "PLTRELSZ";
    case DT_PLTGOT:   return "PLTGOT";
    case DT_HASH:     return "HASH";
    case DT_STRTAB:   return "STRTAB";
    case DT_SYMTAB:   return "SYMTAB";
    case DT_RELA:     return "RELA";
    case DT_RELASZ:   return "RELASZ";
    case DT_RELAENT:  return "RELAENT";
    case DT_STRSZ:    return "STRSZ";
    case DT_SYMENT:   return "SYMENT";
    case DT_INIT:     return "INIT";
    case DT_FINI:     return "FINI";
    case DT_SONAME:   return "SONAME";
    case DT_RPATH:    return "RPATH";
    case DT_DEBUG:    return "DEBUG";
    case DT_TEXTREL:  return "TEXTREL (danger)";
    case DT_JMPREL:   return "JMPREL";
    case DT_BIND_NOW: return "BIND_NOW";
    case DT_FLAGS_1:  return "FLAGS_1";
    case DT_GNU_HASH: return "GNU_HASH";
    default:          return "UNKNOWN";
    }
}

/* ═══════════════════════════════════════════════════════════════════
   GOT/PLT Analysis
   ═══════════════════════════════════════════════════════════════════ */

bool elf_locate_got_plt(const uint8_t *data, size_t size,
                        const elf64_shdr_t *shdrs, uint16_t shdr_count,
                        const char *shstrtab, uint64_t *addr,
                        uint64_t *out_size) {
    (void)data; (void)size;
    if (!addr || !out_size) return false;
    elf_section_info_t got = elf_find_section(shdrs, shdr_count, shstrtab, ".got.plt");
    if (!got.shdr) { got = elf_find_section(shdrs, shdr_count, shstrtab, ".got"); }
    if (!got.shdr) { *addr = 0; *out_size = 0; return false; }
    *addr     = got.shdr->sh_addr;
    *out_size = got.shdr->sh_size;
    return true;
}

bool elf_parse_got_table(const uint8_t *data, size_t size,
                         const elf64_shdr_t *shdrs, uint16_t shdr_count,
                         const char *shstrtab, elf_got_table_t *got) {
    if (!data || !got) return false;
    memset(got, 0, sizeof(*got));

    uint64_t got_addr = 0, got_size = 0;
    if (!elf_locate_got_plt(data, size, shdrs, shdr_count, shstrtab, &got_addr, &got_size))
        return false;

    elf_section_info_t got_sec = elf_find_section(shdrs, shdr_count, shstrtab, ".got.plt");
    if (!got_sec.shdr) got_sec = elf_find_section(shdrs, shdr_count, shstrtab, ".got");
    if (!got_sec.shdr) return false;

    size_t num_entries = got_sec.shdr->sh_size / 8;
    if (num_entries > ELF_MAX_GOT_ENTRIES) num_entries = ELF_MAX_GOT_ENTRIES;
    size_t start = 3;
    if (start >= num_entries) return false;

    got->count = 0;
    for (size_t i = start; i < num_entries && got->count < ELF_MAX_GOT_ENTRIES; i++) {
        size_t off = got_sec.shdr->sh_offset + i * 8;
        if (off + 8 > size) break;
        elf_got_entry_t *entry = &got->entries[got->count];
        memcpy(&entry->value, data + off, 8);
        entry->address     = got_sec.shdr->sh_addr + i * 8;
        entry->is_plt      = true;
        entry->symbol_name = NULL;
        got->count++;
    }
    return true;
}

/* ═══════════════════════════════════════════════════════════════════
   Symbol Resolution
   ═══════════════════════════════════════════════════════════════════ */

static uint8_t elf_st_bind(uint8_t info) { return info >> 4; }
static uint8_t elf_st_type(uint8_t info) { return info & 0x0F; }

const char *elf_symbol_name(uint32_t st_name, const char *strtab, size_t strtab_size) {
    if (!strtab || st_name >= strtab_size) return "(unnamed)";
    return strtab + st_name;
}

bool elf_find_symbol(const elf64_sym_t *syms, uint32_t count,
                     const char *strtab, size_t strtab_size,
                     const char *name, elf64_sym_t *out) {
    if (!syms || !strtab || !name || !out) return false;
    for (uint32_t i = 0; i < count; i++) {
        const char *sname = elf_symbol_name(syms[i].st_name, strtab, strtab_size);
        if (strcmp(sname, name) == 0) {
            memcpy(out, &syms[i], sizeof(elf64_sym_t));
            return true;
        }
    }
    return false;
}

void elf_print_symbol(const elf64_sym_t *sym, const char *strtab, size_t strtab_size, int idx) {
    const char *type_str = "?";
    switch (elf_st_type(sym->st_info)) {
    case STT_NOTYPE:  type_str = "NOTYPE"; break;
    case STT_OBJECT:  type_str = "OBJECT"; break;
    case STT_FUNC:    type_str = "FUNC";   break;
    case STT_SECTION: type_str = "SECTION"; break;
    case STT_FILE:    type_str = "FILE";   break;
    }
    const char *bind_str = "?";
    switch (elf_st_bind(sym->st_info)) {
    case STB_LOCAL:  bind_str = "LOCAL";  break;
    case STB_GLOBAL: bind_str = "GLOBAL"; break;
    case STB_WEAK:   bind_str = "WEAK";   break;
    }
    const char *name = elf_symbol_name(sym->st_name, strtab, strtab_size);
    printf("  [%4d] %-32s  value=0x%016llX  size=%llu  %s/%s\n",
           idx, name, (unsigned long long)sym->st_value,
           (unsigned long long)sym->st_size, type_str, bind_str);
}

/* ═══════════════════════════════════════════════════════════════════
   Binary Loading & Analysis (L3: Engineering Structure)
   ═══════════════════════════════════════════════════════════════════ */

bool elf_binary_init(elf_binary_t *bin, const uint8_t *data, size_t size) {
    if (!bin || !data) return false;
    memset(bin, 0, sizeof(*bin));
    bin->raw_data = data;
    bin->raw_size = size;

    if (!elf_parse_ehdr(data, size, &bin->ehdr)) return false;
    bin->is_64bit         = (bin->ehdr.e_ident[EI_CLASS] == ELFCLASS64);
    bin->is_little_endian = (bin->ehdr.e_ident[EI_DATA] == ELFDATA2LSB);
    bin->elf_class        = (elf_class_t)bin->ehdr.e_ident[EI_CLASS];
    bin->elf_data         = (elf_data_t)bin->ehdr.e_ident[EI_DATA];
    bin->elf_type         = (elf_type_t)bin->ehdr.e_type;
    bin->elf_machine      = (elf_machine_t)bin->ehdr.e_machine;

    elf_parse_phdrs(data, size, &bin->ehdr, bin->phdrs, &bin->phdr_count);
    elf_parse_shdrs(data, size, &bin->ehdr, bin->shdrs, &bin->shdr_count);
    elf_load_shstrtab(data, size, &bin->ehdr, bin->shdrs, &bin->shstrtab, &bin->shstrtab_size);
    elf_parse_dynamic(data, size, bin->dynamic, &bin->dynamic_count,
                      bin->shdrs, bin->shdr_count, bin->shstrtab);
    elf_parse_dynsym(data, size, bin->dynsyms, &bin->dynsym_count,
                     bin->shdrs, bin->shdr_count, bin->shstrtab);
    elf_locate_got_plt(data, size, bin->shdrs, bin->shdr_count,
                       bin->shstrtab, &bin->got_plt_addr, &bin->got_plt_size);

    /* Extract DT_NEEDED */
    bin->needed_count = 0;
    for (uint32_t i = 0; i < bin->dynamic_count; i++) {
        if (bin->dynamic[i].d_tag == DT_NEEDED) {
            if (!bin->dynstr) {
                elf_section_info_t ds = elf_find_section(bin->shdrs, bin->shdr_count, bin->shstrtab, ".dynstr");
                if (ds.shdr) {
                    bin->dynstr = (char*)malloc(ds.shdr->sh_size + 1);
                    if (bin->dynstr) {
                        memcpy(bin->dynstr, data + ds.shdr->sh_offset, ds.shdr->sh_size);
                        bin->dynstr[ds.shdr->sh_size] = '\0';
                        bin->dynstr_size = ds.shdr->sh_size;
                    }
                }
            }
            if (bin->dynstr && bin->dynstr_size > 0 &&
                bin->dynamic[i].d_val < bin->dynstr_size &&
                bin->needed_count < ELF_MAX_NEEDED) {
                strncpy(bin->needed[bin->needed_count], bin->dynstr + bin->dynamic[i].d_val, 127);
                bin->needed_count++;
            }
        }
    }
    elf_binary_detect_security(bin);
    return true;
}

void elf_binary_free(elf_binary_t *bin) {
    if (!bin) return;
    free(bin->shstrtab);
    free(bin->dynstr);
    memset(bin, 0, sizeof(*bin));
}

bool elf_binary_detect_security(const elf_binary_t *bin) {
    if (!bin) return false;
    elf_binary_t *b = (elf_binary_t*)bin;
    b->has_gnu_stack = false;
    b->gnu_stack_exec = false;
    b->has_relro   = false;
    b->has_bind_now = false;
    b->is_pie       = (b->ehdr.e_type == ET_DYN);

    for (uint16_t i = 0; i < b->phdr_count; i++) {
        if (b->phdrs[i].p_type == PT_GNU_STACK) {
            b->has_gnu_stack = true;
            b->gnu_stack_exec = (b->phdrs[i].p_flags & PF_X) != 0;
        }
        if (b->phdrs[i].p_type == PT_GNU_RELRO) { b->has_relro = true; }
    }
    for (uint32_t i = 0; i < b->dynamic_count; i++) {
        if (b->dynamic[i].d_tag == DT_BIND_NOW) { b->has_bind_now = true; }
        if (b->dynamic[i].d_tag == DT_FLAGS_1) {
            if (b->dynamic[i].d_val & DF_1_NOW) b->has_bind_now = true;
        }
    }
    return true;
}

void elf_binary_print_security(const elf_binary_t *bin) {
    if (!bin) return;
    printf("\n╔══ ELF Security Analysis ═══════════════════╗\n");
    printf("║ NX (GNU_STACK):  %-25s║\n",
           bin->has_gnu_stack ? (bin->gnu_stack_exec ? "EXECUTABLE (danger!)" : "NX ENABLED") : "ABSENT (assume NX)");
    printf("║ RELRO:           %-25s║\n",
           bin->has_relro ? (bin->has_bind_now ? "FULL (BIND_NOW)" : "PARTIAL") : "NONE (GOT writable!)");
    printf("║ PIE:             %-25s║\n",
           bin->is_pie ? "ENABLED (ASLR compat)" : "NO PIE (fixed addr)");
    printf("║ GOT.PLT:         0x%016llX (size=%llu) ║\n",
           (unsigned long long)bin->got_plt_addr, (unsigned long long)bin->got_plt_size);

    int risk_level = 0;
    if (!bin->has_gnu_stack || bin->gnu_stack_exec) risk_level += 3;
    if (!bin->has_relro) risk_level += 2;
    if (!bin->has_bind_now && bin->has_relro) risk_level += 1;
    if (!bin->is_pie) risk_level += 2;

    printf("║ Risk Level:      ");
    if (risk_level <= 1)      printf("%-25s║\n", "LOW (well-hardened)");
    else if (risk_level <= 3) printf("%-25s║\n", "MEDIUM");
    else if (risk_level <= 5) printf("%-25s║\n", "HIGH");
    else                      printf("%-25s║\n", "CRITICAL");
    printf("╚══════════════════════════════════════════╝\n");
}

void elf_binary_print_summary(const elf_binary_t *bin) {
    if (!bin) return;
    elf_print_ehdr(&bin->ehdr);
    printf("\n─── Program Headers (%u) ───\n", bin->phdr_count);
    for (uint16_t i = 0; i < bin->phdr_count; i++) elf_print_phdr(&bin->phdrs[i], i);

    if (bin->shstrtab) {
        printf("\n─── Section Headers (%u) ───\n", bin->shdr_count);
        for (uint16_t i = 0; i < bin->shdr_count && i < 30; i++) {
            const char *name = bin->shstrtab + bin->shdrs[i].sh_name;
            elf_print_shdr(&bin->shdrs[i], name, i);
        }
        if (bin->shdr_count > 30) printf("  ... (%u more sections)\n", bin->shdr_count - 30);
    }
    if (bin->dynamic_count > 0) {
        printf("\n─── Dynamic Entries (%u) ───\n", bin->dynamic_count);
        for (uint32_t i = 0; i < bin->dynamic_count && i < 20; i++)
            elf_print_dynamic(&bin->dynamic[i], i);
        if (bin->dynamic_count > 20) printf("  ... (%u more entries)\n", bin->dynamic_count - 20);
    }
    if (bin->needed_count > 0) {
        printf("\n─── Shared Libraries ───\n");
        for (uint32_t i = 0; i < bin->needed_count; i++) printf("  [%u] %s\n", i, bin->needed[i]);
    }
    elf_binary_print_security(bin);
}

/* ═══════════════════════════════════════════════════════════════════
   Segment Analysis for Security (L4: W^X Theorem validation)
   ═══════════════════════════════════════════════════════════════════ */

bool elf_get_executable_segments(const elf64_phdr_t *phdrs, uint16_t count,
                                  elf_segment_summary_t *segs, uint16_t *seg_count) {
    if (!phdrs || !segs || !seg_count) return false;
    *seg_count = 0;
    for (uint16_t i = 0; i < count && *seg_count < 16; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        segs[*seg_count].vaddr       = phdrs[i].p_vaddr;
        segs[*seg_count].memsz       = phdrs[i].p_memsz;
        segs[*seg_count].flags       = phdrs[i].p_flags;
        segs[*seg_count].is_load     = true;
        segs[*seg_count].is_exec     = (phdrs[i].p_flags & PF_X) != 0;
        segs[*seg_count].is_writable = (phdrs[i].p_flags & PF_W) != 0;
        segs[*seg_count].is_readable = (phdrs[i].p_flags & PF_R) != 0;
        (*seg_count)++;
    }
    return true;
}

bool elf_check_nx_compliance(const elf64_phdr_t *phdrs, uint16_t count) {
    if (!phdrs) return false;
    for (uint16_t i = 0; i < count; i++) {
        if (phdrs[i].p_type == PT_LOAD &&
            (phdrs[i].p_flags & PF_W) && (phdrs[i].p_flags & PF_X))
            return false;
    }
    return true;
}

bool elf_check_relro_compliance(const elf_binary_t *bin) {
    if (!bin) return false;
    return bin->has_relro && bin->has_bind_now;
}

/* ═══════════════════════════════════════════════════════════════════
   Binary Patching (for exploit simulation)
   ═══════════════════════════════════════════════════════════════════ */

bool elf_patch_got_entry(const uint8_t *data, size_t size,
                         uint64_t got_addr, uint64_t new_value) {
    (void)data; (void)size; (void)got_addr; (void)new_value;
    printf("[ELF-PATCH] Would patch GOT @ 0x%016llX -> 0x%016llX\n",
           (unsigned long long)got_addr, (unsigned long long)new_value);
    printf("[ELF-PATCH] Real patch requires: ptrace/writev in running process.\n");
    return true;
}

/* ================================================================
   ELF Program Loader Simulation (L5: Kernel loader algorithm)
   ================================================================

   Simulates the kernel's ELF loader: maps LOAD segments, resolves
   symbols, applies relocations. Understand how binary memory layout
   is constructed at runtime - critical for exploit development.
   ================================================================ */

bool elf_simulate_load(const elf_binary_t *bin, uint64_t aslr_offset,
                       elf_load_image_t *image) {
    if (!bin || !image) return false;
    memset(image, 0, sizeof(*image));

    image->base_addr   = aslr_offset;
    image->entry_point = bin->ehdr.e_entry + aslr_offset;
    image->stack_top   = 0x7FFFFFFF0000ULL;
    image->num_load_segments = 0;

    for (uint16_t i = 0; i < bin->phdr_count; i++) {
        if (bin->phdrs[i].p_type != PT_LOAD) continue;
        if (image->num_load_segments >= 8) break;
        uint64_t vaddr = bin->phdrs[i].p_vaddr + aslr_offset;
        uint64_t memsz = bin->phdrs[i].p_memsz;
        image->load_segments[image->num_load_segments][0] = vaddr;
        image->load_segments[image->num_load_segments][1] = memsz;
        image->num_load_segments++;
        printf("[ELF-LOAD] LOAD segment: vaddr=0x%016llX memsz=%llu flags=%c%c%c\n",
               (unsigned long long)vaddr, (unsigned long long)memsz,
               (bin->phdrs[i].p_flags & PF_R) ? 'R' : '-',
               (bin->phdrs[i].p_flags & PF_W) ? 'W' : '-',
               (bin->phdrs[i].p_flags & PF_X) ? 'X' : '-');
    }
    return true;
}

/* ================================================================
   Fake ELF Generator (L6: Test fixture without real binaries)
   ================================================================

   Generates minimal valid ELF64 executables in memory for testing.
   Essential for unit testing parsers without needing real files.
   ================================================================ */



bool elf_generate_fake_executable(fake_elf_t *fake) {
    if (!fake) return false;
    memset(fake, 0, sizeof(*fake));
    uint8_t *buf = fake->data;
    size_t off = 0;

    /* ELF Magic + ident */
    buf[off++] = 0x7F; buf[off++] = 'E'; buf[off++] = 'L'; buf[off++] = 'F';
    buf[off++] = 2; buf[off++] = 1; buf[off++] = 1; buf[off++] = 3;
    for (int i = 0; i < 8; i++) buf[off++] = 0;

    /* e_type = ET_EXEC, e_machine = EM_X86_64 */
    buf[off++] = 0x02; buf[off++] = 0x00;
    buf[off++] = 0x3E; buf[off++] = 0x00;
    buf[off++] = 0x01; buf[off++] = 0x00; buf[off++] = 0x00; buf[off++] = 0x00;

    uint64_t entry = 0x401000ULL; memcpy(buf + off, &entry, 8); off += 8;
    uint64_t phoff = 0x40ULL;     memcpy(buf + off, &phoff, 8); off += 8;
    uint64_t shoff = 0;           memcpy(buf + off, &shoff, 8); off += 8;
    buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0;

    buf[off++] = 0x40; buf[off++] = 0x00;  /* e_ehsize = 64 */
    buf[off++] = 0x38; buf[off++] = 0x00;  /* e_phentsize = 56 */
    buf[off++] = 0x02; buf[off++] = 0x00;  /* e_phnum = 2 */
    for (int i = 0; i < 6; i++) buf[off++] = 0;

    /* PHDR 1: PT_LOAD (R-X, .text) */
    uint32_t ph_type = PT_LOAD, ph_flags = PF_R | PF_X;
    uint64_t ph_offset = 0x1000, ph_vaddr = 0x401000, ph_paddr = 0x401000;
    uint64_t ph_filesz = 0x1000, ph_memsz = 0x1000, ph_align = 0x1000;
    memcpy(buf + off, &ph_type, 4);   off += 4;
    memcpy(buf + off, &ph_flags, 4);  off += 4;
    memcpy(buf + off, &ph_offset, 8); off += 8;
    memcpy(buf + off, &ph_vaddr, 8);  off += 8;
    memcpy(buf + off, &ph_paddr, 8);  off += 8;
    memcpy(buf + off, &ph_filesz, 8); off += 8;
    memcpy(buf + off, &ph_memsz, 8);  off += 8;
    memcpy(buf + off, &ph_align, 8);  off += 8;

    /* PHDR 2: PT_GNU_STACK (RW-, NX) */
    ph_type = PT_GNU_STACK; ph_flags = PF_R | PF_W;
    ph_offset = 0; ph_vaddr = 0; ph_paddr = 0;
    ph_filesz = 0; ph_memsz = 0; ph_align = 0x10;
    memcpy(buf + off, &ph_type, 4);   off += 4;
    memcpy(buf + off, &ph_flags, 4);  off += 4;
    memcpy(buf + off, &ph_offset, 8); off += 8;
    memcpy(buf + off, &ph_vaddr, 8);  off += 8;
    memcpy(buf + off, &ph_paddr, 8);  off += 8;
    memcpy(buf + off, &ph_filesz, 8); off += 8;
    memcpy(buf + off, &ph_memsz, 8);  off += 8;
    memcpy(buf + off, &ph_align, 8);  off += 8;

    fake->size = off;
    fake->valid = true;
    return true;
}

bool elf_generate_fake_shared_object(fake_elf_t *fake) {
    if (!fake) return false;
    memset(fake, 0, sizeof(*fake));
    uint8_t *buf = fake->data;
    size_t off = 0;

    buf[off++] = 0x7F; buf[off++] = 'E'; buf[off++] = 'L'; buf[off++] = 'F';
    buf[off++] = 2; buf[off++] = 1; buf[off++] = 1; buf[off++] = 3;
    for (int i = 0; i < 8; i++) buf[off++] = 0;

    /* e_type = ET_DYN (shared object / PIE) */
    buf[off++] = 0x03; buf[off++] = 0x00;
    buf[off++] = 0x3E; buf[off++] = 0x00;
    buf[off++] = 0x01; buf[off++] = 0x00; buf[off++] = 0x00; buf[off++] = 0x00;

    uint64_t entry = 0x1060ULL; memcpy(buf + off, &entry, 8); off += 8;
    uint64_t phoff = 0x40ULL;   memcpy(buf + off, &phoff, 8); off += 8;
    uint64_t shoff = 0;         memcpy(buf + off, &shoff, 8); off += 8;
    buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 0;

    buf[off++] = 0x40; buf[off++] = 0x00;
    buf[off++] = 0x38; buf[off++] = 0x00;
    buf[off++] = 0x05; buf[off++] = 0x00;
    for (int i = 0; i < 6; i++) buf[off++] = 0;

    /* PHDR 1: PT_LOAD (R-X) */
    { uint32_t p=PT_LOAD, f=PF_R|PF_X; uint64_t o=0, va=0x1000, pa=0x1000, fz=0x200, mz=0x200, al=0x1000;
    memcpy(buf+off,&p,4);off+=4; memcpy(buf+off,&f,4);off+=4; memcpy(buf+off,&o,8);off+=8;
    memcpy(buf+off,&va,8);off+=8; memcpy(buf+off,&pa,8);off+=8; memcpy(buf+off,&fz,8);off+=8;
    memcpy(buf+off,&mz,8);off+=8; memcpy(buf+off,&al,8);off+=8; }

    /* PHDR 2: PT_LOAD (RW-) */
    { uint32_t p=PT_LOAD, f=PF_R|PF_W; uint64_t o=0x1000, va=0x2000, pa=0x2000, fz=0x100, mz=0x100, al=0x1000;
    memcpy(buf+off,&p,4);off+=4; memcpy(buf+off,&f,4);off+=4; memcpy(buf+off,&o,8);off+=8;
    memcpy(buf+off,&va,8);off+=8; memcpy(buf+off,&pa,8);off+=8; memcpy(buf+off,&fz,8);off+=8;
    memcpy(buf+off,&mz,8);off+=8; memcpy(buf+off,&al,8);off+=8; }

    /* PHDR 3: PT_DYNAMIC */
    { uint32_t p=PT_DYNAMIC, f=PF_R|PF_W; uint64_t o=0x1000, va=0x2008, pa=0x2008, fz=0x100, mz=0x100, al=8;
    memcpy(buf+off,&p,4);off+=4; memcpy(buf+off,&f,4);off+=4; memcpy(buf+off,&o,8);off+=8;
    memcpy(buf+off,&va,8);off+=8; memcpy(buf+off,&pa,8);off+=8; memcpy(buf+off,&fz,8);off+=8;
    memcpy(buf+off,&mz,8);off+=8; memcpy(buf+off,&al,8);off+=8; }

    /* PHDR 4: PT_GNU_RELRO */
    { uint32_t p=PT_GNU_RELRO, f=PF_R; uint64_t o=0x1000, va=0x2000, pa=0x2000, fz=0x100, mz=0x100, al=0x1000;
    memcpy(buf+off,&p,4);off+=4; memcpy(buf+off,&f,4);off+=4; memcpy(buf+off,&o,8);off+=8;
    memcpy(buf+off,&va,8);off+=8; memcpy(buf+off,&pa,8);off+=8; memcpy(buf+off,&fz,8);off+=8;
    memcpy(buf+off,&mz,8);off+=8; memcpy(buf+off,&al,8);off+=8; }

    /* PHDR 5: PT_GNU_STACK (RW-, NX) */
    { uint32_t p=PT_GNU_STACK, f=PF_R|PF_W; uint64_t o=0, va=0, pa=0, fz=0, mz=0, al=0x10;
    memcpy(buf+off,&p,4);off+=4; memcpy(buf+off,&f,4);off+=4; memcpy(buf+off,&o,8);off+=8;
    memcpy(buf+off,&va,8);off+=8; memcpy(buf+off,&pa,8);off+=8; memcpy(buf+off,&fz,8);off+=8;
    memcpy(buf+off,&mz,8);off+=8; memcpy(buf+off,&al,8);off+=8; }

    fake->size = off;
    fake->valid = true;
    return true;
}
