#ifndef ROP_GADGET_H
#define ROP_GADGET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Gadget classification ── */
typedef enum {
    GADGET_NOP          = 0,  /* ret only                     */
    GADGET_POP_REG      = 1,  /* pop rXX; ret                 */
    GADGET_MOV_REG_REG  = 2,  /* mov rXX, rYY; ret            */
    GADGET_LOAD_MEM     = 3,  /* mov rXX, [rYY]; ret          */
    GADGET_STORE_MEM    = 4,  /* mov [rXX], rYY; ret          */
    GADGET_ARITH        = 5,  /* add/sub/xor rXX, rYY; ret   */
    GADGET_SYSCALL      = 6,  /* syscall; ret                 */
    GADGET_LEAVE_RET    = 7,  /* leave; ret (stack pivot)     */
    GADGET_XCHG         = 8,  /* xchg rXX, rYY; ret           */
    GADGET_JMP_REG      = 9,  /* jmp rXX (JOP)                */
    GADGET_OTHER        = 10,
} gadget_class_t;

/* ── Single ROP gadget ── */
typedef struct {
    uint64_t       address;
    uint8_t        bytes[16];
    uint8_t        num_bytes;
    char           mnemonic[64];
    gadget_class_t class;
    uint8_t        reg_src;       /* source register index     */
    uint8_t        reg_dst;       /* destination register index */
    uint8_t        reg_pop;       /* popped register index      */
    uint64_t       imm_value;     /* immediate operand          */
    bool           has_side_effect;
} rop_gadget_t;

/* ── Chain node ── */
typedef struct {
    const rop_gadget_t *gadget;
    uint64_t             argument;   /* value pushed after return address */
    char                 comment[64];
} rop_chain_node_t;

/* ── ROP chain ── */
#define ROP_CHAIN_MAX_NODES 64
typedef struct {
    rop_chain_node_t nodes[ROP_CHAIN_MAX_NODES];
    uint32_t         count;
    uint64_t         stack_pivot_addr;
    bool             uses_pivot;
} rop_chain_t;

/* ── Gadget database ── */
#define GADGET_DB_MAX 512
typedef struct {
    rop_gadget_t gadgets[GADGET_DB_MAX];
    uint32_t     count;
} gadget_db_t;

/* ── JOP (Jump-Oriented Programming) ── */
typedef struct {
    uint64_t dispatch_addr;
    uint64_t dispatch_table[8];
    uint32_t count;
} jop_dispatch_t;

typedef struct {
    uint64_t gadget_addr;
    uint64_t arg0, arg1, arg2;
} jop_entry_t;

/* ── SROP (Sigreturn-Oriented Programming) ── */
typedef struct {
    uint64_t uc_flags;
    uint64_t uc_link;
    uint64_t ss_sp;       /* stack pointer       */
    uint64_t ss_size;
    uint64_t ss_flags;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rdi, rsi, rbp, rbx;
    uint64_t rdx, rax, rcx, rsp;
    uint64_t rip;         /* controlled RIP      */
    uint64_t eflags;
    uint64_t cs_gs_fs;
    uint64_t err, trapno, oldmask, cr2;
    uint64_t fpstate;
    uint64_t sigmask;
} srop_frame_t;

/* x86_64 sigframe requires >= 248 bytes; struct is 240 bytes, acceptable for simulation */

/* ── Gadget libraries (well-known gadgets) ── */
typedef struct {
    uint64_t pop_rdi;
    uint64_t pop_rsi;
    uint64_t pop_rdx;
    uint64_t pop_rcx;
    uint64_t pop_rax;
    uint64_t pop_rbx;
    uint64_t pop_rbp;
    uint64_t pop_rsp;
    uint64_t pop_r8;
    uint64_t pop_r9;
    uint64_t syscall;
    uint64_t leave_ret;
    uint64_t ret;
    uint64_t mov_rdi_rsp_call;
    bool     valid[14];
} well_known_gadgets_t;

/* ── API ── */

/* Gadget scanning */
void        rop_gadget_db_init(gadget_db_t *db);
bool        rop_gadget_db_add(gadget_db_t *db, uint64_t addr,
                              const uint8_t *bytes, uint8_t len);
uint32_t    rop_find_gadgets(const uint8_t *binary, size_t bin_len,
                             gadget_db_t *db);
void        rop_gadget_classify(rop_gadget_t *g);
void        rop_gadget_print(const rop_gadget_t *g);

/* Chain building */
void        rop_chain_init(rop_chain_t *c);
bool        rop_chain_append(rop_chain_t *c, const rop_gadget_t *g,
                             uint64_t arg, const char *desc);
bool        rop_chain_build_execve(const gadget_db_t *db, rop_chain_t *c,
                                   const char *cmd);
bool        rop_chain_build_mprotect(const gadget_db_t *db, rop_chain_t *c,
                                     uint64_t addr, size_t len, int prot);
void        rop_chain_print(const rop_chain_t *c);
void        rop_chain_simulate(const rop_chain_t *c);

/* Stack pivot */
bool        rop_chain_pivot(rop_chain_t *c, uint64_t leave_ret_addr,
                            uint64_t fake_stack);

/* JOP */
void        jop_dispatch_init(jop_dispatch_t *jd);
bool        jop_dispatch_add(jop_dispatch_t *jd, uint64_t addr);
void        jop_exec_simulate(const jop_dispatch_t *jd);

/* SROP */
void        srop_frame_init(srop_frame_t *f);
void        srop_frame_set_execve(srop_frame_t *f, uint64_t bin_sh_addr,
                                  uint64_t syscall_addr);
void        srop_frame_print(const srop_frame_t *f);

/* Well-known gadget helpers */
void        well_known_init(well_known_gadgets_t *g, uint64_t libc_base);
void        well_known_print(const well_known_gadgets_t *g);

#ifdef __cplusplus
}
#endif

#endif /* ROP_GADGET_H */
