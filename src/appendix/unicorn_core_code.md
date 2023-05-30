# Unicorn部分核心代码

## unicorn.h

* unicorn.h
  * unicorn/unicorn.h at master · unicorn-engine/unicorn · GitHub
    * https://github.com/unicorn-engine/unicorn/blob/master/include/unicorn/unicorn.h

### arch架构

```c
// Architecture type
typedef enum uc_arch {
    UC_ARCH_ARM = 1, // ARM architecture (including Thumb, Thumb-2)
    UC_ARCH_ARM64,   // ARM-64, also called AArch64
    UC_ARCH_MIPS,    // Mips architecture
    UC_ARCH_X86,     // X86 architecture (including x86 & x86-64)
    UC_ARCH_PPC,     // PowerPC architecture
    UC_ARCH_SPARC,   // Sparc architecture
    UC_ARCH_M68K,    // M68K architecture
    UC_ARCH_RISCV,   // RISCV architecture
    UC_ARCH_S390X,   // S390X architecture
    UC_ARCH_TRICORE, // TriCore architecture
    UC_ARCH_MAX,
} uc_arch;
```

### mode模式

```c
// Mode type
typedef enum uc_mode {
    UC_MODE_LITTLE_ENDIAN = 0,    // little-endian mode (default mode)
    UC_MODE_BIG_ENDIAN = 1 << 30, // big-endian mode

    // arm / arm64
    UC_MODE_ARM = 0,        // ARM mode
    UC_MODE_THUMB = 1 << 4, // THUMB mode (including Thumb-2)
    // Depreciated, use UC_ARM_CPU_* with uc_ctl instead.
    UC_MODE_MCLASS = 1 << 5,  // ARM's Cortex-M series.
    UC_MODE_V8 = 1 << 6,      // ARMv8 A32 encodings for ARM
    UC_MODE_ARMBE8 = 1 << 10, // Big-endian data and Little-endian code.
                              // Legacy support for UC1 only.

    // arm (32bit) cpu types
    // Depreciated, use UC_ARM_CPU_* with uc_ctl instead.
    UC_MODE_ARM926 = 1 << 7,  // ARM926 CPU type
    UC_MODE_ARM946 = 1 << 8,  // ARM946 CPU type
    UC_MODE_ARM1176 = 1 << 9, // ARM1176 CPU type

    // mips
    UC_MODE_MICRO = 1 << 4,    // MicroMips mode (currently unsupported)
    UC_MODE_MIPS3 = 1 << 5,    // Mips III ISA (currently unsupported)
    UC_MODE_MIPS32R6 = 1 << 6, // Mips32r6 ISA (currently unsupported)
    UC_MODE_MIPS32 = 1 << 2,   // Mips32 ISA
    UC_MODE_MIPS64 = 1 << 3,   // Mips64 ISA

    // x86 / x64
    UC_MODE_16 = 1 << 1, // 16-bit mode
    UC_MODE_32 = 1 << 2, // 32-bit mode
    UC_MODE_64 = 1 << 3, // 64-bit mode

    // ppc
    UC_MODE_PPC32 = 1 << 2, // 32-bit mode
    UC_MODE_PPC64 = 1 << 3, // 64-bit mode (currently unsupported)
    UC_MODE_QPX =
        1 << 4, // Quad Processing eXtensions mode (currently unsupported)

    // sparc
    UC_MODE_SPARC32 = 1 << 2, // 32-bit mode
    UC_MODE_SPARC64 = 1 << 3, // 64-bit mode
    UC_MODE_V9 = 1 << 4,      // SparcV9 mode (currently unsupported)

    // riscv
    UC_MODE_RISCV32 = 1 << 2, // 32-bit mode
    UC_MODE_RISCV64 = 1 << 3, // 64-bit mode

    // m68k
} uc_mode;
```

### 错误类型

```c
// All type of errors encountered by Unicorn API.
// These are values returned by uc_errno()
typedef enum uc_err {
    UC_ERR_OK = 0,         // No error: everything was fine
    UC_ERR_NOMEM,          // Out-Of-Memory error: uc_open(), uc_emulate()
    UC_ERR_ARCH,           // Unsupported architecture: uc_open()
    UC_ERR_HANDLE,         // Invalid handle
    UC_ERR_MODE,           // Invalid/unsupported mode: uc_open()
    UC_ERR_VERSION,        // Unsupported version (bindings)
    UC_ERR_READ_UNMAPPED,  // Quit emulation due to READ on unmapped memory:
                           // uc_emu_start()
    UC_ERR_WRITE_UNMAPPED, // Quit emulation due to WRITE on unmapped memory:
                           // uc_emu_start()
    UC_ERR_FETCH_UNMAPPED, // Quit emulation due to FETCH on unmapped memory:
                           // uc_emu_start()
    UC_ERR_HOOK,           // Invalid hook type: uc_hook_add()
    UC_ERR_INSN_INVALID,   // Quit emulation due to invalid instruction:
                           // uc_emu_start()
    UC_ERR_MAP,            // Invalid memory mapping: uc_mem_map()
    UC_ERR_WRITE_PROT,     // Quit emulation due to UC_MEM_WRITE_PROT violation:
                           // uc_emu_start()
    UC_ERR_READ_PROT,      // Quit emulation due to UC_MEM_READ_PROT violation:
                           // uc_emu_start()
    UC_ERR_FETCH_PROT,     // Quit emulation due to UC_MEM_FETCH_PROT violation:
                           // uc_emu_start()
    UC_ERR_ARG, // Inavalid argument provided to uc_xxx function (See specific
                // function API)
    UC_ERR_READ_UNALIGNED,  // Unaligned read
    UC_ERR_WRITE_UNALIGNED, // Unaligned write
    UC_ERR_FETCH_UNALIGNED, // Unaligned fetch
    UC_ERR_HOOK_EXIST,      // hook for this event already existed
    UC_ERR_RESOURCE,        // Insufficient resource: uc_emu_start()
    UC_ERR_EXCEPTION,       // Unhandled CPU exception
} uc_err;
```

### hook类型

```c
// All type of hooks for uc_hook_add() API.
typedef enum uc_hook_type {
    // Hook all interrupt/syscall events
    UC_HOOK_INTR = 1 << 0,
    // Hook a particular instruction - only a very small subset of instructions
    // supported here
    UC_HOOK_INSN = 1 << 1,
    // Hook a range of code
    UC_HOOK_CODE = 1 << 2,
    // Hook basic blocks
    UC_HOOK_BLOCK = 1 << 3,
    // Hook for memory read on unmapped memory
    UC_HOOK_MEM_READ_UNMAPPED = 1 << 4,
    // Hook for invalid memory write events
    UC_HOOK_MEM_WRITE_UNMAPPED = 1 << 5,
    // Hook for invalid memory fetch for execution events
    UC_HOOK_MEM_FETCH_UNMAPPED = 1 << 6,
    // Hook for memory read on read-protected memory
    UC_HOOK_MEM_READ_PROT = 1 << 7,
    // Hook for memory write on write-protected memory
    UC_HOOK_MEM_WRITE_PROT = 1 << 8,
    // Hook for memory fetch on non-executable memory
    UC_HOOK_MEM_FETCH_PROT = 1 << 9,
    // Hook memory read events.
    UC_HOOK_MEM_READ = 1 << 10,
    // Hook memory write events.
    UC_HOOK_MEM_WRITE = 1 << 11,
    // Hook memory fetch for execution events
    UC_HOOK_MEM_FETCH = 1 << 12,
    // Hook memory read events, but only successful access.
    // The callback will be triggered after successful read.
    UC_HOOK_MEM_READ_AFTER = 1 << 13,
    // Hook invalid instructions exceptions.
    UC_HOOK_INSN_INVALID = 1 << 14,
    // Hook on new edge generation. Could be useful in program analysis.
    //
    // NOTE: This is different from UC_HOOK_BLOCK in 2 ways:
    //       1. The hook is called before executing code.
    //       2. The hook is only called when generation is triggered.
    UC_HOOK_EDGE_GENERATED = 1 << 15,
    // Hook on specific tcg op code. The usage of this hook is similar to
    // UC_HOOK_INSN.
    UC_HOOK_TCG_OPCODE = 1 << 16,
} uc_hook_type;
```

## unicorn.py

* unicorn.py
  * unicorn/unicorn.py at master · unicorn-engine/unicorn · GitHub
    * https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/unicorn/unicorn.py

### 主要函数

```c
_setup_prototype(_uc, "uc_version", ctypes.c_uint, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
_setup_prototype(_uc, "uc_arch_supported", ctypes.c_bool, ctypes.c_int)
_setup_prototype(_uc, "uc_open", ucerr, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(uc_engine))
_setup_prototype(_uc, "uc_close", ucerr, uc_engine)
_setup_prototype(_uc, "uc_strerror", ctypes.c_char_p, ucerr)
_setup_prototype(_uc, "uc_errno", ucerr, uc_engine)
_setup_prototype(_uc, "uc_reg_read", ucerr, uc_engine, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_reg_write", ucerr, uc_engine, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_mem_read", ucerr, uc_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
_setup_prototype(_uc, "uc_mem_write", ucerr, uc_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
_setup_prototype(_uc, "uc_emu_start", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_size_t)
_setup_prototype(_uc, "uc_emu_stop", ucerr, uc_engine)
_setup_prototype(_uc, "uc_hook_del", ucerr, uc_engine, uc_hook_h)
_setup_prototype(_uc, "uc_mmio_map", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
_setup_prototype(_uc, "uc_mem_map", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
_setup_prototype(_uc, "uc_mem_map_ptr", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p)
_setup_prototype(_uc, "uc_mem_unmap", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t)
_setup_prototype(_uc, "uc_mem_protect", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
_setup_prototype(_uc, "uc_query", ucerr, uc_engine, ctypes.c_uint32, ctypes.POINTER(ctypes.c_size_t))
_setup_prototype(_uc, "uc_context_alloc", ucerr, uc_engine, ctypes.POINTER(uc_context))
_setup_prototype(_uc, "uc_free", ucerr, ctypes.c_void_p)
_setup_prototype(_uc, "uc_context_save", ucerr, uc_engine, uc_context)
_setup_prototype(_uc, "uc_context_restore", ucerr, uc_engine, uc_context)
_setup_prototype(_uc, "uc_context_size", ctypes.c_size_t, uc_engine)
_setup_prototype(_uc, "uc_context_reg_read", ucerr, uc_context, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_context_reg_write", ucerr, uc_context, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_context_free", ucerr, uc_context)
_setup_prototype(_uc, "uc_mem_regions", ucerr, uc_engine, ctypes.POINTER(ctypes.POINTER(_uc_mem_region)), ctypes.POINTER(ctypes.c_uint32))
# https://bugs.python.org/issue42880
_setup_prototype(_uc, "uc_hook_add", ucerr, uc_engine, ctypes.POINTER(uc_hook_h), ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64)
_setup_prototype(_uc, "uc_ctl", ucerr, uc_engine, ctypes.c_int)
```

## uc_priv.h

* uc_priv.h
  * unicorn/uc_priv.h at master · unicorn-engine/unicorn · GitHub
    * https://github.com/unicorn-engine/unicorn/blob/master/include/uc_priv.h

### hook的结构体

```c
struct hook {
    int type;       // UC_HOOK_*
    int insn;       // instruction for HOOK_INSN
    int refs;       // reference count to free hook stored in multiple lists
    int op;         // opcode for HOOK_TCG_OPCODE
    int op_flags;   // opcode flags for HOOK_TCG_OPCODE
    bool to_delete; // set to true when the hook is deleted by the user. The
                    // destruction of the hook is delayed.
    uint64_t begin, end; // only trigger if PC or memory access is in this
                         // address (depends on hook type)
    void *callback;      // a uc_cb_* type
    void *user_data;
    GHashTable *hooked_regions; // The regions this hook instrumented on
};
```

### hook列表

```c
// hook list offsets
//
// The lowest 6 bits are used for hook type index while the others
// are used for hook flags.
//
// mirrors the order of uc_hook_type from include/unicorn/unicorn.h
typedef enum uc_hook_idx {
    UC_HOOK_INTR_IDX,
    UC_HOOK_INSN_IDX,
    UC_HOOK_CODE_IDX,
    UC_HOOK_BLOCK_IDX,
    UC_HOOK_MEM_READ_UNMAPPED_IDX,
    UC_HOOK_MEM_WRITE_UNMAPPED_IDX,
    UC_HOOK_MEM_FETCH_UNMAPPED_IDX,
    UC_HOOK_MEM_READ_PROT_IDX,
    UC_HOOK_MEM_WRITE_PROT_IDX,
    UC_HOOK_MEM_FETCH_PROT_IDX,
    UC_HOOK_MEM_READ_IDX,
    UC_HOOK_MEM_WRITE_IDX,
    UC_HOOK_MEM_FETCH_IDX,
    UC_HOOK_MEM_READ_AFTER_IDX,
    UC_HOOK_INSN_INVALID_IDX,
    UC_HOOK_EDGE_GENERATED_IDX,
    UC_HOOK_TCG_OPCODE_IDX,

    UC_HOOK_MAX,
} uc_hook_idx;
```

### unicorn对象的结构体

```c
struct uc_struct {
    uc_arch arch;
    uc_mode mode;
    uc_err errnum; // qemu/cpu-exec.c
    AddressSpace address_space_memory;
    AddressSpace address_space_io;
    query_t query;
    reg_read_t reg_read;
    reg_write_t reg_write;
    reg_reset_t reg_reset;

    uc_write_mem_t write_mem;
    uc_read_mem_t read_mem;
    uc_args_void_t release;  // release resource when uc_close()
    uc_args_uc_u64_t set_pc; // set PC for tracecode
    uc_get_pc_t get_pc;
    uc_args_int_t
        stop_interrupt; // check if the interrupt should stop emulation
    uc_memory_map_io_t memory_map_io;

    uc_args_uc_t init_arch, cpu_exec_init_all;
    uc_args_int_uc_t vm_start;
    uc_args_uc_long_t tcg_exec_init;
    uc_args_uc_ram_size_t memory_map;
    uc_args_uc_ram_size_ptr_t memory_map_ptr;
    uc_mem_unmap_t memory_unmap;
    uc_readonly_mem_t readonly_mem;
    uc_mem_redirect_t mem_redirect;
    uc_cpus_init cpus_init;
    uc_target_page_init target_page;
    uc_softfloat_initialize softfloat_initialize;
    uc_tcg_flush_tlb tcg_flush_tlb;
    uc_invalidate_tb_t uc_invalidate_tb;
    uc_gen_tb_t uc_gen_tb;
    uc_tb_flush_t tb_flush;
    uc_add_inline_hook_t add_inline_hook;
    uc_del_inline_hook_t del_inline_hook;

    uc_context_size_t context_size;
    uc_context_save_t context_save;
    uc_context_restore_t context_restore;

    /*  only 1 cpu in unicorn,
        do not need current_cpu to handle current running cpu. */
    CPUState *cpu;

    uc_insn_hook_validate insn_hook_validate;
    uc_opcode_hook_validate_t opcode_hook_invalidate;

    MemoryRegion *system_memory;    // qemu/exec.c
    MemoryRegion *system_io;        // qemu/exec.c
    MemoryRegion io_mem_unassigned; // qemu/exec.c
    RAMList ram_list;               // qemu/exec.c
    /* qemu/exec.c */
    unsigned int alloc_hint;
    /* qemu/exec-vary.c */
    TargetPageBits *init_target_page;
    int target_bits; // User defined page bits by uc_ctl
    int cpu_model;
    BounceBuffer bounce;                // qemu/cpu-exec.c
    volatile sig_atomic_t exit_request; // qemu/cpu-exec.c
    /* qemu/accel/tcg/cpu-exec-common.c */
    /* always be true after call tcg_exec_init(). */
    bool tcg_allowed;
    /* This is a multi-level map on the virtual address space.
       The bottom level has pointers to PageDesc.  */
    void **l1_map; // qemu/accel/tcg/translate-all.c
    size_t l1_map_size;
    /* qemu/accel/tcg/translate-all.c */
    int v_l1_size;
    int v_l1_shift;
    int v_l2_levels;
    /* code generation context */
    TCGContext *tcg_ctx;
    /* memory.c */
    QTAILQ_HEAD(memory_listeners, MemoryListener) memory_listeners;
    QTAILQ_HEAD(, AddressSpace) address_spaces;
    GHashTable *flat_views;
    bool memory_region_update_pending;

    // linked lists containing hooks per type
    struct list hook[UC_HOOK_MAX];
    struct list hooks_to_del;
    int hooks_count[UC_HOOK_MAX];

    // hook to count number of instructions for uc_emu_start()
    uc_hook count_hook;

    size_t emu_counter; // current counter of uc_emu_start()
    size_t emu_count;   // save counter of uc_emu_start()

    int size_recur_mem; // size for mem access when in a recursive call

    bool init_tcg;       // already initialized local TCGv variables?
    bool stop_request;   // request to immediately stop emulation - for
                         // uc_emu_stop()
    bool quit_request;   // request to quit the current TB, but continue to
                         // emulate - for uc_mem_protect()
    bool emulation_done; // emulation is done by uc_emu_start()
    bool timed_out;      // emulation timed out, that can retrieve via
                         // uc_query(UC_QUERY_TIMEOUT)
    QemuThread timer;    // timer for emulation timeout
    uint64_t timeout;    // timeout for uc_emu_start()

    uint64_t invalid_addr; // invalid address to be accessed
    int invalid_error;     // invalid memory code: 1 = READ, 2 = WRITE, 3 = CODE

    int use_exits;
    uint64_t exits[UC_MAX_NESTED_LEVEL]; // When multiple exits is not enabled.
    GTree *ctl_exits; // addresses where emulation stops (@until param of
                      // uc_emu_start()) Also see UC_CTL_USE_EXITS for more
                      // details.

    int thumb; // thumb mode for ARM
    MemoryRegion **mapped_blocks;
    uint32_t mapped_block_count;
    uint32_t mapped_block_cache_index;
    void *qemu_thread_data; // to support cross compile to Windows
                            // (qemu-thread-win32.c)
    uint32_t target_page_size;
    uint32_t target_page_align;
    uint64_t qemu_host_page_size;
    uint64_t qemu_real_host_page_size;
    int qemu_icache_linesize;
    /* ARCH_REGS_STORAGE_SIZE */
    int cpu_context_size;
    uint64_t next_pc; // save next PC for some special cases
    bool hook_insert; // insert new hook at begin of the hook list (append by
                      // default)
    bool first_tb; // is this the first Translation-Block ever generated since
                   // uc_emu_start()?
    bool no_exit_request; // Disable check_exit_request temporarily. A
                          // workaround to treat the IT block as a whole block.
    bool init_done;       // Whether the initialization is done.

    sigjmp_buf jmp_bufs[UC_MAX_NESTED_LEVEL]; // To support nested uc_emu_start
    int nested_level;                         // Current nested_level

    struct TranslationBlock *last_tb; // The real last tb we executed.

    FlatView *empty_view; // Static function variable moved from flatviews_init
};
```

## arm64.h

* arm64.h
  * unicorn/arm64.h at master · unicorn-engine/unicorn · GitHub
    * https://github.com/unicorn-engine/unicorn/blob/master/include/unicorn/arm64.h

### arm64寄存器

```c
//> ARM64 registers
typedef enum uc_arm64_reg {
    UC_ARM64_REG_INVALID = 0,

    UC_ARM64_REG_X29,
    UC_ARM64_REG_X30,
    UC_ARM64_REG_NZCV,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_WSP,
    UC_ARM64_REG_WZR,
    UC_ARM64_REG_XZR,
    UC_ARM64_REG_B0,
    UC_ARM64_REG_B1,
    UC_ARM64_REG_B2,
    UC_ARM64_REG_B3,
    UC_ARM64_REG_B4,
    UC_ARM64_REG_B5,
    UC_ARM64_REG_B6,
    UC_ARM64_REG_B7,
    UC_ARM64_REG_B8,
    UC_ARM64_REG_B9,
    UC_ARM64_REG_B10,
    UC_ARM64_REG_B11,
    UC_ARM64_REG_B12,
    UC_ARM64_REG_B13,
    UC_ARM64_REG_B14,
    UC_ARM64_REG_B15,
    UC_ARM64_REG_B16,
    UC_ARM64_REG_B17,
    UC_ARM64_REG_B18,
    UC_ARM64_REG_B19,
    UC_ARM64_REG_B20,
    UC_ARM64_REG_B21,
    UC_ARM64_REG_B22,
    UC_ARM64_REG_B23,
    UC_ARM64_REG_B24,
    UC_ARM64_REG_B25,
    UC_ARM64_REG_B26,
    UC_ARM64_REG_B27,
    UC_ARM64_REG_B28,
    UC_ARM64_REG_B29,
    UC_ARM64_REG_B30,
    UC_ARM64_REG_B31,
    UC_ARM64_REG_D0,
    UC_ARM64_REG_D1,
    UC_ARM64_REG_D2,
    UC_ARM64_REG_D3,
    UC_ARM64_REG_D4,
    UC_ARM64_REG_D5,
    UC_ARM64_REG_D6,
    UC_ARM64_REG_D7,
    UC_ARM64_REG_D8,
    UC_ARM64_REG_D9,
    UC_ARM64_REG_D10,
    UC_ARM64_REG_D11,
    UC_ARM64_REG_D12,
    UC_ARM64_REG_D13,
    UC_ARM64_REG_D14,
    UC_ARM64_REG_D15,
    UC_ARM64_REG_D16,
    UC_ARM64_REG_D17,
    UC_ARM64_REG_D18,
    UC_ARM64_REG_D19,
    UC_ARM64_REG_D20,
    UC_ARM64_REG_D21,
    UC_ARM64_REG_D22,
    UC_ARM64_REG_D23,
    UC_ARM64_REG_D24,
    UC_ARM64_REG_D25,
    UC_ARM64_REG_D26,
    UC_ARM64_REG_D27,
    UC_ARM64_REG_D28,
    UC_ARM64_REG_D29,
    UC_ARM64_REG_D30,
    UC_ARM64_REG_D31,
    UC_ARM64_REG_H0,
    UC_ARM64_REG_H1,
    UC_ARM64_REG_H2,
    UC_ARM64_REG_H3,
    UC_ARM64_REG_H4,
    UC_ARM64_REG_H5,
    UC_ARM64_REG_H6,
    UC_ARM64_REG_H7,
    UC_ARM64_REG_H8,
    UC_ARM64_REG_H9,
    UC_ARM64_REG_H10,
    UC_ARM64_REG_H11,
    UC_ARM64_REG_H12,
    UC_ARM64_REG_H13,
    UC_ARM64_REG_H14,
    UC_ARM64_REG_H15,
    UC_ARM64_REG_H16,
    UC_ARM64_REG_H17,
    UC_ARM64_REG_H18,
    UC_ARM64_REG_H19,
    UC_ARM64_REG_H20,
    UC_ARM64_REG_H21,
    UC_ARM64_REG_H22,
    UC_ARM64_REG_H23,
    UC_ARM64_REG_H24,
    UC_ARM64_REG_H25,
    UC_ARM64_REG_H26,
    UC_ARM64_REG_H27,
    UC_ARM64_REG_H28,
    UC_ARM64_REG_H29,
    UC_ARM64_REG_H30,
    UC_ARM64_REG_H31,
    UC_ARM64_REG_Q0,
    UC_ARM64_REG_Q1,
    UC_ARM64_REG_Q2,
    UC_ARM64_REG_Q3,
    UC_ARM64_REG_Q4,
    UC_ARM64_REG_Q5,
    UC_ARM64_REG_Q6,
    UC_ARM64_REG_Q7,
    UC_ARM64_REG_Q8,
    UC_ARM64_REG_Q9,
    UC_ARM64_REG_Q10,
    UC_ARM64_REG_Q11,
    UC_ARM64_REG_Q12,
    UC_ARM64_REG_Q13,
    UC_ARM64_REG_Q14,
    UC_ARM64_REG_Q15,
    UC_ARM64_REG_Q16,
    UC_ARM64_REG_Q17,
    UC_ARM64_REG_Q18,
    UC_ARM64_REG_Q19,
    UC_ARM64_REG_Q20,
    UC_ARM64_REG_Q21,
    UC_ARM64_REG_Q22,
    UC_ARM64_REG_Q23,
    UC_ARM64_REG_Q24,
    UC_ARM64_REG_Q25,
    UC_ARM64_REG_Q26,
    UC_ARM64_REG_Q27,
    UC_ARM64_REG_Q28,
    UC_ARM64_REG_Q29,
    UC_ARM64_REG_Q30,
    UC_ARM64_REG_Q31,
    UC_ARM64_REG_S0,
    UC_ARM64_REG_S1,
    UC_ARM64_REG_S2,
    UC_ARM64_REG_S3,
    UC_ARM64_REG_S4,
    UC_ARM64_REG_S5,
    UC_ARM64_REG_S6,
    UC_ARM64_REG_S7,
    UC_ARM64_REG_S8,
    UC_ARM64_REG_S9,
    UC_ARM64_REG_S10,
    UC_ARM64_REG_S11,
    UC_ARM64_REG_S12,
    UC_ARM64_REG_S13,
    UC_ARM64_REG_S14,
    UC_ARM64_REG_S15,
    UC_ARM64_REG_S16,
    UC_ARM64_REG_S17,
    UC_ARM64_REG_S18,
    UC_ARM64_REG_S19,
    UC_ARM64_REG_S20,
    UC_ARM64_REG_S21,
    UC_ARM64_REG_S22,
    UC_ARM64_REG_S23,
    UC_ARM64_REG_S24,
    UC_ARM64_REG_S25,
    UC_ARM64_REG_S26,
    UC_ARM64_REG_S27,
    UC_ARM64_REG_S28,
    UC_ARM64_REG_S29,
    UC_ARM64_REG_S30,
    UC_ARM64_REG_S31,
    UC_ARM64_REG_W0,
    UC_ARM64_REG_W1,
    UC_ARM64_REG_W2,
    UC_ARM64_REG_W3,
    UC_ARM64_REG_W4,
    UC_ARM64_REG_W5,
    UC_ARM64_REG_W6,
    UC_ARM64_REG_W7,
    UC_ARM64_REG_W8,
    UC_ARM64_REG_W9,
    UC_ARM64_REG_W10,
    UC_ARM64_REG_W11,
    UC_ARM64_REG_W12,
    UC_ARM64_REG_W13,
    UC_ARM64_REG_W14,
    UC_ARM64_REG_W15,
    UC_ARM64_REG_W16,
    UC_ARM64_REG_W17,
    UC_ARM64_REG_W18,
    UC_ARM64_REG_W19,
    UC_ARM64_REG_W20,
    UC_ARM64_REG_W21,
    UC_ARM64_REG_W22,
    UC_ARM64_REG_W23,
    UC_ARM64_REG_W24,
    UC_ARM64_REG_W25,
    UC_ARM64_REG_W26,
    UC_ARM64_REG_W27,
    UC_ARM64_REG_W28,
    UC_ARM64_REG_W29,
    UC_ARM64_REG_W30,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X6,
    UC_ARM64_REG_X7,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X9,
    UC_ARM64_REG_X10,
    UC_ARM64_REG_X11,
    UC_ARM64_REG_X12,
    UC_ARM64_REG_X13,
    UC_ARM64_REG_X14,
    UC_ARM64_REG_X15,
    UC_ARM64_REG_X16,
    UC_ARM64_REG_X17,
    UC_ARM64_REG_X18,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X21,
    UC_ARM64_REG_X22,
    UC_ARM64_REG_X23,
    UC_ARM64_REG_X24,
    UC_ARM64_REG_X25,
    UC_ARM64_REG_X26,
    UC_ARM64_REG_X27,
    UC_ARM64_REG_X28,

    UC_ARM64_REG_V0,
    UC_ARM64_REG_V1,
    UC_ARM64_REG_V2,
    UC_ARM64_REG_V3,
    UC_ARM64_REG_V4,
    UC_ARM64_REG_V5,
    UC_ARM64_REG_V6,
    UC_ARM64_REG_V7,
    UC_ARM64_REG_V8,
    UC_ARM64_REG_V9,
    UC_ARM64_REG_V10,
    UC_ARM64_REG_V11,
    UC_ARM64_REG_V12,
    UC_ARM64_REG_V13,
    UC_ARM64_REG_V14,
    UC_ARM64_REG_V15,
    UC_ARM64_REG_V16,
    UC_ARM64_REG_V17,
    UC_ARM64_REG_V18,
    UC_ARM64_REG_V19,
    UC_ARM64_REG_V20,
    UC_ARM64_REG_V21,
    UC_ARM64_REG_V22,
    UC_ARM64_REG_V23,
    UC_ARM64_REG_V24,
    UC_ARM64_REG_V25,
    UC_ARM64_REG_V26,
    UC_ARM64_REG_V27,
    UC_ARM64_REG_V28,
    UC_ARM64_REG_V29,
    UC_ARM64_REG_V30,
    UC_ARM64_REG_V31,

    //> pseudo registers
    UC_ARM64_REG_PC, // program counter register

    UC_ARM64_REG_CPACR_EL1,

    //> thread registers, depreciated, use UC_ARM64_REG_CP_REG instead
    UC_ARM64_REG_TPIDR_EL0,
    UC_ARM64_REG_TPIDRRO_EL0,
    UC_ARM64_REG_TPIDR_EL1,

    UC_ARM64_REG_PSTATE,

    //> exception link registers, depreciated, use UC_ARM64_REG_CP_REG instead
    UC_ARM64_REG_ELR_EL0,
    UC_ARM64_REG_ELR_EL1,
    UC_ARM64_REG_ELR_EL2,
    UC_ARM64_REG_ELR_EL3,

    //> stack pointers registers, depreciated, use UC_ARM64_REG_CP_REG instead
    UC_ARM64_REG_SP_EL0,
    UC_ARM64_REG_SP_EL1,
    UC_ARM64_REG_SP_EL2,
    UC_ARM64_REG_SP_EL3,

    //> other CP15 registers, depreciated, use UC_ARM64_REG_CP_REG instead
    UC_ARM64_REG_TTBR0_EL1,
    UC_ARM64_REG_TTBR1_EL1,

    UC_ARM64_REG_ESR_EL0,
    UC_ARM64_REG_ESR_EL1,
    UC_ARM64_REG_ESR_EL2,
    UC_ARM64_REG_ESR_EL3,

    UC_ARM64_REG_FAR_EL0,
    UC_ARM64_REG_FAR_EL1,
    UC_ARM64_REG_FAR_EL2,
    UC_ARM64_REG_FAR_EL3,

    UC_ARM64_REG_PAR_EL1,

    UC_ARM64_REG_MAIR_EL1,

    UC_ARM64_REG_VBAR_EL0,
    UC_ARM64_REG_VBAR_EL1,
    UC_ARM64_REG_VBAR_EL2,
    UC_ARM64_REG_VBAR_EL3,

    UC_ARM64_REG_CP_REG,

    //> floating point control and status registers
    UC_ARM64_REG_FPCR,
    UC_ARM64_REG_FPSR,

    UC_ARM64_REG_ENDING, // <-- mark the end of the list of registers

    //> alias registers

    UC_ARM64_REG_IP0 = UC_ARM64_REG_X16,
    UC_ARM64_REG_IP1 = UC_ARM64_REG_X17,
    UC_ARM64_REG_FP = UC_ARM64_REG_X29,
    UC_ARM64_REG_LR = UC_ARM64_REG_X30,
} uc_arm64_reg;
```

### arm64指令（支持hook的指令）

```c
//> ARM64 instructions
typedef enum uc_arm64_insn {
    UC_ARM64_INS_INVALID = 0,

    UC_ARM64_INS_MRS,
    UC_ARM64_INS_MSR,
    UC_ARM64_INS_SYS,
    UC_ARM64_INS_SYSL,

    UC_ARM64_INS_ENDING
} uc_arm64_insn;
```

## Unicorn相关错误

* [unicorn - 简书 (jianshu.com) ](https://www.jianshu.com/p/e6a7b30c1e89)

```c
typedef enum uc_err {
    UC_ERR_OK = 0,   // 无错误
    UC_ERR_NOMEM,      // 内存不足: uc_open(), uc_emulate()
    UC_ERR_ARCH,     // 不支持的架构: uc_open()
    UC_ERR_HANDLE,   // 不可用句柄
    UC_ERR_MODE,     // 不可用/不支持架构: uc_open()
    UC_ERR_VERSION,  // 不支持版本 (中间件)
    UC_ERR_READ_UNMAPPED, // 由于在未映射的内存上读取而退出模拟: uc_emu_start()
    UC_ERR_WRITE_UNMAPPED, // 由于在未映射的内存上写入而退出模拟: uc_emu_start()
    UC_ERR_FETCH_UNMAPPED, // 由于在未映射的内存中获取数据而退出模拟: uc_emu_start()
    UC_ERR_HOOK,    // 无效的hook类型: uc_hook_add()
    UC_ERR_INSN_INVALID, // 由于指令无效而退出模拟: uc_emu_start()
    UC_ERR_MAP, // 无效的内存映射: uc_mem_map()
    UC_ERR_WRITE_PROT, // 由于UC_MEM_WRITE_PROT冲突而停止模拟: uc_emu_start()
    UC_ERR_READ_PROT, // 由于UC_MEM_READ_PROT冲突而停止模拟: uc_emu_start()
    UC_ERR_FETCH_PROT, // 由于UC_MEM_FETCH_PROT冲突而停止模拟: uc_emu_start()
    UC_ERR_ARG,     // 提供给uc_xxx函数的无效参数
    UC_ERR_READ_UNALIGNED,  // 未对齐读取
    UC_ERR_WRITE_UNALIGNED,  // 未对齐写入
    UC_ERR_FETCH_UNALIGNED,  // 未对齐的提取
    UC_ERR_HOOK_EXIST,  // 此事件的钩子已经存在
    UC_ERR_RESOURCE,    // 资源不足: uc_emu_start()
    UC_ERR_EXCEPTION, // 未处理的CPU异常
    UC_ERR_TIMEOUT // 模拟超时
} uc_err;
```

* https://rev.ng/gitlab/angr/unicorn/raw/dca32a875e14e35403c62c82c7c15f46c5ef450c/uc.c

```c
UNICORN_EXPORT
const char *uc_strerror(uc_err code)
{
    switch(code) {
        default:
            return "Unknown error code";
        case UC_ERR_OK:
            return "OK (UC_ERR_OK)";
        case UC_ERR_NOMEM:
            return "No memory available or memory not present (UC_ERR_NOMEM)";
        case UC_ERR_ARCH:
            return "Invalid/unsupported architecture (UC_ERR_ARCH)";
        case UC_ERR_HANDLE:
            return "Invalid handle (UC_ERR_HANDLE)";
        case UC_ERR_MODE:
            return "Invalid mode (UC_ERR_MODE)";
        case UC_ERR_VERSION:
            return "Different API version between core & binding (UC_ERR_VERSION)";
        case UC_ERR_READ_UNMAPPED:
            return "Invalid memory read (UC_ERR_READ_UNMAPPED)";
        case UC_ERR_WRITE_UNMAPPED:
            return "Invalid memory write (UC_ERR_WRITE_UNMAPPED)";
        case UC_ERR_FETCH_UNMAPPED:
            return "Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)";
        case UC_ERR_HOOK:
            return "Invalid hook type (UC_ERR_HOOK)";
        case UC_ERR_INSN_INVALID:
            return "Invalid instruction (UC_ERR_INSN_INVALID)";
        case UC_ERR_MAP:
            return "Invalid memory mapping (UC_ERR_MAP)";
        case UC_ERR_WRITE_PROT:
            return "Write to write-protected memory (UC_ERR_WRITE_PROT)";
        case UC_ERR_READ_PROT:
            return "Read from non-readable memory (UC_ERR_READ_PROT)";
        case UC_ERR_FETCH_PROT:
            return "Fetch from non-executable memory (UC_ERR_FETCH_PROT)";
        case UC_ERR_ARG:
            return "Invalid argument (UC_ERR_ARG)";
        case UC_ERR_READ_UNALIGNED:
            return "Read from unaligned memory (UC_ERR_READ_UNALIGNED)";
        case UC_ERR_WRITE_UNALIGNED:
            return "Write to unaligned memory (UC_ERR_WRITE_UNALIGNED)";
        case UC_ERR_FETCH_UNALIGNED:
            return "Fetch from unaligned memory (UC_ERR_FETCH_UNALIGNED)";
        case UC_ERR_RESOURCE:
            return "Insufficient resource (UC_ERR_RESOURCE)";
    }
}
```
