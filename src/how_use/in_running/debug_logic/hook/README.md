# hook

Unicorn模拟期间，常需要去搞懂底层正在发生的细节，查看对应的寄存器、内存的值等等，此时，就可以用到Unicorn所提供的机制：hook。

其中比较常用的一些hook是：

* hook代码
  * hook特定指令
* hook内存
* hook异常
* hook其他

下面分别解释如何使用和具体效果。

## Unicorn支持的全部的hook种类

关于Unicorn支持的hook的全部种类是：

* `UC_HOOK_INTR`
* `UC_HOOK_INSN`
* `UC_HOOK_CODE`
* `UC_HOOK_BLOCK`
* `UC_HOOK_MEM_READ_UNMAPPED`
* `UC_HOOK_MEM_WRITE_UNMAPPED`
* `UC_HOOK_MEM_FETCH_UNMAPPED`
* `UC_HOOK_MEM_READ_PROT`
* `UC_HOOK_MEM_WRITE_PROT`
* `UC_HOOK_MEM_FETCH_PROT`
* `UC_HOOK_MEM_READ`
* `UC_HOOK_MEM_WRITE`
* `UC_HOOK_MEM_FETCH`
* `UC_HOOK_MEM_READ_AFTER`
* `UC_HOOK_INSN_INVALID`
* `UC_HOOK_EDGE_GENERATED`
* `UC_HOOK_TCG_OPCODE`

可以从官网源码[unicorn.h](https://github.com/unicorn-engine/unicorn/blob/master/include/unicorn/unicorn.h)中找到定义：

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
