# hook内存

在Unicorn模拟代码期间，常会涉及到调试查看内存的值，此时就涉及到：内存的hook

Unicorn对于内存的操作的hook，支持：

* `UC_HOOK_MEM_READ`
* `UC_HOOK_MEM_WRITE`

常见的用法有：

以 [模拟akd函数symbol2575](../../../examples/example_akd_symbol2575.md) 为例，其中相关代码是：

```py
def hook_mem_write(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    print(">>> Memory WRITE at 0x%X, size= %u, value= 0x%X, PC= 0x%X" % (address, size, value, pc))
    gNoUse = 1

def hook_mem_read(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    data = uc.mem_read(address, size)
    print("<<< Memory READ at 0x%X, size= %u, value= 0x%s, pc= 0x%X" % (address, size, data.hex(), pc))
    gNoUse = 1

...
        # hook memory read and write
        mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
        mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
```

输出效果：

```bash
# [0x1001c] size=0x4, opcode=FD 7B 0D A9 
  [0x1001c]     stp     x29, x30, [sp, #0xd0]
>>> Memory WRITE at 0x7FFFF0, size= 8, value= 0x0, PC= 0x1001C
>>> Memory WRITE at 0x7FFFF8, size= 8, value= 0x300000, PC= 0x1001C
。。。
# [0x10028] size=0x4, opcode=68 8F 2F 58 
  [0x10028]     ldr     x8, #0x6f214
<<< Memory READ at 0x6F214, size= 8, value= 0x0000000000000000, pc= 0x10028
```

额外解释：

对于其中的`stp`指令触发了多个（2个）的Memeory Write，背后的逻辑是：

`stp`是ARM汇编指令，其中p是pair，一次性操作2个地址，即先后把2个值，分别写入对应的地址，所以才会触发2次的`UC_HOOK_MEM_WRITE`，输出2个log。
