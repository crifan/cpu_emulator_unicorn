# Heap堆

如果要模拟的函数，内部涉及到申请内存malloc等，则往往也要设置对应的headp堆，用于模拟内存管理提供动态申请和释放内存用。

## 举例

### 自己的实例

以 [模拟akd函数symbol2575](../../../examples/example_akd_symbol2575.md) 为例，其中关于Heap堆的代码是：

```py
from libs.UnicornSimpleHeap import UnicornSimpleHeap

ucHeap = None

#-------------------- Heap --------------------

HEAP_ADDRESS = 6 * 1024 * 1024
HEAP_SIZE = 1 * 1024 * 1024

HEAP_ADDRESS_END = HEAP_ADDRESS + HEAP_SIZE
HEAP_ADDRESS_LAST_BYTE = HEAP_ADDRESS_END - 1

...

# callback for tracing instructions
def hook_code(mu, address, size, user_data):
    global ucHeap
...
    # for emulateMalloc
    # if pc == 0x00200000:
    if pc == EMULATE_MALLOC_CODE_START:
        mallocSize = mu.reg_read(UC_ARM64_REG_X0)
        newAddrPtr = ucHeap.malloc(mallocSize)
        mu.reg_write(UC_ARM64_REG_X0, newAddrPtr)
        logging.info("\temulateMalloc: input x0=0x%x, output ret: 0x%x", mallocSize, newAddrPtr)
        gNoUse = 1

...
        # map heap
        mu.mem_map(HEAP_ADDRESS, HEAP_SIZE)
        logging.info("Mapped memory: Heap\t[0x%08X-0x%08X]", HEAP_ADDRESS, HEAP_ADDRESS + HEAP_SIZE)
...
        # init Heap malloc emulation
        ucHeap = UnicornSimpleHeap(uc, HEAP_ADDRESS, HEAP_ADDRESS_LAST_BYTE, debug_print=True)
```

其中此处是：

要模拟的代码内部，涉及到malloc去分配内容，所以借鉴了别人的代码，更新后，独立出单独的库`UnicornSimpleHeap`，然后用于此处模拟调用malloc函数。

而关于Unicorn模拟代码中，调用子函数=调用其他函数的部分，详见：

[调用其他子函数](../../../summary_note/call_other_func/README.md)
