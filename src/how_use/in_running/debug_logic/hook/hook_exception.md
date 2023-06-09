# hook异常

此处的hook异常，主要指的是，当发生一些异常情况时的hook

其中对于内存memory来说，常见的异常就是：未映射（但却去读取或写入对应的）内存地址

对应的hook的类型是：

* `UC_HOOK_MEM_READ_UNMAPPED`
  * 内存地址未映射，但却去：读取内存
* `UC_HOOK_MEM_WRITE_UNMAPPED`
  * 内存地址未映射，但却去：写入内存
* `UC_HOOK_MEM_FETCH_UNMAPPED`
  * 内存地址未映射，但却去：内存取指
    * 取指=读取指令=（Unicorn模拟CPU去）从对应内存地址，读取指令（供后续模拟解析和运行）

以及其他方面的一些异常还有：

* `UC_HOOK_INSN_INVALID`
  * 非法指令

## 组合值

而其中具体使用的时候，更常见的用法是：

* 用组合出来的值
  * `UC_HOOK_MEM_UNMAPPED`
    * = `UC_HOOK_MEM_READ_UNMAPPED` + `UC_HOOK_MEM_WRITE_UNMAPPED` + `UC_HOOK_MEM_FETCH_UNMAPPED`
  * `UC_HOOK_MEM_PROT`
    * = `UC_HOOK_MEM_READ_PROT` + `UC_HOOK_MEM_WRITE_PROT` + `UC_HOOK_MEM_FETCH_PROT`
  * `UC_HOOK_MEM_READ_INVALID`
    * = `UC_HOOK_MEM_READ_PROT` + `UC_HOOK_MEM_READ_UNMAPPED`
  * `UC_HOOK_MEM_WRITE_INVALID`
    * = `UC_HOOK_MEM_WRITE_PROT` + `UC_HOOK_MEM_WRITE_UNMAPPED`
  * `UC_HOOK_MEM_FETCH_INVALID`
    * = `UC_HOOK_MEM_FETCH_PROT` + `UC_HOOK_MEM_FETCH_UNMAPPED`
  * `UC_HOOK_MEM_INVALID`
    * = `UC_HOOK_MEM_UNMAPPED` + `UC_HOOK_MEM_PROT`
  * `UC_HOOK_MEM_VALID`
    * = `UC_HOOK_MEM_READ` + `UC_HOOK_MEM_WRITE` + `UC_HOOK_MEM_FETCH`

对应的组合的值，官网源码中可以找到定义[unicorn.h](https://github.com/unicorn-engine/unicorn/blob/master/include/unicorn/unicorn.h)：

```c
// Hook type for all events of unmapped memory access
#define UC_HOOK_MEM_UNMAPPED                                                   \
    (UC_HOOK_MEM_READ_UNMAPPED + UC_HOOK_MEM_WRITE_UNMAPPED +                  \
     UC_HOOK_MEM_FETCH_UNMAPPED)
// Hook type for all events of illegal protected memory access
#define UC_HOOK_MEM_PROT                                                       \
    (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_FETCH_PROT)
// Hook type for all events of illegal read memory access
#define UC_HOOK_MEM_READ_INVALID                                               \
    (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_READ_UNMAPPED)
// Hook type for all events of illegal write memory access
#define UC_HOOK_MEM_WRITE_INVALID                                              \
    (UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_WRITE_UNMAPPED)
// Hook type for all events of illegal fetch memory access
#define UC_HOOK_MEM_FETCH_INVALID                                              \
    (UC_HOOK_MEM_FETCH_PROT + UC_HOOK_MEM_FETCH_UNMAPPED)
// Hook type for all events of illegal memory access
#define UC_HOOK_MEM_INVALID (UC_HOOK_MEM_UNMAPPED + UC_HOOK_MEM_PROT)
// Hook type for all events of valid memory access
// NOTE: UC_HOOK_MEM_READ is triggered before UC_HOOK_MEM_READ_PROT and
// UC_HOOK_MEM_READ_UNMAPPED, so
//       this hook may technically trigger on some invalid reads.
#define UC_HOOK_MEM_VALID                                                      \
    (UC_HOOK_MEM_READ + UC_HOOK_MEM_WRITE + UC_HOOK_MEM_FETCH)
```

## 用法举例

以 [模拟akd函数symbol2575](../../../examples/example_akd_symbol2575.md) 为例，其中的：

```py

def hook_unmapped(mu, access, address, size, value, context):
    pc = mu.reg_read(UC_ARM64_REG_PC)
    logging.info("!!! Memory UNMAPPED at 0x%X size=0x%x, access(r/w)=%d, value=0x%X, PC=0x%X", address, size, access, value, pc)
    mu.emu_stop()
    return True

def hook_mem_write(uc, access, address, size, value, user_data):
...
    pc = uc.reg_read(UC_ARM64_REG_PC)
    logging.info(" >> Memory WRITE at 0x%X, size=%u, value=0x%X, PC=0x%X", address, size, value, pc)
    # logging.info(" >> Memory WRITE at 0x%X, size=%u, value=0x%s, PC=0x%X", address, size, value.to_bytes(8, "little").hex(), pc))
    gNoUse = 1

def hook_mem_read(uc, access, address, size, value, user_data):
    if address == ARG_routingInfoPtr:
        logging.info("read ARG_routingInfoPtr")
        gNoUse = 1

    pc = uc.reg_read(UC_ARM64_REG_PC)
    data = uc.mem_read(address, size)
    logging.info(" << Memory READ at 0x%X, size=%u, rawValueLittleEndian=0x%s, pc=0x%X", address, size, data.hex(), pc)
    gNoUse = 1

    dataLong = int.from_bytes(data, "little", signed=False)
    if dataLong == 0:
        logging.info(" !! Memory read out 0 -> possbile abnormal -> need attention")
        gNoUse = 1

# def hook_mem_fetch(uc, access, address, size, value, user_data):
#     pc = uc.reg_read(UC_ARM64_REG_PC)
#     logging.info(" >> Memory FETCH at 0x%X, size= %u, value= 0x%X, PC= 0x%X", address, size, value, pc))
#     gNoUse = 1

...
        # hook unmamapped memory
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

        # hook memory read and write
        mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
        mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
        # mu.hook_add(UC_HOOK_MEM_FETCH, hook_mem_fetch)
```

就是对应的：

* `UC_HOOK_MEM_READ`：读取内存
* `UC_HOOK_MEM_WRITE`：写入内存
* `UC_HOOK_MEM_UNMAPPED`：内存发生未映射的错误异常

的hook的用法。

其中`hook_mem_read`中的：

```py
    dataLong = int.from_bytes(data, "little", signed=False)
    if dataLong == 0:
        logging.info(" !! Memory read out 0 -> possbile abnormal -> need attention")
        gNoUse = 1
```

的含义是：代码模拟期间，发生很多次：

* 内存读取出来的值是0

具体的log类似于：

```bash
=== 0x000113E4 <+5092>: E9 6F 40 B9  -> ldr     w9, [sp, #0x6c]
 << Memory READ at 0x77FF7C, size=4, rawValueLittleEndian=0x00000000, pc=0x113E4
```

而，从某个内存地址读取出来的值是0，往往又是：后续其他代码逻辑报错的原因

因为正常情况下，从内存读取出来的值，往往都不是0

所以，由此加了个log日志，变成：

```bash
=== 0x000113E4 <+5092>: E9 6F 40 B9  -> ldr     w9, [sp, #0x6c]
 << Memory READ at 0x77FF7C, size=4, rawValueLittleEndian=0x00000000, pc=0x113E4
 !! Memory read out 0 -> possbile abnormal -> need attention
```

用于提示，此时需要注意，方便后续调试时，找到最近的一处的，可能出错的地方 = 当内存读取值是0的地方。
