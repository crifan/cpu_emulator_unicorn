# 相关数据

其他一些特殊情况中，要给特定内存地址写入特定地址，供后续代码模拟时调用。

一般普通的函数模拟，往往无需此过程。

## 实例

此处以后续的 [模拟akd函数symbol2575 · CPU模拟利器：Unicorn](../../../examples/example_akd_symbol2575.md) 为例，来解释特殊的情况：

由于函数`___lldb_unnamed_symbol2575$$akd`做了特殊的反调试处理：代码中很多`BR`间接跳转，导致需要写入特定内存地址中，特定的值，供后续代码运行时读取，才能正常跳转到对应的行的代码，继续正确运行。

此时就涉及到，要向特定内存地址，写入特定的值。

* 要向什么地址？写入具体什么值？

比如某次调试报错时：

```bash
=== 0x00011130 <+4400>: 36 D9 68 F8  -> ldr     x22, [x9, w8, sxtw #3]
 << Memory READ at 0x69C18, size=8, rawValueLittleEndian=0x0000000000000000, pc=0x11130
```

涉及到要：

* 要写入的地址，就是：`0x69C18`

而要写入的值：
则需要（用工具`Xcode`/`lldb`/`Frida`去）调试去真正的函数执行期间的值，此处调试出是：

* 要写入的值：`0x0000000000078dfa`

然后就可以：

* 向要写入的地址：`0x69C18`
  * 写入具体的值：`0x0000000000078dfa`
    * 且占用地址空间大小是：8字节=64bit的值

如此，即可去调用自己优化后的代码：

向特定内存地址，写入对应字节大小的特定的值

```py

uc = None

def writeMemory(memAddr, newValue, byteLen):
    """
        for ARM64 little endian, write new value into memory address
        memAddr: memory address to write
        newValue: value to write
        byteLen: 4 / 8
    """
    global uc

    valueFormat = "0x%016X" if byteLen == 8 else "0x%08X"
    if isinstance(newValue, bytes):
        logging.info("writeMemory: memAddr=0x%X, newValue=0x%s, byteLen=%d", memAddr, newValue.hex(), byteLen)
        newValueBytes = newValue
    else:
        valueStr = valueFormat % newValue
        logging.info("writeMemory: memAddr=0x%X, newValue=%s, byteLen=%d", memAddr, valueStr, byteLen)
        newValueBytes = newValue.to_bytes(byteLen, "little")
    uc.mem_write(memAddr, newValueBytes)
    logging.info(" >> has write newValueBytes=%s to address=0x%X", newValueBytes, memAddr)

    # # for debug: verify write is OK or not
    # readoutValue = uc.mem_read(memAddr, byteLen)
    # logging.info("for address 0x%X, readoutValue hex=0x%s", memAddr, readoutValue.hex()))
    # # logging.info("readoutValue hexlify=%b", binascii.hexlify(readoutValue))
    # readoutValueLong = int.from_bytes(readoutValue, "little", signed=False)
    # logging.info("readoutValueLong=0x%x", readoutValueLong)
    # # if readoutValue == newValue:
    # if readoutValueLong == newValue:
    #     logging.info("=== Write and read back OK")
    # else:
    #     logging.info("!!! Write and read back Failed")


def emulate_akd_arm64_symbol2575():
    global uc, ucHeap

    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM + UC_MODE_LITTLE_ENDIAN)
    uc = mu

    ...

    writeMemory(0x69C18, 0x0000000000078dfa, 8) # <+4400>: 36 D9 68 F8  -> ldr     x22, [x9, w8, sxtw #3]
```

即可实现，模拟运行时，读取出正确的写入的raw value：

```bash
=== 0x00011130 <+4400>: 36 D9 68 F8  -> ldr     x22, [x9, w8, sxtw #3]
 << Memory READ at 0x69C18, size=8, rawValueLittleEndian=0xfa8d070000000000, pc=0x11130
```

* 注：此处从内存中读取出来的值是`0xfa8d070000000000`，之所以不是（以为的，原先写入的值）`0x0000000000078dfa`，是因为：此处是ARM64，是little endian=小端，所以内存中原始的值，就是按照`fa 8d 07 00 00 00 00 00`存放的。
  * 关于endian的知识，具体详见之前章节：[字节序endian](../../../how_use/background/endian/README.md)

从而使得后续代码逻辑，按照预期的逻辑继续去执行了。
