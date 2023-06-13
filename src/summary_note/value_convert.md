# 数值转换

在Unicorn模拟期间，往往涉及到，向内存中写入对应的值，以及，从内存中读取出特定的值。

在此期间，往往会涉及到：

* 把对应的数据（int、long等）转换成原始的值，再写入内存
* 把从内存中读取出的raw原始数据，转换成对应的数据类型（int、long等）

此处整理相关的心得：

## 把数据写入内存

已整理出相关函数，详见：

[模拟akd函数symbol2575](../../../examples/example_akd_symbol2575.md) 

中的：`writeMemory`

```py
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
```

* 说明

Unicorn模拟期间，常需要，给特定内存地址写入特定的值，用于模拟函数代码的真实的值。

此时，就用调用此函数`writeMemory`，给特定内存地址，写入对应的值了。

其中被注释的掉的部分， 恢复后是：

```py
    # for debug: verify write is OK or not
    readoutValue = uc.mem_read(memAddr, byteLen)
    logging.info("for address 0x%X, readoutValue hex=0x%s", memAddr, readoutValue.hex()))
    # logging.info("readoutValue hexlify=%b", binascii.hexlify(readoutValue))
    readoutValueLong = int.from_bytes(readoutValue, "little", signed=False)
    logging.info("readoutValueLong=0x%x", readoutValueLong)
    # if readoutValue == newValue:
    if readoutValueLong == newValue:
        logging.info("=== Write and read back OK")
    else:
        logging.info("!!! Write and read back Failed")
```

可以去：用于写入后，立刻读取出来，验证和写入的值是否一致，验证写入的操作，是否正确。

* 用法举例

```py
  writeMemory(0x69C18, 0x0000000000078dfa, 8) # <+4400>: 36 D9 68 F8  -> ldr     x22, [x9, w8, sxtw #3]
```

就是之前调试了真实的函数后，去给：

* 内存地址：`0x69C18`
  * 注：对应着实际调试期间的 `0x69C18` = `0x59C18` + `0x10000` 中的`0x59C18`的相对地址，其中`0x10000`是代码的基地址
* 写入对应的值：`0x0000000000078dfa`
* 字节大小=占用地址空间大小（字节数）：`8`个字节

## 从内存中读取数据

已整理出相关函数，详见：

[模拟akd函数symbol2575](../../../examples/example_akd_symbol2575.md) 

中的：`readMemory`

```py
def readMemory(memAddr, byteNum, endian="little", signed=False):
    """read out value from memory"""
    global uc
    readoutRawValue = uc.mem_read(memAddr, byteNum)
    logging.info(" >> readoutRawValue hex=0x%s", readoutRawValue.hex())
    readoutValue = int.from_bytes(readoutRawValue, endian, signed=signed)
    logging.info(" >> readoutValue=0x%016X", readoutValue)
    return readoutValue
```

* 说明

`Unicorn`中的`mem_read`函数读取出来的，是raw value=原始的值=原始的二进制数据

而往往我们之前保存进去的是，对应的int、long等类型的数据

此时，将raw value转换成int、long等数值时，就可以用此处的`readMemory`

* 用法举例

比如之前写入了对应的值：

```py
  writeMemory(0x32850, 0x00000094, 4)             # <+236>: 29 DB A9 B8  -> ldrsw   x9, [x25, w9, sxtw #2]
```

然后就可以去用readMemory去读取出对应的值：

```py
  readMemory(0x32850, 4)
```

用于验证之前写入的值，是否正确。
