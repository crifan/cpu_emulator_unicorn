# 调用其他子函数

Unicorn模拟某个函数运行期间，被模拟的函数A，往往会调用到其他函数B，函数C等等。此时，就涉及到：

Unicorn中，模拟调用`子函数`=`其他函数`。

## 模拟调用子函数的思路和框架

Unicorn中模拟ARM64代码，去模拟A函数：

遇到`blr x8`跳转到B函数，去模拟B函数，搭建一个空的框架，供B函数使用。

此处总体思路是：

* 弄出一个框架函数
  * 暂时只有一个ARM64的`little endian`的`ret`指令
    * 对应值，可以自己手动推算或借助在线网站
      * [Online ARM to HEX Converter (armconverter.com)](https://armconverter.com/?code=ret)
    * 帮忙算出来是：`0x C0 03 5F D6`
      * 对应写成Python二进制就是：`b"\xC0\x03\x5F\xD6"`
    * 注：当然，你可以根据自己需要，去加上更多行的代码
      * ARM汇编转opcode二进制，可以参考上述在线网站去生成
  * 而后续会去给该函数的代码加上`hook_code`
    * 加上相关的逻辑：
      * 获取传入的参数：比如ARM中的**第一个参数**`x0`的值
      * 加上对应处理逻辑：比如此处只是用于演示demo用：给`x0`加上`100`
        * 后续可以根据需要，变成自己的处理逻辑
          * 比如想办法用Python代码实现`malloc`的效果，返回真正的新申请的内存的地址
      * 用`x0`返回值：把新的值写入`x0`寄存器
* 再去把上述的框架函数的opcode，写入对应的内存地址
  * 作为ARM64的代码，用于后续跳转后执行
* 然后去给对应`blr x8`对应的地址，去写入对应的上述新的框架函数的地址，即可

## 举例：模拟调用malloc

此处，用于框架代码，后续用于模拟malloc的函数，暂且叫做 emulateMalloc 相关的实际代码是：

```py
uc = None

#-------------------- emulate malloc --------------------
emulateMallocOpcode = b"\xC0\x03\x5F\xD6" # current only ret=0xC0035FD6
gEmulateMallocCodeSize = len(emulateMallocOpcode)
EMULATE_MALLOC_CODE_START = 2 * 1024 * 1024
EMULATE_MALLOC_CODE_END = EMULATE_MALLOC_CODE_START + gEmulateMallocCodeSize

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
        print("writeMemory: memAddr=0x%X, newValue=0x%s, byteLen=%d" % (memAddr, newValue.hex(), byteLen))
        newValueBytes = newValue
    else:
        valueStr = valueFormat % newValue
        print("writeMemory: memAddr=0x%X, newValue=%s, byteLen=%d" % (memAddr, valueStr, byteLen))
        newValueBytes = newValue.to_bytes(byteLen, "little")
    uc.mem_write(memAddr, newValueBytes)
    print(" >> has write newValueBytes=%s to address=0x%X" % (newValueBytes, memAddr))


# callback for tracing instructions
def hook_code(mu, address, size, user_data):
    pc = mu.reg_read(UC_ARM64_REG_PC)
...
    # common debug
...
    x0 = mu.reg_read(UC_ARM64_REG_X0)
    x1 = mu.reg_read(UC_ARM64_REG_X1)
...

    # for emulateMalloc
    if pc == 0x00200000:
        # emulate pass in parameter(s)/argument(s)
        curX0 = mu.reg_read(UC_ARM64_REG_X0)
        # emulate do something: here is add 100
        retValue = curX0 + 100
        # emulate return value
        mu.reg_write(UC_ARM64_REG_X0, retValue)
        print("input x0=0x%x, output ret: 0x%x" % (curX0, retValue))

# Emulate arm function running
def emulate_akd_arm64e_symbol2540():
    global uc
    print("Emulate arm64 sub_1000A0460 == ___lldb_unnamed_symbol2575$$akd function running")
    try:
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM + UC_MODE_LITTLE_ENDIAN)
...
        # for emuleateMalloc
        writeMemory(EMULATE_MALLOC_CODE_START, emulateMallocOpcode, gEmulateMallocCodeSize)
        writeMemory(0x69BD8, EMULATE_MALLOC_CODE_START + 2, 8)
```

即可输出对应期望的内容：

```bash
=== 0x000100C8  <+200>: E8 33 00 F9  -> str     x8, [sp, #0x60]
 >> Memory WRITE at 0x77FF70, size=8, value=0x200000, PC=0x100C8
=== 0x000100CC  <+204>: 00 01 3F D6  -> blr     x8
>>> Tracing basic block at 0x200000, block size = 0x4
=== 0x00200000 <+2031616>: C0 03 5F D6  -> ret
    debug: PC=0x200000: cpsr=0x20000000, x0=0x0000000000000018, x1=0x0000000000410000
input x0=0x18, output ret: 0x7c
>>> Tracing basic block at 0x100d0, block size = 0x50
=== 0x000100D0  <+208>: 08 00 80 52  -> movz    w8, #0
    debug: PC=0x100D0: x0=0x000000000000007C, x1=0x0000000000410000
=== 0x000100D4  <+212>: 1F 00 00 F1  -> cmp     x0, #0
```

输出的log对应的逻辑解释：

即从原先的代码：

```asm
<+204>: 00 01 3F D6  -> blr     x8
```

跳转到了，我此处的`emulateMalloc`的函数的地址`0x00200000`，去运行了

此函数中，暂时只有一行的ARM64代码：

```bash
0x00200000 <+2031616>: C0 03 5F D6  -> ret
```

其中传入的参数：

* `x0`=`0x0000000000000018`

经过自己hook_code中的处理后：

* 返回值=`x0`=`0x7c`

然后代码返回原先代码的下一行：

```asm
0x000100D0  <+208>: 08 00 80 52  -> movz    w8, #0
```

继续去运行，且对应的返回值：

* `x0`=`0x000000000000007C`

是符合预期的，是我们故意返回的值。

如此，模拟一个B（的框架）函数，供A函数去调用和跳转后再返回，就完成了。

* 附录

完整代码详见：

[模拟akd函数symbol2575](../../../../../examples/example_akd_symbol2575.md)

其中就有真正的完整的模拟malloc的代码，供参考。
