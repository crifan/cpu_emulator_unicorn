# 优化日志输出

TODO：

* 调试的细节的优化=优化输出日志
  * 优化：让输出尽量和Xcode一样 -》方便理解汇编代码
    * 【已解决】Unicorn模拟ARM代码：优化hook打印逻辑
    * 【已解决】Unicorn模拟ARM汇编：优化hook_code调试打印指令的输出日志
  * （批量）调试输出寄存器值
    * 【已解决】Unicorn模拟ARM代码：优化log调试打印寄存器值
    * 【已解决】Unicorn中hook时当特定位置代码时查看打印寄存器的值

---

## 日志优化：通用且统一的方式打印寄存器值

自己的实际代码 [模拟akd函数symbol2575](../../../../examples/example_akd_symbol2575.md) 中的 `hook_code` 中的这部分代码：

```py

# callback for tracing instructions
def hook_code(mu, address, size, user_data):
    global ucHeap

    pc = mu.reg_read(UC_ARM64_REG_PC)
...
    # for debug
    toLogDict = {
        0x00010070: ["x25"],
        0x00010074: ["cpsr", "w9", "x9", "x25"],
        0x00010078: ["cpsr", "x9"],
...
        0x00012450: ["x27"],
    }

    # common debug

    cpsr = mu.reg_read(UC_ARM_REG_CPSR)
    sp = mu.reg_read(UC_ARM_REG_SP)

    w8 = mu.reg_read(UC_ARM64_REG_W8)
    w9 = mu.reg_read(UC_ARM64_REG_W9)
    w10 = mu.reg_read(UC_ARM64_REG_W10)
    w11 = mu.reg_read(UC_ARM64_REG_W11)
    w24 = mu.reg_read(UC_ARM64_REG_W24)
    w26 = mu.reg_read(UC_ARM64_REG_W26)

    x0 = mu.reg_read(UC_ARM64_REG_X0)
    x1 = mu.reg_read(UC_ARM64_REG_X1)
    x2 = mu.reg_read(UC_ARM64_REG_X2)
    x3 = mu.reg_read(UC_ARM64_REG_X3)
    x4 = mu.reg_read(UC_ARM64_REG_X4)
    x8 = mu.reg_read(UC_ARM64_REG_X8)
    x9 = mu.reg_read(UC_ARM64_REG_X9)
    x10 = mu.reg_read(UC_ARM64_REG_X10)
    x16 = mu.reg_read(UC_ARM64_REG_X16)
    x22 = mu.reg_read(UC_ARM64_REG_X22)
    x24 = mu.reg_read(UC_ARM64_REG_X24)
    x25 = mu.reg_read(UC_ARM64_REG_X25)
    x26 = mu.reg_read(UC_ARM64_REG_X26)
    x27 = mu.reg_read(UC_ARM64_REG_X27)

    regNameToValueDict = {
        "cpsr": cpsr,
        "sp": sp,

        "w8": w8,
        "w9": w9,
        "w10": w10,
        "w11": w11,
        "w24": w24,
        "w26": w26,

        "x0": x0,
        "x1": x1,
        "x2": x2,
        "x3": x3,
        "x4": x4,
        "x8": x8,
        "x9": x9,
        "x10": x10,
        "x16": x16,
        "x22": x22,
        "x24": x24,
        "x25": x25,
        "x26": x26,
        "x27": x27,
    }

    toLogAddressList = toLogDict.keys()
    if pc in toLogAddressList:
        toLogRegList = toLogDict[pc]
        initLogStr = "\tdebug: PC=0x%X: " % pc
        regLogStrList = []
        for eachRegName in toLogRegList:
            eachReg = regNameToValueDict[eachRegName]
            isWordReg = re.match("x\d+", eachRegName)
            logFormt = "0x%016X" if isWordReg else "0x%08X"
            curRegValueStr = logFormt % eachReg
            curRegLogStr = "%s=%s" % (eachRegName, curRegValueStr)
            regLogStrList.append(curRegLogStr)
        allRegStr = ", ".join(regLogStrList)
        wholeLogStr = initLogStr + allRegStr
        logging.info("%s", wholeLogStr)
        gNoUse = 1
```

是优化后的，为了实现调试的目的：

希望调试当某个PC值时，去打印对应的寄存器的值

而之前都是，单个的PC地址，分别写调试代码，效率很低。

所以最后统一成此处的代码：

通用的输出log，打印寄存器的代码

而想要新增一个调试时，只需要单独给`toLogDict`加一行定义，比如：

* `0x00010074: ["cpsr", "w9", "x9", "x25"],`

就可以实现：

* 当PC值是`0x00010074`时，打印这些寄存器的值：cpsr、w9、x9、x25

即可输出类似效果：

```bash
=== 0x00010074  <+116>: 29 DB A9 B8  -> ldrsw   x9, [x25, w9, sxtw #2]
    debug: PC=0x10074: cpsr=0x20000000, w9=0x00000008, x9=0x0000000000000008, x25=0x0000000000032850
```

实现我们的调试目的：查看此时特定寄存器的值，是否符合我们的预期。

注：后续如果要打印其他此处未定义的寄存器（比如`x6`等等），自己单独添加定义：`x6 = mu.reg_read(UC_ARM64_REG_X6)` 和 `regNameToValueDict`中加上`"x6": x6,` 即可。
