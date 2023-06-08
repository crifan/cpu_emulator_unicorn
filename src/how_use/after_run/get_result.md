# 获取结果

只有当，实现了前面的

[Unicorn停止运行](../../how_use/after_run/stop.md)

后，在`emu_start`的之后的代码，才会运行到。

然后这部分代码，也往往就是：去获取程序（函数）运行的结果，得到最终的返回值。

## 举例

### 自己的实例

以 [模拟akd函数symbol2575](../../../../examples/example_akd_symbol2575.md) 为例，就是：

```py
        # emulate machine code in infinite time
        mu.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(ARM64_CODE_akd_symbol2575))

        # now print out some registers
        logging.info("---------- Emulation done. Below is the CPU context ----------")

        retVal = mu.reg_read(UC_ARM64_REG_X0)
        # routingInfo = mu.mem_read(ARG_routingInfoPtr)
        # logging.info(">>> retVal=0x%x, routingInfo=%d", retVal, routingInfo))
        logging.info(">>> retVal=0x%x", retVal)

        routingInfoEnd = mu.mem_read(ARG_routingInfoPtr, 8)
        logging.info(">>> routingInfoEnd hex=0x%s", routingInfoEnd.hex())
        routingInfoEndLong = int.from_bytes(routingInfoEnd, "little", signed=False)
        logging.info(">>> routingInfoEndLong=%d", routingInfoEndLong)
```

中的：

```py
        # now print out some registers
        logging.info("---------- Emulation done. Below is the CPU context ----------")

        retVal = mu.reg_read(UC_ARM64_REG_X0)
        # routingInfo = mu.mem_read(ARG_routingInfoPtr)
        # logging.info(">>> retVal=0x%x, routingInfo=%d", retVal, routingInfo))
        logging.info(">>> retVal=0x%x", retVal)

        routingInfoEnd = mu.mem_read(ARG_routingInfoPtr, 8)
        logging.info(">>> routingInfoEnd hex=0x%s", routingInfoEnd.hex())
        routingInfoEndLong = int.from_bytes(routingInfoEnd, "little", signed=False)
        logging.info(">>> routingInfoEndLong=%d", routingInfoEndLong)
```

也就是我们希望的，此处获取对应的返回值的代码逻辑。

而此处特定的要模拟的函数`arm64`的`___lldb_unnamed_symbol2575$$akd`函数的返回值，是通过代码`mu.mem_read(ARG_routingInfoPtr, 8)`，从传入的指针`ARG_routingInfoPtr`中获取返回值

而函数本身的返回值，则是普通的逻辑，通过代码`mu.reg_read(UC_ARM64_REG_X0)`去读取ARM中的寄存器`x0`的值

如此，即可获取到我们希望的返回的值了。
