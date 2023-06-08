# 停止运行

对于Unicorn来说，就是模拟CPU运行，模拟去读取指令和运行指令而已。

所以，换句话说，如果你的给code代码的地址空间写入了代码后，如果没有额外的跳转等复杂逻辑，则：

* **Unicorn会一直运行下去**

如果没有合适的触发时机，去让其停下来，那就变成了死循环，永远不结束了。

而我们的目标是：模拟代码，尤其是函数的逻辑，希望代码运行完毕，输出结果的。

所以，此处往往选择一个合适的时机去触发其让Unicorn停下来。

这个时机，一般都是：`ret`指令，即，当发现正在运行的指令是`ret`指令，则就会调用`emu_stop`去停下来。

## 举例

### 自己的实例

以 [模拟akd函数symbol2575](../../../examples/example_akd_symbol2575.md) 为例，其中的Stop的判断逻辑是：

```py
import re

#-------------------- Code --------------------

# memory address where emulation starts
CODE_ADDRESS = 0x10000

# code size: 4MB
CODE_SIZE = 4 * 1024 * 1024
CODE_ADDRESS_END = (CODE_ADDRESS + CODE_SIZE) # 0x00410000

CODE_ADDRESS_REAL_END = CODE_ADDRESS + gCodeSizeReal

def shouldStopEmulate(curPc, decodedInsn):
    isShouldStop = False
    # isRetInsn = decodedInsn.mnemonic == "ret"
    isRetInsn = re.match("^ret", decodedInsn.mnemonic) # support: ret/retaa/retab/...
    if isRetInsn:
        isPcInsideMainCode = (curPc >= CODE_ADDRESS) and (curPc < CODE_ADDRESS_REAL_END)
        isShouldStop = isRetInsn and isPcInsideMainCode

    return isShouldStop

# callback for tracing instructions
def hook_code(mu, address, size, user_data):
...
    lineCount = int(size / BYTES_PER_LINE)
    for curLineIdx in range(lineCount):
...
        decodedInsnGenerator = cs.disasm(opcodeBytes, address)
        for eachDecodedInsn in decodedInsnGenerator:
            eachInstructionName = eachDecodedInsn.mnemonic

            if shouldStopEmulate(pc, eachDecodedInsn):
                mu.emu_stop()
                logging.info("Emulate done!")

            gNoUse = 1

...

        mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=CODE_ADDRESS_END)
```

其中的主要逻辑是：

在`hook_code`中，借助`Capstone`反编译出当前指令，其中`mnemonic`就是指令名称，当发现是`ret`指令时

注：对于arm64e来说，还有更多的PAC相关ret指令：`retaa`、`retab`等，所以此处用`re`正则去判断指令名称是否匹配，而不是直接判断和`ret`是否相等。

就去调用`emu_stop()`去停止Unicorn的继续运行。

此处有个细节：

此处判断代码结束的条件是：`isShouldStop = isRetInsn and isPcInsideMainCode`

除了：

* `isRetInsn`：判断代码是否是ret指令

还有个：

* `isPcInsideMainCode`：判断代码是否在主体的main的，要模拟运行的函数代码内部，才返回
  * 目的是：防止，触发了别处的特殊代码中的ret，也返回了。
    * 比如别处特殊的代码，就包括，后续的 [调用其他子函数](../../summary_note/call_other_func/README.md) 中，在模拟malloc等函数时，其内部也是有`ret`指令的，此时只是子函数的返回，而不应该是，整个Unicorn的stop
  * 所以要排除这类特殊情况，只是当代码地址在main函数=要模拟的函数内部时，其ret才是真正要返回，要Unicorn停止的意思。
