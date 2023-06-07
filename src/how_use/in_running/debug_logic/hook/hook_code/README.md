# hook代码

Unicorn开始运行后，就可以通过代码的hook，查看具体的要执行的指令情况。

## 举例

### 官网代码

比如 [官网测试代码](../../init/run_test_code.md) 中的：

```py
# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

...

        # tracing one instruction at ADDRESS with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)
```

其中的，此处的：

* hook代码的钩子参数叫：`UC_HOOK_CODE`
* hook代码的函数名：默认的，典型的，都叫做：`hook_code`
* hook_code内部的逻辑：此处只是简单的，打印出
  * address: 当前PC的地址 -> 表示代码执行到哪里了
  * size: 当前指令的字节大小

而此处只是用于演示，所以没有加更多复杂的逻辑。

下面介绍更加实例的，复杂的例子：

### 自己实例

以 [模拟akd函数symbol2575](../../../../../examples/example_akd_symbol2575.md) 为例，其中的代码的hook部分是：

```py
import re
from unicorn import *
from unicorn.arm64_const import *
from unicorn.arm_const import *

# only for debug
gNoUse = 0

#-------------------- Code --------------------

# memory address where emulation starts
CODE_ADDRESS = 0x10000
logging.info("CODE_ADDRESS=0x%X", CODE_ADDRESS)

# code size: 4MB
CODE_SIZE = 4 * 1024 * 1024
logging.info("CODE_SIZE=0x%X", CODE_SIZE)
CODE_ADDRESS_END = (CODE_ADDRESS + CODE_SIZE) # 0x00410000
logging.info("CODE_ADDRESS_END=0x%X", CODE_ADDRESS_END)

CODE_ADDRESS_REAL_END = CODE_ADDRESS + gCodeSizeReal
logging.info("CODE_ADDRESS_REAL_END=0x%X", CODE_ADDRESS_REAL_END)
# CODE_ADDRESS_REAL_LAST_LINE = CODE_ADDRESS_REAL_END - 4
# logging.info("CODE_ADDRESS_REAL_LAST_LINE=0x%X", CODE_ADDRESS_REAL_LAST_LINE)

...

# callback for tracing instructions
def hook_code(mu, address, size, user_data):
...

    if pc == 0x12138:
        spValue = mu.mem_read(sp)
        logging.info("\tspValue=0x%X", spValue)
        gNoUse = 1

    if pc == 0x1213C:
        gNoUse = 1

    if pc == 0x118B4:
        gNoUse = 1

    if pc == 0x118B8:
        gNoUse = 1

...
        # tracing one instruction with customized callback
        # mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=CODE_ADDRESS)
        # mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=CODE_ADDRESS_REAL_END)
        # mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=EMULATE_MALLOC_CODE_END)
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=CODE_ADDRESS_END)
```

代码看起来，很多，很复杂。我们拆开来一点点解释：

#### 添加代码hook

添加代码的hook，和官网示例中类似，都是：

```py
mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=CODE_ADDRESS_END)
```

其中：

* `UC_HOOK_CODE`：是要添加的hook类型，此处表示要去hook的是code代码
* `hook_code`：当执行到代码时，去调用到的（钩子）函数，即我们此处用于调试代码的函数
* `begin=CODE_ADDRESS, end=CODE_ADDRESS_END`：表示触发hook的代码的范围，此处值得说一下这个细节：
  * `begin=CODE_ADDRESS`：表示对于最初的代码的起始地址，这个没啥特殊的
  * `end=CODE_ADDRESS_END`：这个值得重点解释一下
    * 第一层优化：官网示例代码的优化
      * 对于官网示例，默认是：`end=ADDRESS`==代码起始地址 ->其最终的效果是：只触发了第一行的代码，其余代码都没触发此处的函数`hook_code`
      * 所以我们此处要优化改进为：把范围放大到，真正的我们代码的范围
      * 所以之前用了代码：`mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=CODE_ADDRESS_REAL_END)`，表示末尾处用的是`end=CODE_ADDRESS_REAL_END`
    * 第二层优化：包含其他非当前函数的代码
      * 不过此处真正的代码的范围，按理说应该是`end=CODE_ADDRESS_REAL_END`，但是此处没有采用，原因是：
        * 先贴出相关值
          ```bash
          gCodeSizeReal=9416 == 0x24C8
          CODE_ADDRESS=0x10000
          CODE_SIZE=0x400000
          CODE_ADDRESS_END=0x410000
          CODE_ADDRESS_REAL_END=0x124C8
          ```
      * 如果用`end=CODE_ADDRESS_REAL_END`==`0x124C8`，则此处，的确是对于当前要模拟的函数的代码，是正常hook，都可以触发到`hook_code`了，但是，后续对于，
      * 除了 `CODE_ADDRESS`~`CODE_ADDRESS_REAL_END` == `0x10000`~`0x124C8` 之外，
      * 在`CODE_ADDRESS`~`CODE_ADDRESS_END` == `0x10000`~`0x410000` 之内，
      * 还有些额外的代码，是此处特殊的，要模拟的第三方函数，比如`malloc`等，也想要触发调试函数`hook_code`
      * 如果设置了`end=CODE_ADDRESS_REAL_END`，则函数本身之外的其他额外代码，就无法触发`hook_code`，导致无法调试内部细节了

#### 其他细节

`hook_code`中其他部分的代码，也很多，分别实现了各自的目的和效果，包括：

* 日志优化：打印当前正在执行的指令
  * 详见：[优化日志输出](../../../../../how_use/in_running/debug_logic/log/optimize_log.md)
* 借助Capstone查看当前真正执行的指令
  * [Capstone](../../../../../how_use/in_running/debug_logic/print_instruction/capstone.md)

其他一些细节，还有：

* 当特定PC时，查看读取内存的值
  ```py
      if pc == 0x12138:
          spValue = mu.mem_read(sp)
          logging.info("\tspValue=0x%X", spValue)
  ```
* 当特定PC时，暂停运行，用于辅助调试，查看其他的值
  ```py
      if pc == 0x1213C:
          gNoUse = 1
  ```
