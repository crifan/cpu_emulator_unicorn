# 开始运行

Unicorn中，真正触发开始模拟代码，是调用函数`emu_start`。

## emu_start举例

### 之前官网例子

比如之前：[官网测试代码](../../init/run_test_code.md) 中的触发开始运行的代码就是：

```py
    # emulate machine code in infinite time
    mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))
```

### 自己的实例

以 [模拟akd函数symbol2575](../../examples/example_akd_symbol2575.md) 为例，其中的触发开始运行的代码是：

```py
        # emulate machine code in infinite time
        mu.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(ARM64_CODE_akd_symbol2575))
```

其中：

* 代码起始地址：`CODE_ADDRESS`
  * 最开始映射的代码的最初位置
* 代码结束地址：`CODE_ADDRESS + len(ARM64_CODE_akd_symbol2575)`
  * 映射的代码起始位置，加上对应代码长度后的，结束位置

-》这样可以合理的限定Unicorn要模拟运行的代码指令，而不会额外多去运行（本身是其他数据的）无用的指令
