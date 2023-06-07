# 函数参数

很多要模拟的函数，往往是有一些参数的，所以在模拟之前，要先把参数写入对应寄存器或内存，供模拟执行用。

比如，你模拟`add(int a, int b)`的二进制代码执行的话，就要把`a`和`b`的值先写好，比如放到ARM的寄存器`x0`和`x1`中，供模拟调用。

## 实例

以 [模拟akd函数symbol2575](../../../examples/example_akd_symbol2575.md) 为例，当时此处函数要传入的参数值，分别是：

```py
#-------------------- Args --------------------
# memory address for arguments
ARGS_ADDRESS = 8 * 1024 * 1024
ARGS_SIZE =  0x10000

# init args value
ARG_routingInfoPtr = ARGS_ADDRESS
ARG_DSID = 0xfffffffffffffffe
...
        # for current arm64 ___lldb_unnamed_symbol2575$$akd =====
        mu.reg_write(UC_ARM64_REG_X0, ARG_DSID)
        mu.reg_write(UC_ARM64_REG_X1, ARG_routingInfoPtr)
```

* 第一个参数的存放位置：ARM64中的`x0`寄存器
  * 存放的值：`0xfffffffffffffffe`
    * 是所要模拟的函数，（用`Xcode`/`lldb`/`Frida`）调试出来的真实函数调用时传入的值
* 第二个参数的存放位置：ARM64中的`x1`寄存器
  * 存放的值：此处也是调试出真实函数的逻辑，此处是特殊的情况，传入一个指针，该指针用于保存最终要返回的值
    * 所以此处设置一个地址，用于保存后续的返回值
      * 而此处的地址，则选择了内存布局中，高地址部分的`8 * 1024 * 1024`=`8MB`的位置
        * 只要和别处不冲突，任何地址都可以

注：关于其中的，ARM寄存器保存参数的逻辑，属于：

* ARM的函数调用规范
  * 概述：
    * 64位的ARM中，函数参数个数不超过8个，分别保存到`X0`~`X7`中
      * 对比：32位的ARM时，函数参数个数不超过4个，分别保存到`X0`~`X3`中
    * 超出的函数参数，则放到Stack栈中
  * 详见：[调用规范 · 最流行汇编语言：ARM (crifan.org)](https://book.crifan.org/books/popular_assembly_arm/website/arm_overview/calling_convention.html)
