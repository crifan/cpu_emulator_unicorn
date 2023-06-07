# Stack栈

如果函数A内部调用了其他函数，比如B函数，C函数等，则往往又涉及到函数上下文的切换，底层具体实现就是涉及到Stack栈，在调用之前和之后，会操作Stack，保存`PC`、`LR`、多个相关寄存器等等，所以，往往在模拟函数运行之前，也要先去设置好Stack。

* Stack栈
  * 本身特性
    * 本质上：是一个线性表
      * 操作栈顶(top)，进行插入或删除
        * 另一端称为栈底bottom
      * 操作原理：后进先出=LIFO=Last In First Out
  * 生成方向=增长方向
    * 理论上支持
      * Full Descending=满递减=由高地址到低地址
      * 空递增？ = 由低地址到高地址
    * 但是基本上都是用
      * Full Descending=满递减=由高地址到低地址

## ARM中的Stack栈

ARM中的Stack栈，默认情况下，都是：由高地址到低地址。

## 举例

### 自己的实例

以 [模拟akd函数symbol2575](../../../examples/example_akd_symbol2575.md) 为例，其中的Stack栈相关的代码是：

```py
#-------------------- Stack --------------------
# Stack: from High address to lower address ?
STACK_ADDRESS = 7 * 1024 * 1024
STACK_SIZE = 1 * 1024 * 1024
STACK_HALF_SIZE = (int)(STACK_SIZE / 2)

# STACK_ADDRESS_END = STACK_ADDRESS - STACK_SIZE # 8 * 1024 * 1024
# STACK_SP = STACK_ADDRESS - 0x8 # ARM64: offset 0x8

# STACK_TOP = STACK_ADDRESS + STACK_SIZE
STACK_TOP = STACK_ADDRESS + STACK_HALF_SIZE
STACK_SP = STACK_TOP

...

        # map stack
        mu.mem_map(STACK_ADDRESS, STACK_SIZE)
        logging.info("Mapped memory: Stack\t[0x%08X-0x%08X]", STACK_ADDRESS, STACK_ADDRESS + STACK_SIZE)
...

        # initialize stack
        # mu.reg_write(UC_ARM64_REG_SP, STACK_ADDRESS)
        mu.reg_write(UC_ARM64_REG_SP, STACK_SP)
```

其中输出的内存布局中的Stack部分就是：

```bash
Mapped memory: Stack   [0x00700000-0x00800000]
```

其中的：

`mu.reg_write(UC_ARM64_REG_SP, STACK_SP)`

就是真正的Stack初始化的操作，即：设置SP指针，为Stack栈的地址

此处由于是`由高地址到低地址`的Stack，所以最初的`SP`的值是`STACK_TOP`=Stack的最高地址
