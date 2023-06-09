# ERROR: Invalid memory write (UC_ERR_WRITE_UNMAPPED)

* 现象

代码：

```py
# Stack: from High address to lower address ?
STACK_ADDRESS = 8 * 1024 * 1024
STACK_SIZE = 1 * 1024 * 1024
STACK_ADDRESS_END = STACK_ADDRESS - STACK_SIZE # 7 * 1024 * 1024

STACK_SP = STACK_ADDRESS - 0x8 # ARM64: offset 0x8
...
        # map stack
        mu.mem_map(STACK_ADDRESS, STACK_SIZE)
```

报错：`ERROR: Invalid memory write (UC_ERR_WRITE_UNMAPPED)`

* 原因：此处Stack堆栈初始化有问题：Stack的map时的起始地址，有误，写成了Stack的高地址了
* 解决办法：把Stack的起始地址改为，内存的低地址（而不是高地址）
* 具体做法：

代码改为：

```py
        # mu.mem_map(STACK_ADDRESS, STACK_SIZE)
        mu.mem_map(STACK_ADDRESS_END, STACK_SIZE)
```

* 详见：
  * 【已解决】unicorn代码报错：ERROR Invalid memory write UC_ERR_WRITE_UNMAPPED

* 引申

## 给UC_ERR_WRITE_UNMAPPED单独加上hook看出错时详情

* 【已解决】unicorn模拟ARM64代码：给UC_ERR_WRITE_UNMAPPED单独加上hook看出错时详情

通过代码：

```py
def hook_unmapped(mu, access, address, length, value, context):
    pc = mu.reg_read(UC_ARM64_REG_PC)
    print("! mem unmapped: pc: 0x%X access: %d address: 0x%X length: 0x%x value: 0x%X" % (pc, access, address, length, value))
    mu.emu_stop()
    return True

# hook unmamapped memory
mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)
```

实现了一次性hook了，所有类型的unmapped未映射内存的异常

* UC_MEM_READ_UNMAPPED
* UC_MEM_WRITE_UNMAPPED
* UC_MEM_FETCH_UNMAPPED

注：另外想要分别单独去hook，应该也是可以的：

* UC_HOOK_MEM_READ_UNMAPPED
* UC_HOOK_MEM_WRITE_UNMAPPED
* UC_HOOK_MEM_FETCH_UNMAPPED

效果：此处（当出错时）可以输出错误详情：

```bash
! mem unmapped: pc: 0x10000 access: 20 address: 0x7FFF98 length: 0x8 value: 0x0
```

其含义是：

* 当前PC地址：`0x10000`
* 具体操作：`20` == `UC_MEM_WRITE_UNMAPPED`
    * 内存写入时，出现内存未映射的错误
* 具体（此处是写入）操作的地址：`0x7FFF98`
* 具体操作的长度：`8`个字节
* （此处要写入的）涉及的值：`0`
