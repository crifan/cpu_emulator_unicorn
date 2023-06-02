# 典型的内存布局

搞懂了什么是内存布局，再来聊聊，典型的常见的内存布局。

常见的内存布局，内容很多。

用如下图（别人画的，我加了点内容），大概先解释一下，好让大家有个概念：

* （程序的）典型的内存布局
    * ![typical_memory_layout](../../../assets/img/typical_memory_layout.png)

## 内存布局举例

下面，通过具体例子，来解释，内存布局的细节含义：

### 官网示例代码中的内存布局

已我们前面[运行测试代码](https://book.crifan.org/books/cpu_emulator_unicorn/website/init/run_test_code.html)中用到的官网示例代码[unicorn/sample_arm.py](https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/sample_arm.py)来说，其中就是：

* 要模拟执行的代码code
    * 具体是什么：`ARM_CODE   = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0" # mov r0, #0x37; sub r1, r2, r3`
    * 具体放到内存什么地方=范围：`ADDRESS    = 0x10000`

意思是：

把代码`\x37\x00\xa0\xe3\x03\x10\x42\xe0`放到内存地址为`0x10000`开始的地方

就没了。是的。即没有我们提到的，函数参数，也没有Stack、Heap，特定地址写入特定值等内容

因为，此处要模拟的，只是一个代码片段，不是一个完整的函数。

此处只是官网示例的代码，用于演示运行，确保Unicorn模拟环境正常而已。所以没有用完整的函数，只是一小段代码而已。

此时的内存布局，可以理解为：

```bash
Mapped memory: Code     [0x0000000000010000 - 4GB]
```

或：

```bash
Mapped memory: Code     [0x0000000000010000 - 0x0000000000010008]
```

其中：0x0000000000010008 - 0x0000000000010000 = 8 = 上述代码的大小=字节个数

### 实际例子中的内存布局

之前自己的某个代码，经过优化后，内存布局如下：

```bash
Mapped memory: Code     [0x0000000000010000-0x0000000000410000]
Mapped memory: Libc     [0x0000000000500000-0x0000000000580000]
Mapped memory: Heap     [0x0000000000600000-0x0000000000700000]
Mapped memory: Stack    [0x0000000000700000-0x0000000000800000]
Mapped memory: Args     [0x0000000000800000-0x0000000000810000]
```

TODO：把相关，更新版本的内存布局的代码和输出结果，都贴过来，再解释，为何这么布局
