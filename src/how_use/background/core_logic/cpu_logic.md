# CPU的核心逻辑

CPU的运行，本质上就是：从内存中读取指令，并运行指令（包括输出结果，到对应内存地址或寄存器）

## Unicorn模拟CPU的核心逻辑

此处Unicorn要模拟的是CPU的运行。所以也就（只）是，把代码放到对应的地址上，Unicorn开始运行，去对应地址：**读取指令**，（解析并）**执行指令**，即可。

而解析和运行该指令的结果，往往是，本身就是，写入计算后的结果到对应的寄存器或内存而已。

拿最基础的常见的例子来说：让CPU去计算 `2`+`3`，则底层逻辑（你暂时无需知道底层的具体的汇编指令，而只需要知道），肯定就是类似的这种步骤：

把数值`2`放到一个寄存器A中，把`3`放到另外一个寄存器B中，然后执行寄存器A加上寄存器B，然后计算的结果，保存到寄存器A中，或者另外写入到寄存器C中，甚至写入到某个内存地址，供后续读取和使用

如此，Unicorn模拟的就只是，CPU的指令的读取、解析、运行、输出结果的过程，而已。

而在指令执行期间的所需要的其他内容，比如后续会涉及到的函数参数、Stack栈、Heap堆等等，则都是为了：确保Unicorn模拟CPU的结果，和真实的代码执行的结果，要（完全）一致，才有价值，才能真正得到的希望的输出的结果。
