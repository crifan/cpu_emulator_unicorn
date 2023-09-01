# 查看当前指令

Unicorn模拟CPU去执行（函数）代码指令时，由于调试需要，往往需要查看（搞清楚）当前正在执行的指令是什么。

而关于Unicorn当前正在执行的指令是什么：

* Unicorn内部肯定是有的：在涉及到二进制代码解析时
  * 但是只有指令解析的结果，而具体的指令是什么，则：没有提供外部的任何接口
    * 所以Unicorn中，无法获取到，对应的是什么指令，这方面的信息
* 如果想要搞清楚：当前是什么指令
  * 暂时只能：引入外部的反汇编器disassembler，比如`Capstone`，自己去把二进制翻译为对应指令
    * 注：而`Capstone`翻译的指令，和`Unicorn`底层实际上所运行的指令：
      * 一般来说应该是一样的
        * 当然，大部分时候，也的确是一样的
      * 但按理说，也可以是不一样的
        * 比如某些极其特殊的情况
          * 举例
            * `Unicorn`内部用到的代码解析是，比如说是只支持`ARM64`的，而额外引用的`Casptone`，比如说支持新的`arm64e`架构
              * 可能会出现，对于同样的二进制`7F  23 03 D5`，`Unicorn`内部被翻译为`HINT`指令，而`Capstone`（反汇编）打印出是（实际上arm64e中才支持的）PAC相关指令：`pacibsp`
    * 详见独立子教程：[反汇编利器：Capstone](https://book.crifan.org/books/ultimate_disassembler_capstone/website/)
