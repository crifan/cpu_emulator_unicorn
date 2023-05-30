# 优化日志输出

TODO：

* 调试的细节的优化=优化输出日志
  * 优化：让输出尽量和Xcode一样 -》方便理解汇编代码
    * 【已解决】Unicorn模拟ARM代码：优化hook打印逻辑
    * 【已解决】Unicorn模拟ARM汇编：优化hook_code调试打印指令的输出日志
  * （批量）调试输出寄存器值
    * 【已解决】Unicorn模拟ARM代码：优化log调试打印寄存器值
    * 【已解决】Unicorn中hook时当特定位置代码时查看打印寄存器的值
  * 打印出当前的opcode
    * 【规避解决】Unicorn模拟ARM：去hook查看将要解码的opcode二进制

---
