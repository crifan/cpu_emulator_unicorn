# 概述Unicorn核心思路

使用Unicorn去模拟代码执行的核心思路是：

* 背景知识
  * 先要具备相关技术背景知识，至少包括
    * 对于程序运行本质（读取指令，运行指令）有所了解
    * 对基本的典型的内存布局有所了解
* 运行前
  * 先要准备好要运行的代码
    * 往往是对应的二进制文件
      * 比如用lldb调试iOS逆向的iPhone中程序期间，导出的某个函数的全部或部分的代码
  * 稍微复杂点的情况，还要准备其他相关内容
    * 设置好要模拟的传入函数的参数
    * 给特定内存位置写入对应的数据
    * 如果程序内部跳转调用其他子函数，则还要设置好：Stack栈
    * 如果期间涉及到malloc等内存分配，则还要准备好：Heap堆
* 运行中
  * 主要就是调用`emu_start`触发开始模拟
  * 期间更多的是，要调试搞懂代码逻辑或者查看对应的寄存器或内存的值
    * 所以往往要用对应的手段去调试
      * 典型都有hook机制：hook代码（甚至hook特定指令）、hook内存、hook异常
      * 以及用好日志打印，其中有很多可以优化的地方
      * 包括可能利用Capstone去查看当前正在运行的是什么指令
* 运行后
  * 常常是判断指令是`ret`时调用`emu_stop`而停止模拟运行
  * 然后再去从返回的寄存器或特定内存地址，获取程序模拟的最终的输出结果

下面详细解释具体过程。