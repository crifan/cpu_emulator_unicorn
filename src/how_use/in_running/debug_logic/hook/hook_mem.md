# hook内存

TODO：

* 内存：hook_mem_write、hook_mem_read
  * 【已解决】unicorn中给内存的读和写单独加上hook以辅助调试异常情况
  * 要能看懂触发和输出的log背后的含义
    * 【已解决】unicorn模拟ARM代码：分析内存读取和写入分析代码模拟逻辑
      * 比如：单个指令： stp  x28, x27, [sp, #0x80]，输出多个Memory WRITE

---
