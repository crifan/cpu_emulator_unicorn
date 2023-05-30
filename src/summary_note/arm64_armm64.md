# ARM64和arm64e

TODO：

* ARM、ARM64、arm64e
  * ARM64和ARM，有些寄存器是公共的，所以放到了ARM中，而ARM64没有
    * 比如
      * 有：UC_ARM_REG_CPSR
      * 没有：UC_ARM64_REG_CPSR
    * 详见：
      * 【已解决】Unicorn中Python中的ARM64的CPSR寄存器定义
  * 暂时不支持arm64e（的PAC指令）
    * 所以无法彻底解决
      * 【未解决】unicorn如何模拟ARM中PAC指令pacibsp
      * 【未解决】iOS逆向：用unicorn模拟执行arm64e的arm汇编代码
    * 报错：UC_ERR_EXCEPTION
      * 此处是：不支持arm64e的pac指令BRAA而导致CPU异常
        * 【未解决】Unicorn模拟ARM代码报错：ERROR Unhandled CPU exception UC_ERR_EXCEPTION

---
