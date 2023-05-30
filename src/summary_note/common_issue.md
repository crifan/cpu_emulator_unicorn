# 常见错误

TODO：

* 报错：ERROR: Invalid memory mapping (UC_ERR_MAP)
  * 举例
    * 【已解决】Unicorn模拟___lldb_unnamed_symbol2575$$akd：PC在+380处Invalid memory mapping UC_ERR_MAP
    * 【已解决】iOS逆向akd之Unicorn模拟arm64代码：PC在0x64378时出错Memory UNMAPPED at 0x0
    * 【已解决】Unicorn模拟arm64：PC在+7428时blr x8报错UC_ERR_MAP
    * 【已解决】Unicorn模拟arm64：PC在+9296时报错UC_ERR_MAP 0xFFFFFFFFFFFFFFFE
    * 【已解决】Unicorn模拟arm64代码：PC在+552时报错ERROR Invalid memory mapping 
    * 【已解决】Unicorn模拟arm64：PC在+4448时报错UC_ERR_MAP at 0xFFFFFFFFFFFFFFFDUC_ERR_MAP
    * 【已解决】Unicorn模拟arm64：PC在+7396时UC_ERR_MAP出错0xFFFFFFFFFFFFFFFE
    * 【已解决】iOS逆向akd用Unicorn模拟代码：PC在0x000100CC时报错Invalid memory mapping UC_ERR_MAP 0xFFFFFFFFFFFFFFFE
    * 【已解决】iOS逆向akd用Unicorn模拟ARM：PC在0x0001011C时出错Invalid memory mapping UC_ERR_MAP
    * 【已解决】Unicorn模拟arm64：PC在+4404时报错UC_ERR_MAP
    * 【已解决】iOS逆向akd之Unicorn模拟arm64代码：PC在0x00010088时出错br跳转0地址
    * 【已解决】unicorn模拟ARM64代码报错：ERROR Invalid memory mapping UC_ERR_MAP
    * 【已解决】Unicorn模拟ARM代码出错：Memory UNMAPPED at 0x24C6
    * 【未解决】Unicorn模拟ARM代码出错：PC是0x10090时Memory UNMAPPED at 0x100AF6C88
  * 原因：
    * 表面原因：多数是，内存地址是0或另外某个未映射的地址
    * 深层原因：模拟的代码前面的中间的某些步骤，已经出错了，导致此处的异常
      * 比如之前就读取某个地址的值是0
        * 其实是需要实现准备好环境：向对应地址写入对应的值，即可避免规避此问题
  * -》高级技巧和心得
    * 后来发现此处被调试的程序，有个通用的逻辑：给特定内存地址写入特定值，就可以批量的避免后续的跳转问题了
      * 【已解决】Unicorn模拟arm64代码：尝试批量一次性解决全部的br跳转导致内存映射错误UC_ERR_MAP
      * 【已解决】Unicorn模拟arm64代码：把导出的x9和x10的2段数据导入到Unicorn模拟代码中
      * 【已解决】Unicorn模拟arm64代码：导出lldb调试时x9和x10两个段的实际数据值到文件
      * 【已解决】Unicorn模拟arm64代码：搞懂___lldb_unnamed_symbol2575$$akd函数br跳转涉及到的固定的值的内存范围
      * 【已解决】Unicorn模拟arm64代码：计算br跳转涉及到的x10函数偏移量地址的合适的范围
      * 【已解决】Unicorn模拟arm64：修正导出的x10的带偏移量的函数地址
      * 【已解决】Unicorn模拟arm64代码：计算br跳转涉及到的x9的合适的范围
* 报错：ERROR: Invalid memory write (UC_ERR_WRITE_UNMAPPED)
  * 【已解决】unicorn代码报错：ERROR Invalid memory write UC_ERR_WRITE_UNMAPPED
    * 内存的hook
      * 【已解决】unicorn模拟ARM64代码：给UC_ERR_WRITE_UNMAPPED单独加上hook看出错时详情
* 报错：Memory UNMAPPED at
  * 【已解决】iOS逆向akd之Unicorn模拟arm64代码：PC在0x64378时出错Memory UNMAPPED at 0x0

---
