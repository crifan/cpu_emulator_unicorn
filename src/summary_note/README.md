# 经验和心得

TODO：

* 无法跳过当前指令
  * 【未解决】unicorn模拟ARM汇编如何忽略特定指令为nop空指令
* 如果指令不好模拟，数量不多的话，可以考虑手动修改原始二进制
  * 比如arm64e的braa变br
    * 【已解决】Unicorn模拟ARM64代码：手动把braa改为br指令看是否还会报错UC_ERR_EXCEPTION
  * 其他指令变nop
    * 【已解决】通过修改ARM汇编二进制文件实现Unicorn忽略执行特定指令
* 其他
  * 【未解决】Unicorn模拟arm：函数___lldb_unnamed_symbol2575$$akd模拟完毕但是没有生成要的结果
  * 【未解决】iOS逆向akd：用Unicorn模拟运行arm64的akd函数sub_1000A0460的opcode代码
  * 【已解决】Unicorn模拟arm64代码：___lldb_unnamed_symbol2575$$akd调用子函数___lldb_unnamed_symbol2567$$akd
  * 【未解决】Unicorn模拟arm：给___lldb_unnamed_symbol2567$$akd函数准备调试环境
  * 【未解决】研究对比___lldb_unnamed_symbol2575$$akd的+4448到+8516的逻辑的真实过程和模拟过程之间的差异

---
