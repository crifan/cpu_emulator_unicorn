# Capstone

TODO：

* 配合Capstone去查看反汇编代码
  * 【已解决】unicorn中用Capstone反汇编查看当前汇编代码指令
  * 【已解决】iOS逆向：unicorn查看当前被识别出是什么ARM汇编指令
  * 资料
    * 反汇编框架 Capstone
  * 相关
    * 【已解决】Mac中安装和初始化Capstone去显示反汇编代码
  * 注意
    * Capstone反汇编出来的指令，有些细节和Xcode中不太一样 == 注意：用Capstone去反汇编看到的指令，和Unicorn真正执行的指令，未必相同，但是可供参考。基本上差距不大
      * mov vs movz
        * 【已解决】Unicorn模拟arm64e代码时把mov识别成movz
      * 有些值是计算后的值，而不是指令本身的值
        * 【整理】Unicorn调试心得：Capstone反汇编中有些值是计算后的结果而不是原始ARM指令中的值
        * 【已解决】为何Unicorn/Capstone对于68 8F 2F 58反汇编ARM指令结果是错误的
        * 【已解决】unicorn模拟ARM指令：Capstone和Xcode的指令反汇编结果不一样

---
