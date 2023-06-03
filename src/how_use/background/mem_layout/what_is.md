# 什么是内存布局

内存布局，指的是：

* 你把要放置的东西，具体放哪里了

而此处的：

* 要放置的东西
  * 主要指的是：`代码`=`code`
    * 详见后续章节：[设置代码](../../../how_use/before_run/set_code/README.md)
  * 其他往往也涉及到
    * `数据`=`data`
    * 其他 = 能让程序正常运行起来的各种配合的环境
      * `Stack`栈
        * 详见后续章节：[Stack栈](../../../how_use/before_run/set_other/stack.md)
      * `Heap`堆
        * 详见后续章节：[Heap堆](../../../how_use/before_run/set_other/heap.md)
      * 有时候还要
        * 给特定内存写入特定值
          * 详见后续章节：[相关数据](../../../how_use/before_run/set_other/related_data.md)
      * 等等
* 放哪里 中的 哪里 指的是：`内存`=`memory`
* 具体放哪里了 中的 具体 指的是：放到**内存**中的哪个**范围**了
  * 往往涉及到：`起始地址` + 这段的`空间大小` = `结束地址`
