# 运行后

在Unicorn模拟代码运行之后，所涉及到的内容主要有：

* 如果不设置合适的停止时机，往往Unicorn会一直运行下去，所以找个合适时机去停止运行
  * 往往都是`ret`指令时，去调用`emu_stop`去停止
* 运行后，获取程序输出的结果

下面分别详细解释：
