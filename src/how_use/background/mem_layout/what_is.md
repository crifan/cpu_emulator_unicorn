# 什么是内存布局

内存布局，指的是：

* 你把要放置的东西，具体放哪里了

而此处的：

* 要放置的东西
  * 主要指的是：`代码`=`code`
  * 其他往往也涉及到
    * `数据`=`data`
    * 其他 = 能让程序正常运行起来的各种配合的环境
      * `Stack`栈
      * `Heap`堆
      * 有时候还要
        * 给特定内存写入特定值
      * 等等
* 放哪里 中的 哪里 指的是：`内存`=`memory`
* 具体放哪里了 中的 具体 指的是：放到**内存**中的哪个**范围**了
  * 往往涉及到：`起始地址` + 这段的`空间大小` = `结束地址`

## 内存中要存放哪些东西

下面再来详细介绍一下，内存中要存放哪些东西：

### 代码

所以如果要让CPU能运行你的指令，你要先去把你的代码，放到内存中，供CPU读取。

所以，第一个优先要放到内存中的，就是：代码。

注：代码==指令==二进制==opcode

而你把代码放到具体哪个位置，就是内存布局中，代码的地址空间范围。

### 其他

而能让CPU顺利模拟运行你的代码之外，对于实际情况中，比如稍微复杂一点的代码，往往还有会涉及到其他一些内容：

* 函数的参数
* Stack栈
* heap堆
* 事先要写入特定内存的值

下面分别介绍一下：

#### 函数的参数

很多要模拟的函数，往往是有一些参数的，所以在模拟之前，要先把参数写入对应寄存器或内存，供模拟执行用。

比如，你模拟`add(int a, int b)`的二进制代码执行的话，就要把`a`和`b`的值先写好，比如放到ARM的寄存器`x0`和`x1`中，供模拟调用。

#### Stack栈

如果函数A内部调用了其他函数，比如B函数，C函数等，则往往又涉及到函数上下文的切换，底层具体实现就是涉及到Stack栈，在调用之前和之后，代码中会操作Stack，保存PC、LR、多个相关寄存器等等，所以，往往在模拟函数运行之前，也要先去设置好Stack。

#### heap堆

如果要模拟的函数，内部涉及到申请内存malloc等，则往往也要设置对应的headp堆，用于模拟内存管理提供动态申请和释放内存用。

### 给特定内存写入特定的值

其他一些特殊情况中，要给特定内存地址写入特定地址，供后续代码模拟时调用。

一般普通的函数模拟，往往无需此过程。