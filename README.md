# CPU模拟利器：Unicorn

* 最新版本：`v2.1`
* 更新时间：`20230901`

## 简介

介绍如何用Unicorn去模拟CPU去执行函数的二进制代码而得到结果。先给出Unicorn的概览；再介绍如何初始Unicorn，包括下载和安装以及运行测试代码确保环境无误。接着详细介绍如何使用Unicorn，yo尤其是概述Unicorn核心思路，接着介绍背景知识，包括程序运行的本质，涉及到CPU的核心逻辑和搞懂什么是指令；以及内存布局相关内容，包括什么是内存布局、内存地址空间范围、典型的内存布局；以及字节序endian。接着介绍运行前的准备，包括设置代码和其他内容。其他内容包含函数参数、相关数据、Stack栈、heap堆；接着介绍运行中的内容，包括如何开始运行，如何调试逻辑，主要是hook，包括hook代码和指令、hook内存、hook异常等内容；以及打印日志，包括优化日志输出。然后是运行后的内容，包括停止运行的逻辑，以及获取结果。接着整理了大量的经验和心得，包括常见的错误，比如UC_ERR_MAP、UC_ERR_WRITE_UNMAPPED等，其中涉及到br间接跳转去混淆相关内容；其他心得还包括手动修改指令、内存读取和写入时的数值转换、如何调用其他子函数、以及具体的模拟malloc、free、vm_deallocate等具体函数实现；以及用到Unicorn的showcase。然后加上一些实际案例，比如模拟akd函数symbol2575和其他一些示例代码；最后附录整理一些Unicorn文档和资料以及Unicorn的部分核心代码。最后贴出引用资料。

## 源码+浏览+下载

本书的各种源码、在线浏览地址、多种格式文件下载如下：

### HonKit源码

* [crifan/cpu_emulator_unicorn: CPU模拟利器：Unicorn](https://github.com/crifan/cpu_emulator_unicorn)

#### 如何使用此HonKit源码去生成发布为电子书

详见：[crifan/honkit_template: demo how to use crifan honkit template and demo](https://github.com/crifan/honkit_template)

### 在线浏览

* [CPU模拟利器：Unicorn book.crifan.org](https://book.crifan.org/books/cpu_emulator_unicorn/website/)
* [CPU模拟利器：Unicorn crifan.github.io](https://crifan.github.io/cpu_emulator_unicorn/website/)

### 离线下载阅读

* [CPU模拟利器：Unicorn PDF](https://book.crifan.org/books/cpu_emulator_unicorn/pdf/cpu_emulator_unicorn.pdf)
* [CPU模拟利器：Unicorn ePub](https://book.crifan.org/books/cpu_emulator_unicorn/epub/cpu_emulator_unicorn.epub)
* [CPU模拟利器：Unicorn Mobi](https://book.crifan.org/books/cpu_emulator_unicorn/mobi/cpu_emulator_unicorn.mobi)

## 版权和用途说明

此电子书教程的全部内容，如无特别说明，均为本人原创。其中部分内容参考自网络，均已备注了出处。如发现有侵权，请通过邮箱联系我 `admin 艾特 crifan.com`，我会尽快删除。谢谢合作。

各种技术类教程，仅作为学习和研究使用。请勿用于任何非法用途。如有非法用途，均与本人无关。

## 鸣谢

感谢我的老婆**陈雪**的包容理解和悉心照料，才使得我`crifan`有更多精力去专注技术专研和整理归纳出这些电子书和技术教程，特此鸣谢。

## 其他

### 作者的其他电子书

本人`crifan`还写了其他`150+`本电子书教程，感兴趣可移步至：

[crifan/crifan_ebook_readme: Crifan的电子书的使用说明](https://github.com/crifan/crifan_ebook_readme)

### 关于作者

关于作者更多介绍，详见：

[关于CrifanLi李茂 – 在路上](https://www.crifan.org/about/)
