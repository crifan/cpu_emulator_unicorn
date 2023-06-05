# CPU模拟利器：Unicorn

* 最新版本：`v0.9`
* 更新时间：`20230605`

## 简介

介绍如何用Unicorn去模拟CPU去执行函数的二进制代码而得到结果。先给出Unicorn的概览；再介绍如何初始Unicorn，包括下载和安装以及运行测试代码确保环境无误。接着详细介绍如何使用Unicorn，包括准备执行环境，尤其是内存布局、以及函数参数、预先写入值等等；接着是写hook去hook代码、内存、异常等内容；然后才是开始运行，得到运行结果；接着整理了大量的经验和心得，包括常见的错误、如何优化日志输出、相关的数值转换、和ARM相关的ARM64和arm64e方面的内容、模拟调用其他子函数、以及模拟一些函数的具体实现和Capstone去实现反汇编。然后给出一些具体的实例的完整代码。

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
