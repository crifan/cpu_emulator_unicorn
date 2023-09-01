# 参考资料

* 【整理】Unicorn相关内容
* 【整理】Unicorn相关文档和资料
* 【已解决】iOS逆向：unicorn的基本用法和基本逻辑
* 【记录】Unicorn相关知识：Unicorn和QEMU
* 【已解决】iOS逆向：Mac中安装unicorn
* 【已解决】Mac M2 Max中安装Unicorn
* 【已解决】Mac M2 Max中安装cmake
* 【已解决】Mac中安装pkg-config
* 【记录】Mac中用VSCode调试unicorn的示例代码sample_arm64.py
* 【已解决】Unicorn模拟ARM代码：优化内存分配布局内存映射
* 【已解决】Unicorn模拟arm64函数：___lldb_unnamed_symbol2575$$akd优化内存代码布局和输出日志
* 【已解决】iPhone11中ARM汇编Stack栈指针SP的增长方向
* 【已解决】ARM中汇编字节序的大端和小端
* 【未解决】iOS逆向：unicorn中传递函数指针参数
* 【已解决】Unicorn模拟arm64：PC在+4404时报错UC_ERR_MAP
* 【已解决】Unicorn模拟ARM代码：优化给内存地址写入对应的值
* 【已解决】unicorn模拟ARM中LR和SP寄存器堆栈信息
* 【已解决】unicorn中没有触发后续代码的hook函数hook_code
* 【未解决】unicorn中用UC_HOOK_INSN去给指令加上hook
* 【已解决】unicorn中给内存的读和写单独加上hook以辅助调试异常情况
* 【已解决】unicorn模拟ARM代码：分析内存读取和写入分析代码模拟逻辑
* 【已解决】Unicorn模拟ARM代码：优化hook打印逻辑
* 【已解决】Unicorn模拟ARM汇编：优化hook_code调试打印指令的输出日志
* 【已解决】Unicorn模拟ARM代码：优化log调试打印寄存器值
* 【已解决】Unicorn中hook时当特定位置代码时查看打印寄存器的值
* 【规避解决】Unicorn模拟ARM：去hook查看将要解码的opcode二进制
* 【已解决】unicorn中hook_code中查看当前要执行的二进制code代码指令数据
* 【已解决】iOS逆向：unicorn查看当前被识别出是什么ARM汇编指令
* 【已解决】Unicorn模拟arm64e代码时把mov识别成movz
* 【已解决】Unicorn模拟arm64：判断遇到指令ret时结束停止模拟
* 【未解决】unicorn模拟ARM汇编如何忽略特定指令为nop空指令
* 【未解决】Unicorn模拟arm：函数___lldb_unnamed_symbol2575$$akd模拟完毕但是没有生成要的结果
* 【未解决】iOS逆向akd：用Unicorn模拟运行arm64的akd函数sub_1000A0460的opcode代码
* 【已解决】Unicorn模拟arm64代码：___lldb_unnamed_symbol2575$$akd调用子函数___lldb_unnamed_symbol2567$$akd
* 【未解决】Unicorn模拟arm：给___lldb_unnamed_symbol2567$$akd函数准备调试环境
* 【未解决】研究对比___lldb_unnamed_symbol2575$$akd的+4448到+8516的逻辑的真实过程和模拟过程之间的差异
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
* 【已解决】Unicorn模拟arm64代码：尝试批量一次性解决全部的br跳转导致内存映射错误UC_ERR_MAP
* 【已解决】Unicorn模拟arm64代码：搞懂___lldb_unnamed_symbol2575$$akd函数br跳转涉及到的固定的值的内存范围
* 【已解决】Unicorn模拟arm64代码：计算br跳转涉及到的x10函数偏移量地址的合适的范围
* 【已解决】Unicorn模拟arm64代码：计算br跳转涉及到的x9的合适的范围
* 【已解决】Unicorn模拟arm64代码：导出lldb调试时x9和x10两个段的实际数据值到文件
* 【已解决】Unicorn模拟arm64：修正导出的x10的带偏移量的函数地址
* 【已解决】Unicorn模拟arm64代码：把导出的x9和x10的2段数据导入到Unicorn模拟代码中
* 【已解决】unicorn代码报错：ERROR Invalid memory write UC_ERR_WRITE_UNMAPPED
* 【已解决】unicorn模拟ARM64代码：给UC_ERR_WRITE_UNMAPPED单独加上hook看出错时详情
* 【已解决】Unicorn模拟ARM64代码：手动把braa改为br指令看是否还会报错UC_ERR_EXCEPTION
* 【已解决】通过修改ARM汇编二进制文件实现Unicorn忽略执行特定指令
* 【已解决】Python中把byteaddary转成64位的unsigned long long的数值
* 【已解决】Python中把int值转换成字节bytes
* 【已解决】unicorn代码mem_read报错：mem_read() missing 1 required positional argument size
* 【已解决】Unicorn模拟ARM代码：写入正确的地址但是读取出来数据值仍旧是错的
* 【已解决】Unicorn模拟ARM代码：mem_read内存读取的值和ldr指令加载出来的值不一样
* 【已解决】Unicorn模拟ARM：用内存映射并写入地址0x75784的内容
* 【已解决】Unicorn中Python中的ARM64的CPSR寄存器定义
* 【未解决】unicorn如何模拟ARM中PAC指令pacibsp
* 【未解决】iOS逆向：用unicorn模拟执行arm64e的arm汇编代码
* 【未解决】Unicorn模拟ARM代码报错：ERROR Unhandled CPU exception UC_ERR_EXCEPTION
* 【已解决】Unicorn模拟ARM64的函数中调用其他子函数
* 【未解决】Unicorn模拟arm：确保子函数___lldb_unnamed_symbol2567$$akd参数值正确
* 【已解决】Unicorn模拟arm64代码：模拟___lldb_unnamed_symbol2567$$akd直接返回值
* 【已解决】Unicorn模拟ARM64：模拟造出返回特定值的空函数的arm汇编代码的opcode
* 【已解决】Unicorn模拟ARM64代码：参考afl-unicorn的UnicornSimpleHeap模拟malloc
* 【已解决】Unicorn模拟ARM64：如何模拟malloc分配内存
* 【已解决】Unicorn模拟ARM：模拟malloc报错内存重叠Heap over underflow
* 【已解决】Unicorn模拟malloc内存分配：返回重复内存地址
* 【已解决】Unicorn模拟arm64：模拟free释放内存
* 【已解决】Unicorn模拟arm64：模拟vm_deallocate释放内存
* 【未解决】iOS逆向：如何反代码混淆反混淆去混淆
* 
* [反汇编利器：Capstone](https://book.crifan.org/books/ultimate_disassembler_capstone/website/)
* 
* [unicorn - 简书 (jianshu.com) ](https://www.jianshu.com/p/e6a7b30c1e89)
* [Unicorn.js: ARM (alexaltea.github.io)](https://alexaltea.github.io/unicorn.js/demo.html?arch=arm)
* [iOS Tampering and Reverse Engineering - OWASP Mobile Application Security](https://mas.owasp.org/MASTG/iOS/0x06c-Reverse-Engineering-and-Tampering/#unicorn)
* [Unicorn & QEMU – Unicorn – The Ultimate CPU emulator (unicorn-engine.org)](https://www.unicorn-engine.org/docs/beyond_qemu.html)
* [为什么使用汇编可以 Hook objc_msgSend（上）- 汇编基础 - 一片瓜田 (desgard.com)](https://www.desgard.com/2020/04/05/why-hook-msg_objc-can-use-asm-1.html)
* [Opcode - Wikipedia](https://en.wikipedia.org/wiki/Opcode)
* [[原创] Unicorn 在 Android 的应用-『Android安全』-看雪安全论坛](https://bbs.pediy.com/thread-253868.htm)
* [Programming with Python language – Capstone – The Ultimate Disassembler (capstone-engine.org)](http://www.capstone-engine.org/lang_python.html)
* [capstone/bindings/python at master · capstone-engine/capstone · GitHub](https://github.com/capstone-engine/capstone/tree/master/bindings/python)
* [Unicorn快速入门 - iPlayForSG - 博客园 (cnblogs.com)](https://www.cnblogs.com/Here-is-SG/p/17080180.html)
* [Online ARM to HEX Converter (armconverter.com)](https://armconverter.com/?code=ret)
* [Showcases – Unicorn – The Ultimate CPU emulator](https://www.unicorn-engine.org/showcase/)
* [afl-unicorn: Fuzzing Arbitrary Binary Code | by Nathan Voss | HackerNoon.com | Medium](https://medium.com/hackernoon/afl-unicorn-fuzzing-arbitrary-binary-code-563ca28936bf)
* [afl-unicorn/unicorn_loader.py at master · Battelle/afl-unicorn · GitHub](https://github.com/Battelle/afl-unicorn/blob/master/unicorn_mode/helper_scripts/unicorn_loader.py)
* 