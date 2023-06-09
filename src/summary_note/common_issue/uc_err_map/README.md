# ERROR: Invalid memory mapping (UC_ERR_MAP)

* 现象：`ERROR: Invalid memory mapping (UC_ERR_MAP)` == `Memory UNMAPPED at `
* 原因：
  * 表面原因：多数是，内存地址是`0`或另外某个未映射的地址
  * 深层原因：模拟的代码前面的中间的某些步骤，已经出错了，导致此处的异常
    * 比如之前就读取某个地址的值是0
      * 其实是需要实现准备好环境：向对应地址写入对应的值，即可避免规避此问题

## 举例说明

* 【已解决】Unicorn模拟___lldb_unnamed_symbol2575$$akd：PC在+380处Invalid memory mapping UC_ERR_MAP

中的：

```bash
=== 0x0001016C  <+364>: 28 DB A8 B8  -> ldrsw   x8, [x25, w8, sxtw #2]
 << Memory READ at 0x32858, size=4, rawValueLittleEndian=0x00000000, pc=0x1016C
=== 0x00010170  <+368>: 1F 20 03 D5  -> nop
=== 0x00010174  <+372>: AA 5C 2C 58  -> ldr     x10, #0x68d08
 << Memory READ at 0x68D08, size=8, rawValueLittleEndian=0x0000000000000000, pc=0x10174
=== 0x00010178  <+376>: 08 01 0A 8B  -> add     x8, x8, x10
=== 0x0001017C  <+380>: 00 01 1F D6  -> br      x8
!!! Memory UNMAPPED at 0x0 size=0x4, access(r/w)=21, value=0x0, PC=0x0
ERROR: Invalid memory mapping (UC_ERR_MAP)
```

需要对于上述，前面出现的`Memory READ`的`rawValueLittleEndian=0x0000000000000000`，即内存读取出来值是0的地方，写入特定的值

此特定的值，需要调试真实代码才能得到

此次调试后得到的值是：

`<+380>: 00 01 1F D6  -> br      x8`

* 真实值
  * br x8
    * 要去跳转到：+484
      * +484
        * = x8 + x10
        * = 0x00000000000000c4 + 0x0000000102e70580
        * = 0x00000000000000c4 + akd`___lldb_unnamed_symbol2575$$akd + 288
        * = 0x0000000102e70644
        * = akd`___lldb_unnamed_symbol2575$$akd + 484

而：

* x10=akd`___lldb_unnamed_symbol2575$$akd + 288

此处模拟值：
有2个：
* 针对于
  * <+364>: 28 DB A8 B8 -> ldrsw  x8, [x25, w8, sxtw #2]
* 要写入地址：x8 = 0x32858
  * 要写入值：0x00000000000000c4
和：
* 针对于
  * <+372>: AA 5C 2C 58 -> ldr   x10, #0x68d08
* 要写入地址：x10 = 0x68D08
  * 要写入值：函数起始地址 + 288
    * = 0x10000 + 0x120
    * = 0x10120

所以解决办法是：

去写入对应的值：

```py
  writeMemory(0x32858, 0xc4, 8)           # <+364>: 28 DB A8 B8  -> ldrsw   x8, [x25, w8, sxtw #2]
  writeMemory(0x68D08, 0x10120, 8)        # <+372>: AA 5C 2C 58  -> ldr     x10, #0x68d08

  0x0001016C: ["w8", "x25"],
  0x00010170: ["x8"],
  0x00010178: ["x10"],
```

然后解决解决问题，输出log中可以看出

```bash
=== 0x0001016C  <+364>: 28 DB A8 B8  -> ldrsw   x8, [x25, w8, sxtw #2]
    debug: PC=0x1016C: w8=0x00000002, x25=0x0000000000032850
 << Memory READ at 0x32858, size=4, rawValueLittleEndian=0xc4000000, pc=0x1016C
=== 0x00010170  <+368>: 1F 20 03 D5  -> nop
    debug: PC=0x10170: x8=0x00000000000000C4
=== 0x00010174  <+372>: AA 5C 2C 58  -> ldr     x10, #0x68d08
 << Memory READ at 0x68D08, size=8, rawValueLittleEndian=0x2001010000000000, pc=0x10174
=== 0x00010178  <+376>: 08 01 0A 8B  -> add     x8, x8, x10
    debug: PC=0x10178: x10=0x0000000000010120
=== 0x0001017C  <+380>: 00 01 1F D6  -> br      x8
>>> Tracing basic block at 0x101e4, block size = 0x48
=== 0x000101E4  <+484>: 16 00 80 52  -> movz    w22, #0
=== 0x000101E8  <+488>: 08 F3 8B 52  -> movz    w8, #0x5f98
```

代码在`<+380>`之后，可以正常继续运行了。
