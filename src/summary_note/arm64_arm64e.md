# ARM64和arm64e

Unicorn支持多种架构，其中包括`ARM`

ARM架构和Unicorn的相关概念有：

* `ARM`：指的是总体的概念，ARM架构
  * `ARM64`：指的是，ARM架构下的子架构，64位的`ARM64`
    * `arm64e`：指的是，ARM64之后，新增加的，`ARMv8.3`之后新增了`PAC`指令，对应底层ARM汇编成为`arm64e`，其支持新的PAC相关指令

由此，要注意的有些细节：

* Unicorn中的ARM
  * `ARM64`和`ARM`，有些寄存器是公共的，所以放到了ARM中，而ARM64没有
    * 比如
      * 有：`UC_ARM_REG_CPSR`
      * 没有：`UC_ARM64_REG_CPSR`
  * 暂时不支持`arm64e`（的PAC指令）
    * 举例
      * pacibsp
        ```asm
        akd`___lldb_unnamed_symbol2540$$akd:
        ->  0x1045f598c <+0>:     pacibsp
        ```
    * 所以无法彻底解决
      * 会报错：UC_ERR_EXCEPTION
        * 举例
          * 不支持arm64e的pac指令BRAA而导致CPU异常：`ERROR Unhandled CPU exception UC_ERR_EXCEPTION`
      * 只能用其他办法规避
        * 比如
          * 把PAC相关指令，换成NOP空指令或对应的去掉PAC部分的指令
            * 详见：[手动修改指令](./../summary_note/manual_change_opcode.md)
