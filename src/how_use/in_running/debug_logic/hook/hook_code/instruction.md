# hook指令

Unicorn对于指令的hook的核心用法：
* 调用`hook_add`时传递参数
  * `type`=`UC_HOOK_INSN`
  * `ins` = `UC_{arch}_INS_{xxx}`
    * `arch`：架构，`X86`/`ARM64`等
    * `xxx`：指令名称
* 具体支持的指令
  * `X86`：支持很多指令的hook
    * 比如
      * `UC_X86_INS_SYSCALL`
      * `UC_X86_INS_IN`
      * `UC_X86_INS_OUT`
    * 其他指令详见：[x86_const](https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/unicorn/x86_const.py)
  * `ARM64`：只支持极其有限的几个指令，其他指令不支持
    * `UC_ARM64_INS_MRS`
    * `UC_ARM64_INS_MSR`
    * `UC_ARM64_INS_SYS`
    * `UC_ARM64_INS_SYSL`

## 如何使用hook_add的UC_HOOK_INSN

官网有例子[sample_arm64](https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/sample_arm64.py)，供参考：

```py
def test_arm64_hook_mrs():
  def _hook_mrs(uc, reg, cp_reg, _):
    print(f">>> Hook MRS instruction: reg = 0x{reg:x}(UC_ARM64_REG_X2) cp_reg = {cp_reg}")
    uc.reg_write(reg, 0x114514)
    print(">>> Write 0x114514 to X")

    # Skip MRS instruction
    return True

。。。
    # Hook MRS instruction
    mu.hook_add(UC_HOOK_INSN, _hook_mrs, None, 1, 0, UC_ARM64_INS_MRS)
```
