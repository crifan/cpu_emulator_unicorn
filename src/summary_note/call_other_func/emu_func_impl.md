# 模拟函数实现

此处接着说，模拟调用其他子函数期间，常常会涉及到的一些，相对通用的函数，如何去模拟。

* 注：完整代码 [模拟akd函数symbol2575](../../../../../examples/example_akd_symbol2575.md) ，包括下面几个模拟函数，需要的可以去参考。

## 模拟malloc申请内存

此处最后是：

* 参考[网上源码unicorn_loader](https://github.com/Battelle/afl-unicorn/blob/master/unicorn_mode/helper_scripts/unicorn_loader.py)
* 加上自己后续的优化

目前最新代码是：

* `UnicornSimpleHeap.py`

```py
# Function: Emulate memory management (malloc/free/...)
# Author: Crifan Li
# Update: 20230529

from unicorn import *
import logging

# Page size required by Unicorn
UNICORN_PAGE_SIZE = 0x1000

# Max allowable segment size (1G)
MAX_ALLOWABLE_SEG_SIZE = 1024 * 1024 * 1024

# Alignment functions to align all memory segments to Unicorn page boundaries (4KB pages only)
ALIGN_PAGE_DOWN = lambda x: x & ~(UNICORN_PAGE_SIZE - 1)
ALIGN_PAGE_UP   = lambda x: (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE-1)

# refer: https://github.com/Battelle/afl-unicorn/blob/master/unicorn_mode/helper_scripts/unicorn_loader.py
class UnicornSimpleHeap(object):
    """ Use this class to provide a simple heap implementation. This should
        be used if malloc/free calls break things during emulation. This heap also
        implements basic guard-page capabilities which enable immediate notice of
        heap overflow and underflows.
    """

    # Helper data-container used to track chunks
    class HeapChunk(object):
        def __init__(self, actual_addr, total_size, data_size):
            self.total_size = total_size                        # Total size of the chunk (including padding and guard page)
            self.actual_addr = actual_addr                      # Actual start address of the chunk
            self.data_size = data_size                          # Size requested by the caller of actual malloc call
            self.data_addr = actual_addr + UNICORN_PAGE_SIZE    # Address where data actually starts

        # Returns true if the specified buffer is completely within the chunk, else false
        def is_buffer_in_chunk(self, addr, size):
            if addr >= self.data_addr and ((addr + size) <= (self.data_addr + self.data_size)):
                return True
            else:
                return False

        def isSameChunk(self, anotherChunk):
            isSame = (self.actual_addr == anotherChunk.actual_addr) and (self.total_size == anotherChunk.total_size)
            return isSame

        def debug(self):
            chunkEndAddr = self.actual_addr + self.total_size
            chunkStr = "chunk: [0x%X-0x%X] ptr=0x%X, size=%d=0x%X"% (self.actual_addr, chunkEndAddr, self.data_addr, self.data_size, self.data_size)
            return chunkStr

        def isOverlapped(self, newChunk):
            # logging.info("debug: self=%s, newChunk=%s", self.debug(), newChunk.debug())
            selfStartAddr = self.actual_addr
            selfLastAddr = selfStartAddr + self.total_size - 1
            newChunkStartAddr = newChunk.actual_addr
            newChunkLastAddr = newChunkStartAddr + newChunk.total_size - 1
            isOverlapStart = (newChunkStartAddr >= selfStartAddr) and (newChunkStartAddr <= selfLastAddr)
            isOverlapEnd = (newChunkLastAddr >= selfStartAddr) and (newChunkLastAddr <= selfLastAddr)
            isOverlapped = isOverlapStart or isOverlapEnd
            return isOverlapped

    # # Skip the zero-page to avoid weird potential issues with segment registers
    # HEAP_MIN_ADDR = 0x00002000 # 8KB
    # HEAP_MAX_ADDR = 0xFFFFFFFF # 4GB-1
    _headMinAddr = None
    _heapMaxAddr = None

    _uc = None              # Unicorn engine instance to interact with
    _chunks = []            # List of all known chunks
    _debug_print = False    # True to print debug information

    # def __init__(self, uc, debug_print=False):
    def __init__(self, uc, headMinAddr, heapMaxAddr, debug_print=False):
        self._uc = uc
        self._headMinAddr = headMinAddr
        self._heapMaxAddr = heapMaxAddr
        self._debug_print = debug_print

        # Add the watchpoint hook that will be used to implement psuedo-guard page support
        self._uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, self.__check_mem_access)

    def isChunkAllocated(self, newChunk):
        isAllocated = False
        for eachChunk in self._chunks:
            if eachChunk.isSameChunk(newChunk):
                isAllocated = True
                break
        return isAllocated

    def isChunkOverlapped(self, newChunk):
        isOverlapped = False
        for eachChunk in self._chunks:
            if eachChunk.isOverlapped(newChunk):
                isOverlapped = True
                break
        return isOverlapped

    def malloc(self, size):
        # Figure out the overall size to be allocated/mapped
        #    - Allocate at least 1 4k page of memory to make Unicorn happy
        #    - Add guard pages at the start and end of the region
        total_chunk_size = UNICORN_PAGE_SIZE + ALIGN_PAGE_UP(size) + UNICORN_PAGE_SIZE
        # Gross but efficient way to find space for the chunk:
        chunk = None
        # for addr in range(self.HEAP_MIN_ADDR, self.HEAP_MAX_ADDR, UNICORN_PAGE_SIZE):
        for addr in range(self._headMinAddr, self._heapMaxAddr, UNICORN_PAGE_SIZE):
            try:
                # self._uc.mem_map(addr, total_chunk_size, UC_PROT_READ | UC_PROT_WRITE)
                chunk = self.HeapChunk(addr, total_chunk_size, size)
                # chunkStr = "[0x{0:X}-0x{1:X}]".format(chunk.actual_addr, chunk.actual_addr + chunk.total_size)
                chunkStr = chunk.debug()
                # if chunk in self._chunks:
                # if self.isChunkAllocated(chunk):
                if self.isChunkOverlapped(chunk):
                    # if self._debug_print:
                    #     logging.info(" ~~ Omit overlapped chunk: %s", chunkStr)
                    continue
                else:
                    if self._debug_print:
                        # logging.info("Heap: allocating 0x{0:X} byte addr=0x{1:X} of chunk {2:s}".format(chunk.data_size, chunk.data_addr, chunkStr))
                        logging.info(" ++ Allocated heap chunk: %s", chunkStr)
                    break
            except UcError as err:
                logging.error("!!! Heap malloc failed: error=%s", err)
                continue
        # Something went very wrong
        if chunk == None:
            return 0
        self._chunks.append(chunk)
        return chunk.data_addr

    def calloc(self, size, count):
        # Simple wrapper around malloc with calloc() args
        return self.malloc(size*count)

    def realloc(self, ptr, new_size):
        # Wrapper around malloc(new_size) / memcpy(new, old, old_size) / free(old)
        if self._debug_print:
            logging.info("Reallocating chunk @ 0x{0:016x} to be 0x{1:x} bytes".format(ptr, new_size))
        old_chunk = None
        for chunk in self._chunks:
            if chunk.data_addr == ptr:
                old_chunk = chunk
        new_chunk_addr = self.malloc(new_size)
        if old_chunk != None:
            self._uc.mem_write(new_chunk_addr, str(self._uc.mem_read(old_chunk.data_addr, old_chunk.data_size)))
            self.free(old_chunk.data_addr)
        return new_chunk_addr

    def free(self, addr):
        for chunk in self._chunks:
            if chunk.is_buffer_in_chunk(addr, 1):
                if self._debug_print:
                    logging.info("Freeing 0x{0:x}-byte chunk @ 0x{0:016x}".format(chunk.req_size, chunk.data_addr))
                self._uc.mem_unmap(chunk.actual_addr, chunk.total_size)
                self._chunks.remove(chunk)
                return True
        return False

    # Implements basic guard-page functionality
    def __check_mem_access(self, uc, access, address, size, value, user_data):
        for chunk in self._chunks:
            if address >= chunk.actual_addr and ((address + size) <= (chunk.actual_addr + chunk.total_size)):
                if chunk.is_buffer_in_chunk(address, size) == False:
                    if self._debug_print:
                        logging.info("Heap over/underflow attempting to {0} 0x{1:x} bytes @ {2:016x}".format( \
                            "write" if access == UC_MEM_WRITE else "read", size, address))
                    # Force a memory-based crash
                    uc.force_crash(UcError(UC_ERR_READ_PROT))
```

调用代码：`emulate_akd_getIDMSRoutingInfo.py`

```py
from libs.UnicornSimpleHeap import UnicornSimpleHeap

ucHeap = None

#-------------------- Stack --------------------
HEAP_ADDRESS = 6 * 1024 * 1024
HEAP_SIZE = 1 * 1024 * 1024
HEAP_ADDRESS_END = HEAP_ADDRESS + HEAP_SIZE
HEAP_ADDRESS_LAST_BYTE = HEAP_ADDRESS_END - 1

。。。
# callback for tracing instructions
def hook_code(mu, address, size, user_data):
    global ucHeap

    # for emulateMalloc
    if pc == 0x00200000:
        mallocSize = mu.reg_read(UC_ARM64_REG_X0)
        newAddrPtr = ucHeap.malloc(mallocSize)
        mu.reg_write(UC_ARM64_REG_X0, newAddrPtr)
        print("input x0=0x%x, output ret: 0x%x" % (mallocSize, newAddrPtr))

...
def emulate_arm64():
    global uc, ucHeap
    try:
        # Initialize emulator in ARM mode
        # mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM + UC_MODE_LITTLE_ENDIAN)
...
        # map heap
        mu.mem_map(HEAP_ADDRESS, HEAP_SIZE)
        print("Mapped memory: Heap\t[0x%016X-0x%016X]" % (HEAP_ADDRESS, HEAP_ADDRESS + HEAP_SIZE))
```

输出：

```bash
Heap: allocating 0x18-byte chunk @ 0x0000000000601000
input x0=0x18, output ret: 0x601000
```

模拟malloc分配出内存，供后续使用。

## 模拟free释放内存

此处模拟free去释放内存，其实就是参考自己的[模拟调用子函数的框架](../../summary_note/call_other_func/README.md)，然后加上，其实就一行代码`ret`而已。

相关部分代码是：

```py
#-------------------- emulate free --------------------
emulateFreeOpcode = b"\xC0\x03\x5F\xD6" # current only ret=0xC0035FD6
gEmulateFreeCodeSize = len(emulateFreeOpcode)


EMULATE_FREE_CODE_START = (2 * 1024 * 1024) + (128 * 1024)
EMULATE_FREE_CODE_END = EMULATE_FREE_CODE_START + gEmulateFreeCodeSize


FREE_JUMP_ADDR = 0x69B88
FREE_JUMP_VALUE = EMULATE_FREE_CODE_START + 2
FREE_JUMP_SIZE = 8

...

def hook_code(mu, address, size, user_data):
...
    if pc == EMULATE_FREE_CODE_START:
        address = mu.reg_read(UC_ARM64_REG_X0)
        print("emulateFree: input address=0x%x" % (address))
...


print("\t\t\t  [0x%08X-0x%08X]   emulateFree jump" % (FREE_JUMP_ADDR, FREE_JUMP_ADDR + FREE_JUMP_SIZE))

print("\t\t\t  [0x%08X-0x%08X] func: emulateFree" % (EMULATE_FREE_CODE_START, EMULATE_FREE_CODE_END))

        # for emuleateFree
        writeMemory(EMULATE_FREE_CODE_START, emulateFreeOpcode, gEmulateFreeCodeSize)
        writeMemory(FREE_JUMP_ADDR, FREE_JUMP_VALUE, FREE_JUMP_SIZE) # <+256>: 0A DB 6A F8  -> ldr     x10, [x24, w10, sxtw #3]
```

log输出是：

```bash
Mapped memory: Code     [0x00010000-0x00410000]
                          [0x00010000-0x000124C8] func: ___lldb_unnamed_symbol2575$$akd
                          [0x00031220-0x00033450]   fix br err: x9SmallOffset
                          [0x00068020-0x00069B80]   fix br err: x10AbsFuncAddrWithOffset
                          [0x00069B88-0x00069B90]   emulateFree jump
                          [0x00069BC0-0x00069BC8]   emulateAkdFunc2567 jump
                          [0x00069BD8-0x00069BE0]   emulateMalloc jump
                          [0x00069BE8-0x00069BF0]   line 7392 jump
                          [0x00069C08-0x00069C10]   emulateDemalloc jump
                          [0x00200000-0x00200004] func: emulateMalloc
                          [0x00220000-0x00220004] func: emulateFree
                          [0x00280000-0x00280004] func: emulateAkdFunc2567
Mapped memory: Libc     [0x00500000-0x00580000]
Mapped memory: Heap     [0x00600000-0x00700000]
Mapped memory: Stack    [0x00700000-0x00800000]
Mapped memory: Args     [0x00800000-0x00810000]
...
writeMemory: memAddr=0x220000, newValue=0xc0035fd6, byteLen=4
 >> has write newValueBytes=b'\xc0\x03_\xd6' to address=0x220000
writeMemory: memAddr=0x69B88, newValue=0x0000000000220002, byteLen=8
 >> has write newValueBytes=b'\x02\x00"\x00\x00\x00\x00\x00' to address=0x69B88
...
=== 0x00010100  <+256>: 0A DB 6A F8  -> ldr     x10, [x24, w10, sxtw #3]
    debug: PC=0x10100: x24=0x0000000000069B80, w10=0x00000001
 << Memory READ at 0x69B88, size=8, rawValueLittleEndian=0x0200220000000000, pc=0x10100
=== 0x00010104  <+260>: 5B 09 00 D1  -> sub     x27, x10, #2
    debug: PC=0x10104: x10=0x0000000000220002
=== 0x00010108  <+264>: 56 F9 95 12  -> movn    w22, #0xafca
    debug: PC=0x10108: x27=0x0000000000220000
```

之后输出：

```bash
=== 0x0001244C <+9292>: F3 03 10 AA  -> mov     x19, x16
    debug: PC=0x1244C: x16=0xD5709BDDEAB9B930
=== 0x00012450 <+9296>: 60 03 3F D6  -> blr     x27
    debug: PC=0x12450: x27=0x0000000000220000
>>> Tracing basic block at 0x220000, block size = 0x4
=== 0x00220000 <+2162688>: C0 03 5F D6  -> ret
emulateFree: input address=0x604000
```

跳转到了此处的`free`，且传入的地址，是之前`malloc`出来的地址：`0x604000`，即可。

## 模拟vm_deallocate释放内存

最后去用代码模拟demalloc释放内存：

```py
def readMemory(memAddr, byteNum, endian="little", signed=False):
    """read out value from memory"""
    global uc
    readoutRawValue = uc.mem_read(memAddr, byteNum)
    print(" >> readoutRawValue hex=0x%s" % readoutRawValue.hex())
    readoutValueLong = int.from_bytes(readoutRawValue, endian, signed=signed)
    print(" >> readoutValueLong=0x%016X" % readoutValueLong)
    return readoutValueLong

def writeMemory(memAddr, newValue, byteLen):
    """
        for ARM64 little endian, write new value into memory address
        memAddr: memory address to write
        newValue: value to write
        byteLen: 4 / 8
    """
    global uc

    valueFormat = "0x%016X" if byteLen == 8 else "0x%08X"
    if isinstance(newValue, bytes):
        print("writeMemory: memAddr=0x%X, newValue=0x%s, byteLen=%d" % (memAddr, newValue.hex(), byteLen))
        newValueBytes = newValue
    else:
        valueStr = valueFormat % newValue
        print("writeMemory: memAddr=0x%X, newValue=%s, byteLen=%d" % (memAddr, valueStr, byteLen))
        newValueBytes = newValue.to_bytes(byteLen, "little")
    uc.mem_write(memAddr, newValueBytes)
    print(" >> has write newValueBytes=%s to address=0x%X" % (newValueBytes, memAddr))

#-------------------- emulate demalloc --------------------
emulateDemallocOpcode = b"\xC0\x03\x5F\xD6" # current only ret=0xC0035FD6
gEmulateDemallocCodeSize = len(emulateDemallocOpcode)

EMULATE_DEMALLOC_CODE_START = (2 * 1024 * 1024) + (256 * 1024)
EMULATE_DEMALLOC_CODE_END = EMULATE_DEMALLOC_CODE_START + gEmulateDemallocCodeSize

DEMALLOC_JUMP_ADDR = 0x69C08
DEMALLOC_JUMP_VALUE = EMULATE_DEMALLOC_CODE_START + 2
DEMALLOC_JUMP_SIZE = 8

...

def hook_code(mu, address, size, user_data):
...
    if pc == EMULATE_DEMALLOC_CODE_START:
        targetTask = mu.reg_read(UC_ARM64_REG_X0)
        address = mu.reg_read(UC_ARM64_REG_X1)
        size = mu.reg_read(UC_ARM64_REG_X2)
        # zeroValue = 0
        # zeroValueBytes = zeroValue.to_bytes(size, "little")
        if (address > 0) and (size > 0):
            writeMemory(address, 0, size)
        print("emulateDemalloc: input targetTask=0x%X,address=0x%X,size=%d=0x%X" % (targetTask, address, size, size))
        gNoUse = 1
...
        print("\t\t\t  [0x%08X-0x%08X]   emulateDemalloc jump" % (DEMALLOC_JUMP_ADDR, DEMALLOC_JUMP_ADDR + DEMALLOC_JUMP_SIZE))
...
        # for emuleateDemalloc
        writeMemory(EMULATE_DEMALLOC_CODE_START, emulateDemallocOpcode, gEmulateDemallocCodeSize)
        writeMemory(DEMALLOC_JUMP_ADDR, DEMALLOC_JUMP_VALUE, DEMALLOC_JUMP_SIZE) # <+7420>: 28 D9 68 F8  -> ldr     x8, [x9, w8, sxtw #3]
```

即可去模拟demalloc去释放内存：

此处只是设置对应内存地址范围内的值都是0

此处输出log：

```bash
=== 0x00011CE0 <+7392>: 28 D9 68 F8  -> ldr     x8, [x9, w8, sxtw #3]
    debug: PC=0x11CE0: w8=0x0000000D, x9=0x0000000000069B80
 << Memory READ at 0x69BE8, size=8, rawValueLittleEndian=0x0200080000000000, pc=0x11CE0
=== 0x00011CE4 <+7396>: 00 E1 5F B8  -> ldur    w0, [x8, #-2]
    debug: PC=0x11CE4: x8=0x0000000000080002
 << Memory READ at 0x80000, size=4, rawValueLittleEndian=0x03020000, pc=0x11CE4
=== 0x00011CE8 <+7400>: E1 3B 40 F9  -> ldr     x1, [sp, #0x70]
 << Memory READ at 0x77FF80, size=8, rawValueLittleEndian=0x0000000000000000, pc=0x11CE8
=== 0x00011CEC <+7404>: E2 6F 40 B9  -> ldr     w2, [sp, #0x6c]
 << Memory READ at 0x77FF7C, size=4, rawValueLittleEndian=0x00000000, pc=0x11CEC
=== 0x00011CF0 <+7408>: 48 3F 00 51  -> sub     w8, w26, #0xf
=== 0x00011CF4 <+7412>: FA 50 8B 52  -> movz    w26, #0x5a87
=== 0x00011CF8 <+7416>: 9A 84 AD 72  -> movk    w26, #0x6c24, lsl #16
=== 0x00011CFC <+7420>: 28 D9 68 F8  -> ldr     x8, [x9, w8, sxtw #3]
    debug: PC=0x11CFC: w8=0x00000011, x9=0x0000000000069B80
 << Memory READ at 0x69C08, size=8, rawValueLittleEndian=0x0200240000000000, pc=0x11CFC
=== 0x00011D00 <+7424>: 08 09 00 D1  -> sub     x8, x8, #2
    debug: PC=0x11D00: x8=0x0000000000240002
=== 0x00011D04 <+7428>: 00 01 3F D6  -> blr     x8
>>> Tracing basic block at 0x240000, block size = 0x4
=== 0x00240000 <+2293760>: C0 03 5F D6  -> ret
emulateDemalloc: input targetTask=0x203,address=0x0,size=0=0x0
>>> Tracing basic block at 0x11d08, block size = 0x50
=== 0x00011D08 <+7432>: F1 43 45 A9  -> ldp     x17, x16, [sp, #0x50]
 << Memory READ at 0x77FF60, size=8, rawValueLittleEndian=0x0010600000000000, pc=0x11D08
 << Memory READ at 0x77FF68, size=8, rawValueLittleEndian=0x30b9b9eadd9b70d5, pc=0x11D08
...
```

即可顺利继续运行。

其中此处：

* `address`=`0x0`
* `size`=`0`=`0x0`

-》导致效果是：实际上没有去清空内存值为`0`

-》原因是：

* `address`=`0x0`=`x1`=`[sp + 0x70]`
* `size`=`0`=`0x0`=`w2`=`[sp + -0x6C]`

对应的sp堆栈的位置中，没有去设置对应的值，所以都是0
