# 模拟akd函数symbol2575

TODO：

再去把相关附件文件 也贴出来，和加上具体解释，或者指向之前的具体章节有详细解释。

---

## 文件: `emulate_akd_getIDMSRoutingInfo.py`

```py
# Function: Use Unicorn to emulate akd +[AKADIProxy getIDMSRoutingInfo:forDSID:] internal implementation function code to running
#   arm64e: ___lldb_unnamed_symbol2540$$akd
#   arm64: ___lldb_unnamed_symbol2575$$akd
# Author: Crifan Li
# Update: 20220608

from __future__ import print_function
import re
from unicorn import *
from unicorn.arm64_const import *
from unicorn.arm_const import *
# import binascii
from capstone import *
from capstone.arm64 import *

from libs.UnicornSimpleHeap import UnicornSimpleHeap

import os
from datetime import datetime,timedelta
import logging
from libs.crifan import crifanLogging

def getCurDatetimeStr(outputFormat="%Y%m%d_%H%M%S"):
    """
    get current datetime then format to string


    eg:
        20171111_220722


    :param outputFormat: datetime output format
    :return: current datetime formatted string
    """
    curDatetime = datetime.now() # 2017-11-11 22:07:22.705101
    curDatetimeStr = curDatetime.strftime(format=outputFormat) #'20171111_220722'
    return curDatetimeStr


def getFilenameNoPointSuffix(curFilePath):
    """Get current filename without point and suffix


    Args:
        curFilePath (str): current file path. Normally can use __file__
    Returns:
        str, file name without .xxx
    Raises:
    Examples:
        input: /Users/xxx/pymitmdump/mitmdumpOtherApi.py
        output: mitmdumpOtherApi
    """
    root, pointSuffix = os.path.splitext(curFilePath)
    curFilenameNoSuffix = root.split(os.path.sep)[-1]
    return curFilenameNoSuffix

################################################################################
# Global Variable
################################################################################

# current all code is 4 byte -> single line arm code
# gSingleLineCode = True

# only for debug
gNoUse = 0

BYTES_PER_LINE = 4

uc = None
ucHeap = None

################################################################################
# Util Function
################################################################################

def readBinFileBytes(inputFilePath):
    fileBytes = None
    with open(inputFilePath, "rb") as f:
        fileBytes = f.read()
    return fileBytes

def readMemory(memAddr, byteNum, endian="little", signed=False):
    """read out value from memory"""
    global uc
    readoutRawValue = uc.mem_read(memAddr, byteNum)
    logging.info(" >> readoutRawValue hex=0x%s", readoutRawValue.hex())
    readoutValueLong = int.from_bytes(readoutRawValue, endian, signed=signed)
    logging.info(" >> readoutValueLong=0x%016X", readoutValueLong)
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
        logging.info("writeMemory: memAddr=0x%X, newValue=0x%s, byteLen=%d", memAddr, newValue.hex(), byteLen)
        newValueBytes = newValue
    else:
        valueStr = valueFormat % newValue
        logging.info("writeMemory: memAddr=0x%X, newValue=%s, byteLen=%d", memAddr, valueStr, byteLen)
        newValueBytes = newValue.to_bytes(byteLen, "little")
    uc.mem_write(memAddr, newValueBytes)
    logging.info(" >> has write newValueBytes=%s to address=0x%X", newValueBytes, memAddr)

    # # for debug: verify write is OK or not
    # readoutValue = uc.mem_read(memAddr, byteLen)
    # logging.info("for address 0x%X, readoutValue hex=0x%s", memAddr, readoutValue.hex()))
    # # logging.info("readoutValue hexlify=%b", binascii.hexlify(readoutValue))
    # readoutValueLong = int.from_bytes(readoutValue, "little", signed=False)
    # logging.info("readoutValueLong=0x%x", readoutValueLong)
    # # if readoutValue == newValue:
    # if readoutValueLong == newValue:
    #     logging.info("=== Write and read back OK")
    # else:
    #     logging.info("!!! Write and read back Failed")

def shouldStopEmulate(curPc, decodedInsn):
    isShouldStop = False
    # isRetInsn = decodedInsn.mnemonic == "ret"
    isRetInsn = re.match("^ret", decodedInsn.mnemonic) # support: ret/retaa/retab/...
    if isRetInsn:
        isPcInsideMainCode = (curPc >= CODE_ADDRESS) and (curPc < CODE_ADDRESS_REAL_END)
        isShouldStop = isRetInsn and isPcInsideMainCode

    return isShouldStop

# debug related

def bytesToOpcodeStr(curBytes):
    opcodeByteStr = ''.join('{:02X} '.format(eachByte) for eachByte in curBytes)
    return opcodeByteStr

def dbgAddressRangeStr(startAddress, size):
    endAddress = startAddress + (size - 1)
    addrRangeStr = "0x%X:0x%X" % (startAddress, endAddress)
    return addrRangeStr

################################################################################
# Main
################################################################################

# init logging
curLogFile = "%s_%s.log" % (getFilenameNoPointSuffix(__file__), getCurDatetimeStr())
# 'TIAutoOrder_20221201_174058.log'
curLogFullFile = os.path.join("debug", "log", curLogFile) # 'emulate_akd_getIDMSRoutingInfo_20230529_094920.log'
# 'debug\\log\\TIAutoOrder_20221201_174112.log'
crifanLogging.loggingInit(filename=curLogFullFile)
# crifanLogging.testLogging()
# logging.debug("debug log")
# logging.info("info log")
logging.info("Output log to %s", curLogFullFile)


# Init Capstone instance
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
cs.detail = True

# Init Unicorn

# code to be emulated

# for arm64e: ___lldb_unnamed_symbol2540$$akd
# akd_symbol2540_FilePath = "input/akd_getIDMSRoutingInfo/arm64e/akd_arm64e_symbol2540.bin"
# akd_symbol2540_FilePath = "input/akd_getIDMSRoutingInfo/arm64e/akd_arm64e_symbol2540_noCanary.bin"
# akd_symbol2540_FilePath = "input/akd_getIDMSRoutingInfo/arm64e/akd_arm64e_symbol2540_noCanary_braaToBr.bin"
# b"\x7F\x23\x03\xD5..."

# for arm64: ___lldb_unnamed_symbol2575$$akd
akd_symbol2575_FilePath = "input/akd_getIDMSRoutingInfo/arm64/akd_arm64_symbol2575.bin"
logging.info("akd_symbol2575_FilePath=%s", akd_symbol2575_FilePath)
ARM64_CODE_akd_symbol2575 = readBinFileBytes(akd_symbol2575_FilePath) # b'\xff\xc3\x03\xd1\xfco\t\xa9\xfag\n\xa9\xf8_\x0b\xa9\xf6W\x0c\xa9\xf4O
gCodeSizeReal = len(ARM64_CODE_akd_symbol2575)
logging.info("gCodeSizeReal=%d == 0x%X", gCodeSizeReal, gCodeSizeReal)
# ___lldb_unnamed_symbol2540: 10064 == 0x2750
# ___lldb_unnamed_symbol2575 == sub_1000A0460: 9416 == 0x24C8

#-------------------- Code --------------------

# memory address where emulation starts
CODE_ADDRESS = 0x10000
logging.info("CODE_ADDRESS=0x%X", CODE_ADDRESS)

# code size: 4MB
CODE_SIZE = 4 * 1024 * 1024
logging.info("CODE_SIZE=0x%X", CODE_SIZE)
CODE_ADDRESS_END = (CODE_ADDRESS + CODE_SIZE) # 0x00410000
logging.info("CODE_ADDRESS_END=0x%X", CODE_ADDRESS_END)

CODE_ADDRESS_REAL_END = CODE_ADDRESS + gCodeSizeReal
logging.info("CODE_ADDRESS_REAL_END=0x%X", CODE_ADDRESS_REAL_END)
# CODE_ADDRESS_REAL_LAST_LINE = CODE_ADDRESS_REAL_END - 4
# logging.info("CODE_ADDRESS_REAL_LAST_LINE=0x%X", CODE_ADDRESS_REAL_LAST_LINE)

#-------------------- Try fix br jump UC_ERR_MAP --------------------

x9SmallOffsetFile = "input/akd_getIDMSRoutingInfo/arm64/lldb_memory/akd_arm64_data_0x100d91680_0x100d938b0_x9SmallOffset.bin"
logging.info("x9SmallOffsetFile=%s", x9SmallOffsetFile)
x9SmallOffsetBytes = readBinFileBytes(x9SmallOffsetFile)
x9SmallOffsetBytesLen = len(x9SmallOffsetBytes) # b' \x00\x00\x00\xc0\x00\x00\x00\\\x00\x00\x00D\x00\x00\x00h\x00\x00\x00H\x01 ...
# logging.info("x9SmallOffsetBytesLen=%d=0x%X", x9SmallOffsetBytesLen, x9SmallOffsetBytesLen))

x9SmallOffsetStartAddress = CODE_ADDRESS + 0x21220
# logging.info("x9SmallOffsetStartAddress=0x%X", x9SmallOffsetStartAddress)
x9SmallOffsetEndAddress = x9SmallOffsetStartAddress + x9SmallOffsetBytesLen
# logging.info("x9SmallOffsetEndAddress=0x%X", x9SmallOffsetEndAddress)

# x10AbsFuncAddrWithOffsetFile = "input/akd_getIDMSRoutingInfo/arm64/lldb_memory/akd_arm64_data_0x100dc8480_0x100dc9fe0_x10AbsFuncAddrWithOffset.bin"
x10AbsFuncAddrWithOffsetFile = "input/akd_getIDMSRoutingInfo/arm64/lldb_memory/akd_arm64_data_x10EmulateAddr.bin"
logging.info("x10AbsFuncAddrWithOffsetFile=%s", x10AbsFuncAddrWithOffsetFile)
x10AbsFuncAddrWithOffsetBytes = readBinFileBytes(x10AbsFuncAddrWithOffsetFile)
# x10AbsFuncAddrWithOffsetBytesLen = len(x10AbsFuncAddrWithOffsetBytes) # b'\xa8F\xd6\x00\x01\x00\x00\x00\x10G\xd6\x00\x01\x00\x00\x00lG\xd6\x00\x01 ...
x10AbsFuncAddrWithOffsetBytesLen = len(x10AbsFuncAddrWithOffsetBytes) # b'HB\x00\x00\x00\x00\x00\x00\xb0B\x00\x00\x00\x00\x00\x00\x0cC\x00\x00\x00\ ...
# logging.info("x10AbsFuncAddrWithOffsetBytesLen=%d=0x%X", x10AbsFuncAddrWithOffsetBytesLen, x10AbsFuncAddrWithOffsetBytesLen)) # x10AbsFuncAddrWithOffsetBytesLen=7008=0x1B60

x10AbsFuncAddrWithOffsetStartAddress = CODE_ADDRESS + 0x58020
# logging.info("x10AbsFuncAddrWithOffsetStartAddress=0x%X", x10AbsFuncAddrWithOffsetStartAddress)
x10AbsFuncAddrWithOffsetEndAddress = x10AbsFuncAddrWithOffsetStartAddress + x10AbsFuncAddrWithOffsetBytesLen
# logging.info("x10AbsFuncAddrWithOffsetEndAddress=0x%X", x10AbsFuncAddrWithOffsetEndAddress)

#-------------------- emulate malloc --------------------
emulateMallocOpcode = b"\xC0\x03\x5F\xD6" # current only ret=0xC0035FD6
gEmulateMallocCodeSize = len(emulateMallocOpcode)

EMULATE_MALLOC_CODE_START = 2 * 1024 * 1024
EMULATE_MALLOC_CODE_END = EMULATE_MALLOC_CODE_START + gEmulateMallocCodeSize

MALLOC_JUMP_ADDR = 0x69BD8
MALLOC_JUMP_VALUE = EMULATE_MALLOC_CODE_START + 2
MALLOC_JUMP_SIZE = 8

#-------------------- emulate free --------------------
emulateFreeOpcode = b"\xC0\x03\x5F\xD6" # current only ret=0xC0035FD6
gEmulateFreeCodeSize = len(emulateFreeOpcode)

EMULATE_FREE_CODE_START = (2 * 1024 * 1024) + (128 * 1024)
EMULATE_FREE_CODE_END = EMULATE_FREE_CODE_START + gEmulateFreeCodeSize

FREE_JUMP_ADDR = 0x69B88
FREE_JUMP_VALUE = EMULATE_FREE_CODE_START + 2
FREE_JUMP_SIZE = 8

#-------------------- emulate demalloc --------------------

emulateDemallocOpcode = b"\xC0\x03\x5F\xD6" # current only ret=0xC0035FD6
gEmulateDemallocCodeSize = len(emulateDemallocOpcode)

EMULATE_DEMALLOC_CODE_START = (2 * 1024 * 1024) + (256 * 1024)
EMULATE_DEMALLOC_CODE_END = EMULATE_DEMALLOC_CODE_START + gEmulateDemallocCodeSize

DEMALLOC_JUMP_ADDR = 0x69C08
DEMALLOC_JUMP_VALUE = EMULATE_DEMALLOC_CODE_START + 2
DEMALLOC_JUMP_SIZE = 8

#-------------------- emulate (call sub function) ___lldb_unnamed_symbol2567$$akd --------------------
emulateAkdFunc2567Opcode = b"\xC0\x03\x5F\xD6" # current only ret=0xC0035FD6
gEmulateAkdFunc2567Size = len(emulateAkdFunc2567Opcode)

EMULATE_AKD_FUNC_2567_START = (2 * 1024 * 1024) + (512 * 1024)
EMULATE_AKD_FUNC_2567_END = EMULATE_AKD_FUNC_2567_START + gEmulateAkdFunc2567Size

AKD_FUNC_2567_JUMP_ADDR = 0x69BC0
AKD_FUNC_2567_JUMP_VALUE = EMULATE_AKD_FUNC_2567_START + 3
AKD_FUNC_2567_JUMP_SIZE = 8

#-------------------- misc jump address and value --------------------

LINE_7396_STORE_VALUE_ADDR = 0x80000

LINE_7392_JUMP_ADDR = 0x69BE8
LINE_7392_JUMP_VALUE = LINE_7396_STORE_VALUE_ADDR + 2
LINE_7392_JUMP_SIZE = 8


#-------------------- __stack_chk_guard --------------------
# ->  0x10469c484 <+36>: ldr    x8, #0x54354              ; (void *)0x00000001f13db058: __stack_chk_guard
#       x8 = 0x00000001f13db058  libsystem_c.dylib`__stack_chk_guard
LIBC_ADDRESS = 5 * 1024 * 1024
LIBC_SIZE = 512 * 1024
STACK_CHECK_GUADR_ADDRESS = LIBC_ADDRESS + 0xB058

#-------------------- Heap --------------------

HEAP_ADDRESS = 6 * 1024 * 1024
HEAP_SIZE = 1 * 1024 * 1024

HEAP_ADDRESS_END = HEAP_ADDRESS + HEAP_SIZE
HEAP_ADDRESS_LAST_BYTE = HEAP_ADDRESS_END - 1

#-------------------- Stack --------------------
# Stack: from High address to lower address ?
STACK_ADDRESS = 7 * 1024 * 1024
STACK_SIZE = 1 * 1024 * 1024
STACK_HALF_SIZE = (int)(STACK_SIZE / 2)

# STACK_ADDRESS_END = STACK_ADDRESS - STACK_SIZE # 8 * 1024 * 1024
# STACK_SP = STACK_ADDRESS - 0x8 # ARM64: offset 0x8

# STACK_TOP = STACK_ADDRESS + STACK_SIZE
STACK_TOP = STACK_ADDRESS + STACK_HALF_SIZE
STACK_SP = STACK_TOP

FP_X29_VALUE = STACK_SP + 0x30

LR_INIT_ADDRESS = CODE_ADDRESS

#-------------------- Args --------------------

# memory address for arguments
ARGS_ADDRESS = 8 * 1024 * 1024
ARGS_SIZE =  0x10000

# init args value
ARG_routingInfoPtr = ARGS_ADDRESS
ARG_DSID = 0xfffffffffffffffe

#-------------------- Unicorn Hook --------------------

# callback for tracing basic blocks
def hook_block(mu, address, size, user_data):
    logging.info("@@@ Tracing basic block at 0x%x, block size = 0x%x", address, size)

# callback for tracing instructions
def hook_code(mu, address, size, user_data):
    global ucHeap

    pc = mu.reg_read(UC_ARM64_REG_PC)

    # logging.info(">>> Tracing instruction at 0x%x, instruction size = 0x%x", address, size)
    lineCount = int(size / BYTES_PER_LINE)
    for curLineIdx in range(lineCount):
        startAddress = address + curLineIdx * BYTES_PER_LINE
        codeOffset = startAddress - CODE_ADDRESS
        opcodeBytes = mu.mem_read(startAddress, BYTES_PER_LINE)
        opcodeByteStr = bytesToOpcodeStr(opcodeBytes)
        decodedInsnGenerator = cs.disasm(opcodeBytes, address)
        # if gSingleLineCode:
        for eachDecodedInsn in decodedInsnGenerator:
            eachInstructionName = eachDecodedInsn.mnemonic
            offsetStr = "<+%d>" % codeOffset
            logging.info("--- 0x%08X %7s: %s -> %s\t%s", startAddress, offsetStr, opcodeByteStr, eachInstructionName, eachDecodedInsn.op_str)
            if shouldStopEmulate(pc, eachDecodedInsn):
                mu.emu_stop()
                logging.info("Emulate done!")

            gNoUse = 1

    # for debug
    toLogDict = {
        0x00010070: ["x25"],
        0x00010074: ["cpsr", "w9", "x9", "x25"],
        0x00010078: ["cpsr", "x9"],
        0x00010080: ["cpsr", "x9", "x10"],
        0x00010084: ["cpsr", "x9"],
        0x00010100: ["x24", "w10"],
        0x00010104: ["x10"],
        0x00010108: ["x27"],
        0x00200000: ["cpsr", "x0", "x1"],
        0x000100D0: ["x0", "x1"],
        0x000100F8: ["x9", "x10"],
        0x000100FC: ["x9"],
        0x0001011C: ["x9"],
        0x0001016C: ["w8", "x25"],
        0x00010170: ["x8"],
        0x00010178: ["x10"],
        0x00011124: ["w24"],
        0x00011128: ["w8"],
        0x0001112C: ["x9"],
        0x00011150: ["x8", "x9"],
        0x00011160: ["x0", "x1", "x2", "x3", "x4", "x26"],
        0x00011164: ["x0"],
        0x000118B4: ["x0", "x22"],
        0x000118B8: ["x0", "x9"],
        0x00011CE0: ["w8", "x9"],
        0x00011CE4: ["x8"],
        0x00011CFC: ["w8", "x9"],
        0x00011D00: ["x8"],
        0x00012138: ["sp"],
        0x00012430: ["x25", "w8"],
        0x00012434: ["x8"],
        0x0001243C: ["x8", "x9"],
        0x00012440: ["x8"],
        0x0001244C: ["x16"],
        0x00012450: ["x27"],
    }

    # common debug

    cpsr = mu.reg_read(UC_ARM_REG_CPSR)
    sp = mu.reg_read(UC_ARM_REG_SP)

    w8 = mu.reg_read(UC_ARM64_REG_W8)
    w9 = mu.reg_read(UC_ARM64_REG_W9)
    w10 = mu.reg_read(UC_ARM64_REG_W10)
    w11 = mu.reg_read(UC_ARM64_REG_W11)
    w24 = mu.reg_read(UC_ARM64_REG_W24)
    w26 = mu.reg_read(UC_ARM64_REG_W26)

    x0 = mu.reg_read(UC_ARM64_REG_X0)
    x1 = mu.reg_read(UC_ARM64_REG_X1)
    x2 = mu.reg_read(UC_ARM64_REG_X2)
    x3 = mu.reg_read(UC_ARM64_REG_X3)
    x4 = mu.reg_read(UC_ARM64_REG_X4)
    x8 = mu.reg_read(UC_ARM64_REG_X8)
    x9 = mu.reg_read(UC_ARM64_REG_X9)
    x10 = mu.reg_read(UC_ARM64_REG_X10)
    x16 = mu.reg_read(UC_ARM64_REG_X16)
    x22 = mu.reg_read(UC_ARM64_REG_X22)
    x24 = mu.reg_read(UC_ARM64_REG_X24)
    x25 = mu.reg_read(UC_ARM64_REG_X25)
    x26 = mu.reg_read(UC_ARM64_REG_X26)
    x27 = mu.reg_read(UC_ARM64_REG_X27)

    regNameToValueDict = {
        "cpsr": cpsr,
        "sp": sp,

        "w8": w8,
        "w9": w9,
        "w10": w10,
        "w11": w11,
        "w24": w24,
        "w26": w26,

        "x0": x0,
        "x1": x1,
        "x2": x2,
        "x3": x3,
        "x4": x4,
        "x8": x8,
        "x9": x9,
        "x10": x10,
        "x16": x16,
        "x22": x22,
        "x24": x24,
        "x25": x25,
        "x26": x26,
        "x27": x27,
    }

    toLogAddressList = toLogDict.keys()
    if pc in toLogAddressList:
        toLogRegList = toLogDict[pc]
        initLogStr = "\tdebug: PC=0x%X: " % pc
        regLogStrList = []
        for eachRegName in toLogRegList:
            eachReg = regNameToValueDict[eachRegName]
            isWordReg = re.match("x\d+", eachRegName)
            logFormt = "0x%016X" if isWordReg else "0x%08X"
            curRegValueStr = logFormt % eachReg
            curRegLogStr = "%s=%s" % (eachRegName, curRegValueStr)
            regLogStrList.append(curRegLogStr)
        allRegStr = ", ".join(regLogStrList)
        wholeLogStr = initLogStr + allRegStr
        logging.info("%s", wholeLogStr)
        gNoUse = 1

    # for emulateMalloc
    # if pc == 0x00200000:
    if pc == EMULATE_MALLOC_CODE_START:
        mallocSize = mu.reg_read(UC_ARM64_REG_X0)
        newAddrPtr = ucHeap.malloc(mallocSize)
        mu.reg_write(UC_ARM64_REG_X0, newAddrPtr)
        logging.info("\temulateMalloc: input x0=0x%x, output ret: 0x%x", mallocSize, newAddrPtr)
        gNoUse = 1

    if pc == EMULATE_FREE_CODE_START:
        address = mu.reg_read(UC_ARM64_REG_X0)
        logging.info("\temulateFree: input address=0x%x", address)
        gNoUse = 1

    if pc == EMULATE_DEMALLOC_CODE_START:
        targetTask = mu.reg_read(UC_ARM64_REG_X0)
        address = mu.reg_read(UC_ARM64_REG_X1)
        size = mu.reg_read(UC_ARM64_REG_X2)
        # zeroValue = 0
        # zeroValueBytes = zeroValue.to_bytes(size, "little")
        if (address > 0) and (size > 0):
            writeMemory(address, 0, size)
        logging.info("\temulateDemalloc: input targetTask=0x%X,address=0x%X,size=%d=0x%X", targetTask, address, size, size)
        gNoUse = 1

    if pc == EMULATE_AKD_FUNC_2567_START:
        paraX0 = mu.reg_read(UC_ARM64_REG_X0)
        paraX1 = mu.reg_read(UC_ARM64_REG_X1)
        paraX2 = mu.reg_read(UC_ARM64_REG_X2)
        paraX3 = mu.reg_read(UC_ARM64_REG_X3)
        paraX4 = mu.reg_read(UC_ARM64_REG_X4)

        realDebuggedRetValue = 0
        mu.reg_write(UC_ARM64_REG_X0, realDebuggedRetValue)
        logging.info("\temulateAkdFunc2567: input x0=0x%x,x1=0x%x,x2=0x%x,x3=0x%x,x4=0x%x, output ret: 0x%x", paraX0,paraX1,paraX2,paraX3,paraX4, realDebuggedRetValue)
        gNoUse = 1
    
    # if pc == 0x00011754:
    #     logging.info("")

    # if pc == 0x0001010C:
    #     logging.info("")

    if pc == 0x12138:
        spValue = mu.mem_read(sp)
        logging.info("\tspValue=0x%X", spValue)
        gNoUse = 1

    if pc == 0x1213C:
        gNoUse = 1

    if pc == 0x118B4:
        gNoUse = 1

    if pc == 0x118B8:
        gNoUse = 1


def hook_unmapped(mu, access, address, size, value, context):
    pc = mu.reg_read(UC_ARM64_REG_PC)
    logging.info("!!! Memory UNMAPPED at 0x%X size=0x%x, access(r/w)=%d, value=0x%X, PC=0x%X", address, size, access, value, pc)
    mu.emu_stop()
    return True

def hook_mem_write(uc, access, address, size, value, user_data):
    if address == ARG_routingInfoPtr:
        logging.info("write ARG_routingInfoPtr")
        gNoUse = 1

    pc = uc.reg_read(UC_ARM64_REG_PC)
    logging.info(" >> Memory WRITE at 0x%X, size=%u, value=0x%X, PC=0x%X", address, size, value, pc)
    # logging.info(" >> Memory WRITE at 0x%X, size=%u, value=0x%s, PC=0x%X", address, size, value.to_bytes(8, "little").hex(), pc))
    gNoUse = 1

def hook_mem_read(uc, access, address, size, value, user_data):
    if address == ARG_routingInfoPtr:
        logging.info("read ARG_routingInfoPtr")
        gNoUse = 1

    pc = uc.reg_read(UC_ARM64_REG_PC)
    data = uc.mem_read(address, size)
    logging.info(" << Memory READ at 0x%X, size=%u, rawValueLittleEndian=0x%s, pc=0x%X", address, size, data.hex(), pc)
    gNoUse = 1

    dataLong = int.from_bytes(data, "little", signed=False)
    if dataLong == 0:
        logging.info(" !! Memory read out 0 -> possbile abnormal -> need attention")
        gNoUse = 1


# def hook_mem_fetch(uc, access, address, size, value, user_data):
#     pc = uc.reg_read(UC_ARM64_REG_PC)
#     logging.info(" >> Memory FETCH at 0x%X, size= %u, value= 0x%X, PC= 0x%X", address, size, value, pc))
#     gNoUse = 1

#-------------------- Unicorn main --------------------

# Emulate arm function running
def emulate_akd_arm64_symbol2575():
    global uc, ucHeap
    logging.info("Emulate arm64 sub_1000A0460 == ___lldb_unnamed_symbol2575$$akd function running")
    try:
        # Initialize emulator in ARM mode
        # mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM + UC_MODE_LITTLE_ENDIAN)
        uc = mu
        # map code memory for this emulation
        mu.mem_map(CODE_ADDRESS, CODE_SIZE)
        logging.info("Mapped memory: Code\t[0x%08X-0x%08X]", CODE_ADDRESS, CODE_ADDRESS + CODE_SIZE)
        # code sub area
        logging.info("\t\t\t  [0x%08X-0x%08X] func: ___lldb_unnamed_symbol2575$$akd", CODE_ADDRESS, CODE_ADDRESS_REAL_END)
        logging.info("\t\t\t  [0x%08X-0x%08X]   fix br err: x9SmallOffset", x9SmallOffsetStartAddress, x9SmallOffsetEndAddress)
        logging.info("\t\t\t  [0x%08X-0x%08X]   fix br err: x10AbsFuncAddrWithOffset", x10AbsFuncAddrWithOffsetStartAddress, x10AbsFuncAddrWithOffsetEndAddress)
        logging.info("\t\t\t  [0x%08X-0x%08X]   emulateFree jump", FREE_JUMP_ADDR, FREE_JUMP_ADDR + FREE_JUMP_SIZE)
        logging.info("\t\t\t  [0x%08X-0x%08X]   emulateAkdFunc2567 jump", AKD_FUNC_2567_JUMP_ADDR, AKD_FUNC_2567_JUMP_ADDR + AKD_FUNC_2567_JUMP_SIZE)
        logging.info("\t\t\t  [0x%08X-0x%08X]   emulateMalloc jump", MALLOC_JUMP_ADDR, MALLOC_JUMP_ADDR + MALLOC_JUMP_SIZE)
        logging.info("\t\t\t  [0x%08X-0x%08X]   line 7392 jump", LINE_7392_JUMP_ADDR, LINE_7392_JUMP_ADDR + LINE_7392_JUMP_SIZE)
        logging.info("\t\t\t  [0x%08X-0x%08X]   emulateDemalloc jump", DEMALLOC_JUMP_ADDR, DEMALLOC_JUMP_ADDR + DEMALLOC_JUMP_SIZE)
        logging.info("\t\t\t  [0x%08X-0x%08X] func: emulateMalloc", EMULATE_MALLOC_CODE_START, EMULATE_MALLOC_CODE_END)
        logging.info("\t\t\t  [0x%08X-0x%08X] func: emulateFree", EMULATE_FREE_CODE_START, EMULATE_FREE_CODE_END)
        logging.info("\t\t\t  [0x%08X-0x%08X] func: emulateAkdFunc2567", EMULATE_AKD_FUNC_2567_START, EMULATE_AKD_FUNC_2567_END)

        # map libc, for __stack_chk_guard
        mu.mem_map(LIBC_ADDRESS, LIBC_SIZE)
        logging.info("Mapped memory: Libc\t[0x%08X-0x%08X]", LIBC_ADDRESS, LIBC_ADDRESS + LIBC_SIZE)
        # map heap
        mu.mem_map(HEAP_ADDRESS, HEAP_SIZE)
        logging.info("Mapped memory: Heap\t[0x%08X-0x%08X]", HEAP_ADDRESS, HEAP_ADDRESS + HEAP_SIZE)
        # map stack
        mu.mem_map(STACK_ADDRESS, STACK_SIZE)
        # mu.mem_map(STACK_ADDRESS_END, STACK_SIZE)
        logging.info("Mapped memory: Stack\t[0x%08X-0x%08X]", STACK_ADDRESS, STACK_ADDRESS + STACK_SIZE)
        # map arguments
        mu.mem_map(ARGS_ADDRESS, ARGS_SIZE)
        logging.info("Mapped memory: Args\t[0x%08X-0x%08X]", ARGS_ADDRESS, ARGS_ADDRESS + ARGS_SIZE)

        # init Heap malloc emulation
        ucHeap = UnicornSimpleHeap(uc, HEAP_ADDRESS, HEAP_ADDRESS_LAST_BYTE, debug_print=True)

        # write machine code to be emulated to memory
        # mu.mem_write(CODE_ADDRESS, ARM64_CODE_akd_symbol2540)
        mu.mem_write(CODE_ADDRESS, ARM64_CODE_akd_symbol2575)

        # # for debug: test memory set to 0
        # testAddr = 0x300000
        # testInt = 0x12345678
        # testIntBytes = testInt.to_bytes(8, "little", signed=False)
        # mu.mem_write(testAddr, testIntBytes)
        # readoutInt1 = readMemory(testAddr, 8)
        # logging.info("readoutInt1=0x%x", readoutInt1)
        # writeMemory(testAddr, 0, 3)
        # readoutInt2 = readMemory(testAddr, 8)
        # logging.info("readoutInt2=0x%x", readoutInt2)

        mu.mem_write(x9SmallOffsetStartAddress, x9SmallOffsetBytes)
        logging.info(" >> has write %d=0x%X bytes into memory [0x%X-0x%X]", x9SmallOffsetBytesLen, x9SmallOffsetBytesLen, x9SmallOffsetStartAddress, x9SmallOffsetStartAddress + x9SmallOffsetBytesLen)
        mu.mem_write(x10AbsFuncAddrWithOffsetStartAddress, x10AbsFuncAddrWithOffsetBytes)
        logging.info(" >> has write %d=0x%X bytes into memory [0x%X-0x%X]", x10AbsFuncAddrWithOffsetBytesLen, x10AbsFuncAddrWithOffsetBytesLen, x10AbsFuncAddrWithOffsetStartAddress, x10AbsFuncAddrWithOffsetStartAddress + x10AbsFuncAddrWithOffsetBytesLen)

        # for emuleateMalloc
        writeMemory(EMULATE_MALLOC_CODE_START, emulateMallocOpcode, gEmulateMallocCodeSize)
        # writeMemory(0x69BD8, EMULATE_MALLOC_CODE_START + 2, 8)
        writeMemory(MALLOC_JUMP_ADDR, MALLOC_JUMP_VALUE, MALLOC_JUMP_SIZE)

        # for emuleateFree
        writeMemory(EMULATE_FREE_CODE_START, emulateFreeOpcode, gEmulateFreeCodeSize)
        writeMemory(FREE_JUMP_ADDR, FREE_JUMP_VALUE, FREE_JUMP_SIZE) # <+256>: 0A DB 6A F8  -> ldr     x10, [x24, w10, sxtw #3]

        # for emuleateDemalloc
        writeMemory(EMULATE_DEMALLOC_CODE_START, emulateDemallocOpcode, gEmulateDemallocCodeSize)
        writeMemory(DEMALLOC_JUMP_ADDR, DEMALLOC_JUMP_VALUE, DEMALLOC_JUMP_SIZE) # <+7420>: 28 D9 68 F8  -> ldr     x8, [x9, w8, sxtw #3]

        # for emulateAkdFunc2567
        writeMemory(EMULATE_AKD_FUNC_2567_START, emulateAkdFunc2567Opcode, gEmulateAkdFunc2567Size)
        # writeMemory(0x69BC0, EMULATE_AKD_FUNC_2567_START + 3, 8) # <+4432>: 28 D9 68 F8  -> ldr     x8, [x9, w8, sxtw #3]
        writeMemory(AKD_FUNC_2567_JUMP_ADDR, AKD_FUNC_2567_JUMP_VALUE, AKD_FUNC_2567_JUMP_SIZE) # <+4432>: 28 D9 68 F8  -> ldr     x8, [x9, w8, sxtw #3]

        # initialize some memory

        # for arm64e:
        # writeMemory(0x757DC, 0x0000000100af47c2, 8)
        # writeMemory(0x662FC, 0x237d5780000100A0, 8)

        # for arm64:

        # for __stack_chk_guard
        writeMemory(0x64378, STACK_CHECK_GUADR_ADDRESS, 4)
        writeMemory(0x50B058, 0x75c022d064c70008, 8)

        # Note: following addr and value have been replaced by: x9 and x10, two group addr and values
        # writeMemory(0x32850, 0x00000094, 4)             # <+236>: 29 DB A9 B8  -> ldrsw   x9, [x25, w9, sxtw #2]
        # readMemory(0x32850, 4)
        # writeMemory(0x32870, 0xffffdbc4, 4)     # <+116>: 29 DB A9 B8  -> ldrsw   x9, [x25, w9, sxtw #2]
        # readMemory(0x32870, 4)
        # writeMemory(0x68CF8, CODE_ADDRESS_REAL_END, 8)  # <+124>: EA 63 2C 58  -> ldr     x10, #0x68cf8
        # readMemory(0x68CF8, 8)
        # writeMemory(0x68D00, 0x1008C, 8)        # <+244>: 6A 60 2C 58  -> ldr     x10, #0x68d00
        # readMemory(0x68D00, 8)
        # writeMemory(0x32858, 0xc4, 4)           # <+364>: 28 DB A8 B8  -> ldrsw   x8, [x25, w8, sxtw #2]
        # readMemory(0x32858, 4)
        # writeMemory(0x68D08, 0x10120, 8)        # <+372>: AA 5C 2C 58  -> ldr     x10, #0x68d08
        # readMemory(0x68D08, 8)

        writeMemory(0x69C18, 0x0000000000078dfa, 8) # <+4400>: 36 D9 68 F8  -> ldr     x22, [x9, w8, sxtw #3]
        writeMemory(0x78DF8, 0x0000000000003f07, 8) # <+4404>: C0 EE 5F B8  -> ldr     w0, [x22, #-2]!

        writeMemory(LINE_7392_JUMP_ADDR, LINE_7392_JUMP_VALUE, LINE_7392_JUMP_SIZE) # <+7392>: 28 D9 68 F8  -> ldr     x8, [x9, w8, sxtw #3]
        writeMemory(LINE_7396_STORE_VALUE_ADDR, 0x00000203, 4) # <+7396>: 00 E1 5F B8  -> ldur    w0, [x8, #-2]

        # initialize machine registers

        # # for arm64e arm64e ___lldb_unnamed_symbol2540$$akd
        # mu.reg_write(UC_ARM64_REG_X0, ARG_routingInfoPtr)
        # mu.reg_write(UC_ARM64_REG_X1, ARG_DSID)

        # for current arm64 ___lldb_unnamed_symbol2575$$akd =====
        mu.reg_write(UC_ARM64_REG_X0, ARG_DSID)
        mu.reg_write(UC_ARM64_REG_X1, ARG_routingInfoPtr)

        # mu.reg_write(UC_ARM64_REG_LR, CODE_ADDRESS_END)
        mu.reg_write(UC_ARM64_REG_LR, LR_INIT_ADDRESS)
        
        # initialize stack
        # mu.reg_write(UC_ARM64_REG_SP, STACK_ADDRESS)
        mu.reg_write(UC_ARM64_REG_SP, STACK_SP)

        mu.reg_write(UC_ARM64_REG_FP, FP_X29_VALUE)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing one instruction with customized callback
        # mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=CODE_ADDRESS)
        # mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=CODE_ADDRESS_REAL_END)
        # mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=EMULATE_MALLOC_CODE_END)
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=CODE_ADDRESS_END)

        # hook unmamapped memory
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

        # hook memory read and write
        mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
        mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
        # mu.hook_add(UC_HOOK_MEM_FETCH, hook_mem_fetch)

        logging.info("---------- Emulation Start ----------")

        # emulate machine code in infinite time
        mu.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(ARM64_CODE_akd_symbol2575))

        # now print out some registers
        logging.info("---------- Emulation done. Below is the CPU context ----------")

        retVal = mu.reg_read(UC_ARM64_REG_X0)
        # routingInfo = mu.mem_read(ARG_routingInfoPtr)
        # logging.info(">>> retVal=0x%x, routingInfo=%d", retVal, routingInfo))
        logging.info(">>> retVal=0x%x", retVal)

        routingInfoEnd = mu.mem_read(ARG_routingInfoPtr, 8)
        logging.info(">>> routingInfoEnd hex=0x%s", routingInfoEnd.hex())
        routingInfoEndLong = int.from_bytes(routingInfoEnd, "little", signed=False)
        logging.info(">>> routingInfoEndLong=%d", routingInfoEndLong)

    except UcError as e:
        logging.info("ERROR: %s", e)
        logging.info("\n")

if __name__ == '__main__':
    emulate_akd_arm64_symbol2575()
    logging.info("=" * 26)

```


### 输出log举例

```bash
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:157  INFO    Output log to debug/log/emulate_akd_getIDMSRoutingInfo_20230607_230151.log
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:176  INFO    akd_symbol2575_FilePath=input/akd_getIDMSRoutingInfo/arm64/akd_arm64_symbol2575.bin
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:179  INFO    gCodeSizeReal=9416 == 0x24C8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:187  INFO    CODE_ADDRESS=0x10000
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:191  INFO    CODE_SIZE=0x400000
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:193  INFO    CODE_ADDRESS_END=0x410000
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:196  INFO    CODE_ADDRESS_REAL_END=0x124C8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:203  INFO    x9SmallOffsetFile=input/akd_getIDMSRoutingInfo/arm64/lldb_memory/akd_arm64_data_0x100d91680_0x100d938b0_x9SmallOffset.bin
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:215  INFO    x10AbsFuncAddrWithOffsetFile=input/akd_getIDMSRoutingInfo/arm64/lldb_memory/akd_arm64_data_x10EmulateAddr.bin
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:563  INFO    Emulate arm64 sub_1000A0460 == ___lldb_unnamed_symbol2575$$akd function running
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:571  INFO    Mapped memory: Code    [0x00010000-0x00410000]
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:573  INFO                             [0x00010000-0x000124C8] func: ___lldb_unnamed_symbol2575$$akd
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:574  INFO                             [0x00031220-0x00033450]   fix br err: x9SmallOffset
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:575  INFO                             [0x00068020-0x00069B80]   fix br err: x10AbsFuncAddrWithOffset
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:576  INFO                             [0x00069B88-0x00069B90]   emulateFree jump
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:577  INFO                             [0x00069BC0-0x00069BC8]   emulateAkdFunc2567 jump
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:578  INFO                             [0x00069BD8-0x00069BE0]   emulateMalloc jump
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:579  INFO                             [0x00069BE8-0x00069BF0]   line 7392 jump
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:580  INFO                             [0x00069C08-0x00069C10]   emulateDemalloc jump
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:581  INFO                             [0x00200000-0x00200004] func: emulateMalloc
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:582  INFO                             [0x00220000-0x00220004] func: emulateFree
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:583  INFO                             [0x00280000-0x00280004] func: emulateAkdFunc2567
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:587  INFO    Mapped memory: Libc    [0x00500000-0x00580000]
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:590  INFO    Mapped memory: Heap    [0x00600000-0x00700000]
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:594  INFO    Mapped memory: Stack   [0x00700000-0x00800000]
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:597  INFO    Mapped memory: Args    [0x00800000-0x00810000]
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:618  INFO     >> has write 8752=0x2230 bytes into memory [0x31220-0x33450]
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:620  INFO     >> has write 7008=0x1B60 bytes into memory [0x68020-0x69B80]
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:102  INFO    writeMemory: memAddr=0x200000, newValue=0xc0035fd6, byteLen=4
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\xc0\x03_\xd6' to address=0x200000
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:106  INFO    writeMemory: memAddr=0x69BD8, newValue=0x0000000000200002, byteLen=8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\x02\x00 \x00\x00\x00\x00\x00' to address=0x69BD8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:102  INFO    writeMemory: memAddr=0x220000, newValue=0xc0035fd6, byteLen=4
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\xc0\x03_\xd6' to address=0x220000
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:106  INFO    writeMemory: memAddr=0x69B88, newValue=0x0000000000220002, byteLen=8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\x02\x00"\x00\x00\x00\x00\x00' to address=0x69B88
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:102  INFO    writeMemory: memAddr=0x240000, newValue=0xc0035fd6, byteLen=4
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\xc0\x03_\xd6' to address=0x240000
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:106  INFO    writeMemory: memAddr=0x69C08, newValue=0x0000000000240002, byteLen=8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\x02\x00$\x00\x00\x00\x00\x00' to address=0x69C08
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:102  INFO    writeMemory: memAddr=0x280000, newValue=0xc0035fd6, byteLen=4
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\xc0\x03_\xd6' to address=0x280000
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:106  INFO    writeMemory: memAddr=0x69BC0, newValue=0x0000000000280003, byteLen=8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\x03\x00(\x00\x00\x00\x00\x00' to address=0x69BC0
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:106  INFO    writeMemory: memAddr=0x64378, newValue=0x0050B058, byteLen=4
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'X\xb0P\x00' to address=0x64378
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:106  INFO    writeMemory: memAddr=0x50B058, newValue=0x75C022D064C70008, byteLen=8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\x08\x00\xc7d\xd0"\xc0u' to address=0x50B058
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:106  INFO    writeMemory: memAddr=0x69C18, newValue=0x0000000000078DFA, byteLen=8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\xfa\x8d\x07\x00\x00\x00\x00\x00' to address=0x69C18
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:106  INFO    writeMemory: memAddr=0x78DF8, newValue=0x0000000000003F07, byteLen=8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\x07?\x00\x00\x00\x00\x00\x00' to address=0x78DF8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:106  INFO    writeMemory: memAddr=0x69BE8, newValue=0x0000000000080002, byteLen=8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\x02\x00\x08\x00\x00\x00\x00\x00' to address=0x69BE8
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:106  INFO    writeMemory: memAddr=0x80000, newValue=0x00000203, byteLen=4
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:109  INFO     >> has write newValueBytes=b'\x03\x02\x00\x00' to address=0x80000
20230607 23:01:51 emulate_akd_getIDMSRoutingInfo.py:708  INFO    ---------- Emulation Start ----------
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:326  INFO    @@@ Tracing basic block at 0x10000, block size = 0x8c
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010000    <+0>: FF C3 03 D1  -> sub    sp, sp, #0xf0
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010004    <+4>: FC 6F 09 A9  -> stp    x28, x27, [sp, #0x90]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FFA0, size=8, value=0x0, PC=0x10004
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FFA8, size=8, value=0x0, PC=0x10004
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010008    <+8>: FA 67 0A A9  -> stp    x26, x25, [sp, #0xa0]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FFB0, size=8, value=0x0, PC=0x10008
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FFB8, size=8, value=0x0, PC=0x10008
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001000C   <+12>: F8 5F 0B A9  -> stp    x24, x23, [sp, #0xb0]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FFC0, size=8, value=0x0, PC=0x1000C
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FFC8, size=8, value=0x0, PC=0x1000C
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010010   <+16>: F6 57 0C A9  -> stp    x22, x21, [sp, #0xc0]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FFD0, size=8, value=0x0, PC=0x10010
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FFD8, size=8, value=0x0, PC=0x10010
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010014   <+20>: F4 4F 0D A9  -> stp    x20, x19, [sp, #0xd0]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FFE0, size=8, value=0x0, PC=0x10014
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FFE8, size=8, value=0x0, PC=0x10014
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010018   <+24>: FD 7B 0E A9  -> stp    x29, x30, [sp, #0xe0]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FFF0, size=8, value=0x780030, PC=0x10018
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FFF8, size=8, value=0x10000, PC=0x10018
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001001C   <+28>: FD 83 03 91  -> add    x29, sp, #0xe0
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010020   <+32>: 1F 20 03 D5  -> nop
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010024   <+36>: A8 1A 2A 58  -> ldr    x8, #0x64378
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:544  INFO     << Memory READ at 0x64378, size=8, rawValueLittleEndian=0x58b0500000000000, pc=0x10024
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010028   <+40>: 08 01 40 F9  -> ldr    x8, [x8]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:544  INFO     << Memory READ at 0x50B058, size=8, rawValueLittleEndian=0x0800c764d022c075, pc=0x10028
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001002C   <+44>: A8 83 1A F8  -> stur   x8, [x29, #-0x58]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FF98, size=8, value=0x75C022D064C70008, PC=0x1002C
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010030   <+48>: FA 50 8B 52  -> movz   w26, #0x5a87
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010034   <+52>: 9A 84 AD 72  -> movk   w26, #0x6c24, lsl #16
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010038   <+56>: 08 18 00 91  -> add    x8, x0, #6
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001003C   <+60>: 1F 15 00 F1  -> cmp    x8, #5
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010040   <+64>: 04 28 48 BA  -> ccmn   x0, #8, #4, hs
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010044   <+68>: 28 00 80 52  -> movz   w8, #0x1
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010048   <+72>: E8 03 88 1A  -> csel   w8, wzr, w8, eq
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001004C   <+76>: 4B B4 94 52  -> movz   w11, #0xa5a2
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010050   <+80>: 6B 7B B2 72  -> movk   w11, #0x93db, lsl #16
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010054   <+84>: 3F 00 00 F1  -> cmp    x1, #0
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010058   <+88>: E9 17 9F 1A  -> cset   w9, eq
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001005C   <+92>: 28 01 08 2A  -> orr    w8, w9, w8
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010060   <+96>: 49 03 08 0B  -> add    w9, w26, w8
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010064  <+100>: 29 01 0B 0B  -> add    w9, w9, w11
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010068  <+104>: 29 85 00 51  -> sub    w9, w9, #0x21
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001006C  <+108>: 39 3F 11 10  -> adr    x25, #0x32850
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010070  <+112>: 1F 20 03 D5  -> nop
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x10070: x25=0x0000000000032850
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010074  <+116>: 29 DB A9 B8  -> ldrsw  x9, [x25, w9, sxtw #2]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x10074: cpsr=0x20000000, w9=0x00000008, x9=0x0000000000000008, x25=0x0000000000032850
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:544  INFO     << Memory READ at 0x32870, size=4, rawValueLittleEndian=0xc4dbffff, pc=0x10074
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010078  <+120>: 1F 20 03 D5  -> nop
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x10078: cpsr=0x20000000, x9=0xFFFFFFFFFFFFDBC4
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001007C  <+124>: EA 63 2C 58  -> ldr    x10, #0x68cf8
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:544  INFO     << Memory READ at 0x68CF8, size=8, rawValueLittleEndian=0xc824010000000000, pc=0x1007C
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010080  <+128>: 29 01 0A 8B  -> add    x9, x9, x10
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x10080: cpsr=0x20000000, x9=0xFFFFFFFFFFFFDBC4, x10=0x00000000000124C8
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010084  <+132>: 16 F9 95 12  -> movn   w22, #0xafc8
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x10084: cpsr=0x20000000, x9=0x000000000001008C
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010088  <+136>: 20 01 1F D6  -> br     x9
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:326  INFO    @@@ Tracing basic block at 0x1008c, block size = 0x44
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001008C  <+140>: F7 03 01 AA  -> mov    x23, x1
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010090  <+144>: FC 03 00 AA  -> mov    x28, x0
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010094  <+148>: 08 01 00 52  -> eor    w8, w8, #1
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010098  <+152>: 69 A5 00 51  -> sub    w9, w11, #0x29
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001009C  <+156>: 16 69 09 1B  -> madd   w22, w8, w9, w26
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100A0  <+160>: 14 26 95 D2  -> movz   x20, #0xa930
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100A4  <+164>: 34 4B BD F2  -> movk   x20, #0xea59, lsl #16
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100A8  <+168>: B4 7B D3 F2  -> movk   x20, #0x9bdd, lsl #32
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100AC  <+172>: 14 AE FA F2  -> movk   x20, #0xd570, lsl #48
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100B0  <+176>: C8 2E 00 11  -> add    w8, w22, #0xb
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100B4  <+180>: 78 D6 2C 10  -> adr    x24, #0x69b80
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100B8  <+184>: 1F 20 03 D5  -> nop
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100BC  <+188>: 08 DB 68 F8  -> ldr    x8, [x24, w8, sxtw #3]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:544  INFO     << Memory READ at 0x69BD8, size=8, rawValueLittleEndian=0x0200200000000000, pc=0x100BC
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100C0  <+192>: 08 09 00 D1  -> sub    x8, x8, #2
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100C4  <+196>: 00 03 80 52  -> movz   w0, #0x18
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100C8  <+200>: E8 33 00 F9  -> str    x8, [sp, #0x60]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FF70, size=8, value=0x200000, PC=0x100C8
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100CC  <+204>: 00 01 3F D6  -> blr    x8
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:326  INFO    @@@ Tracing basic block at 0x200000, block size = 0x4
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00200000 <+2031616>: C0 03 5F D6  -> ret
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x200000: cpsr=0x20000000, x0=0x0000000000000018, x1=0x0000000000800000
20230607 23:01:56 UnicornSimpleHeap.py:120  INFO     ++ Allocated heap chunk: chunk: [0x600000-0x603000] ptr=0x601000, size=24=0x18
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:469  INFO           emulateMalloc: input x0=0x18, output ret: 0x601000
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:326  INFO    @@@ Tracing basic block at 0x100d0, block size = 0x50
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100D0  <+208>: 08 00 80 52  -> movz   w8, #0
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x100D0: x0=0x0000000000601000, x1=0x0000000000800000
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100D4  <+212>: 1F 00 00 F1  -> cmp    x0, #0
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100D8  <+216>: E9 07 9F 1A  -> cset   w9, ne
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100DC  <+220>: EA 17 9F 1A  -> cset   w10, eq
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100E0  <+224>: C9 06 09 0B  -> add    w9, w22, w9, lsl #1
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100E4  <+228>: 53 25 1A 1B  -> madd   w19, w10, w26, w9
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100E8  <+232>: C9 16 96 1A  -> cinc   w9, w22, eq
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100EC  <+236>: 29 DB A9 B8  -> ldrsw  x9, [x25, w9, sxtw #2]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100F0  <+240>: 1F 20 03 D5  -> nop
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100F4  <+244>: 6A 60 2C 58  -> ldr    x10, #0x68d00
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100F8  <+248>: 29 01 0A 8B  -> add    x9, x9, x10
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x100F8: x9=0x0000000000000094, x10=0x000000000001008C
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000100FC  <+252>: CA 06 00 11  -> add    w10, w22, #1
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x100FC: x9=0x0000000000010120
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010100  <+256>: 0A DB 6A F8  -> ldr    x10, [x24, w10, sxtw #3]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x10100: x24=0x0000000000069B80, w10=0x00000001
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010104  <+260>: 5B 09 00 D1  -> sub    x27, x10, #2
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x10104: x10=0x0000000000220002
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010108  <+264>: 56 F9 95 12  -> movn   w22, #0xafca
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x10108: x27=0x0000000000220000
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001010C  <+268>: 10 26 95 D2  -> movz   x16, #0xa930
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010110  <+272>: 30 4B BD F2  -> movk   x16, #0xea59, lsl #16
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010114  <+276>: B0 7B D3 F2  -> movk   x16, #0x9bdd, lsl #32
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010118  <+280>: 10 AE FA F2  -> movk   x16, #0xd570, lsl #48
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001011C  <+284>: 20 01 1F D6  -> br     x9
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x1011C: x9=0x0000000000010120
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:326  INFO    @@@ Tracing basic block at 0x10120, block size = 0x2c
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010120  <+288>: F5 03 00 AA  -> mov    x21, x0
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010124  <+292>: 14 00 14 8B  -> add    x20, x0, x20
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010128  <+296>: 08 F3 8B D2  -> movz   x8, #0x5f98
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001012C  <+300>: 68 AB A4 F2  -> movk   x8, #0x255b, lsl #16
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010130  <+304>: 08 B9 D1 F2  -> movk   x8, #0x8dc8, lsl #32
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010134  <+308>: 68 3E E7 F2  -> movk   x8, #0x39f3, lsl #48
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010138  <+312>: 1F 20 00 A9  -> stp    xzr, x8, [x0]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x601000, size=8, value=0x0, PC=0x10138
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x601008, size=8, value=0x39F38DC8255B5F98, PC=0x10138
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001013C  <+316>: 1F 10 00 B9  -> str    wzr, [x0, #0x10]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x601010, size=4, value=0x0, PC=0x1013C
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010140  <+320>: 00 00 82 52  -> movz   w0, #0x1000
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010144  <+324>: E8 33 40 F9  -> ldr    x8, [sp, #0x60]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010148  <+328>: 00 01 3F D6  -> blr    x8
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:326  INFO    @@@ Tracing basic block at 0x200000, block size = 0x4
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00200000 <+2031616>: C0 03 5F D6  -> ret
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x200000: cpsr=0x20000000, x0=0x0000000000001000, x1=0x0000000000800000
20230607 23:01:56 UnicornSimpleHeap.py:120  INFO     ++ Allocated heap chunk: chunk: [0x603000-0x606000] ptr=0x604000, size=4096=0x1000
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:469  INFO           emulateMalloc: input x0=0x1000, output ret: 0x604000
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:326  INFO    @@@ Tracing basic block at 0x1014c, block size = 0x34
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001014C  <+332>: A0 02 00 F9  -> str    x0, [x21]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x601000, size=8, value=0x604000, PC=0x1014C
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010150  <+336>: 48 0B 00 51  -> sub    w8, w26, #2
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010154  <+340>: 1F 00 00 F1  -> cmp    x0, #0
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010158  <+344>: E9 17 9F 1A  -> cset   w9, eq
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001015C  <+348>: EA 07 9F 1A  -> cset   w10, ne
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010160  <+352>: 48 4D 08 1B  -> madd   w8, w10, w8, w19
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010164  <+356>: 09 09 09 0B  -> add    w9, w8, w9, lsl #2
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010168  <+360>: 68 16 93 1A  -> cinc   w8, w19, eq
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001016C  <+364>: 28 DB A8 B8  -> ldrsw  x8, [x25, w8, sxtw #2]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x1016C: w8=0x00000002, x25=0x0000000000032850
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010170  <+368>: 1F 20 03 D5  -> nop
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x10170: x8=0x00000000000000C4
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010174  <+372>: AA 5C 2C 58  -> ldr    x10, #0x68d08
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010178  <+376>: 08 01 0A 8B  -> add    x8, x8, x10
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:460  INFO           debug: PC=0x10178: x10=0x0000000000010120
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001017C  <+380>: 00 01 1F D6  -> br     x8
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:326  INFO    @@@ Tracing basic block at 0x101e4, block size = 0x48
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000101E4  <+484>: 16 00 80 52  -> movz   w22, #0
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000101E8  <+488>: 08 F3 8B 52  -> movz   w8, #0x5f98
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000101EC  <+492>: 68 AB A4 72  -> movk   w8, #0x255b, lsl #16
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000101F0  <+496>: 08 05 40 11  -> add    w8, w8, #1, lsl #12
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000101F4  <+500>: A8 0A 00 B9  -> str    w8, [x21, #8]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x601008, size=4, value=0x255B6F98, PC=0x101F4
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000101F8  <+504>: 28 00 80 52  -> movz   w8, #0x1
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x000101FC  <+508>: F3 03 09 AA  -> mov    x19, x9
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010200  <+512>: F0 03 14 AA  -> mov    x16, x20
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010204  <+516>: 55 B4 94 52  -> movz   w21, #0xa5a2
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010208  <+520>: 75 7B B2 72  -> movk   w21, #0x93db, lsl #16
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001020C  <+524>: A9 02 13 0B  -> add    w9, w21, w19
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010210  <+528>: 29 01 08 0B  -> add    w9, w9, w8
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010214  <+532>: 29 65 00 51  -> sub    w9, w9, #0x19
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010218  <+536>: 29 DB A9 B8  -> ldrsw  x9, [x25, w9, sxtw #2]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001021C  <+540>: 1F 20 03 D5  -> nop
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010220  <+544>: CA 57 2C 58  -> ldr    x10, #0x68d18
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010224  <+548>: 29 01 0A 8B  -> add    x9, x9, x10
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010228  <+552>: 20 01 1F D6  -> br     x9
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:326  INFO    @@@ Tracing basic block at 0x1022c, block size = 0x84
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001022C  <+556>: FC 13 00 F9  -> str    x28, [sp, #0x20]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FF30, size=8, value=0x-2, PC=0x1022C
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010230  <+560>: F7 03 00 F9  -> str    x23, [sp]
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:533  INFO     >> Memory WRITE at 0x77FF10, size=8, value=0x800000, PC=0x10230
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010234  <+564>: 09 DA 8A D2  -> movz   x9, #0x56d0
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010238  <+568>: C9 B4 A2 F2  -> movk   x9, #0x15a6, lsl #16
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x0001023C  <+572>: 49 84 CC F2  -> movk   x9, #0x6422, lsl #32
20230607 23:01:56 emulate_akd_getIDMSRoutingInfo.py:346  INFO    --- 0x00010240  <+576>: E9 51 E5 F2  -> movk   x9, #0x2a8f, lsl #48
...
```

## 文件: `libs/UnicornSimpleHeap.py`

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
