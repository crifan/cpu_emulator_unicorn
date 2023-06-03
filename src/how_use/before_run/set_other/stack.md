# Stack栈

TODO：

* 寄存器、堆栈
  * 【已解决】unicorn模拟ARM中LR和SP寄存器堆栈信息

---

* Stack栈
  * 本身特性
    * 本质上：是一个线性表
      * 操作栈顶(top)，进行插入或删除
        * 另一端称为栈底bottom
      * 操作原理：后进先出=LIFO=Last In First Out
  * 生成方向=增长方向
    * 理论上支持
      * Full Descending=满递减=由高地址到低地址
      * 空递增？ = 由低地址到高地址
    * 但是基本上都是用：
      * Full Descending=满递减=由高地址到低地址

## ARM中的Stack栈

ARM中的Stack栈，默认情况下，都是：由高地址到低地址。
