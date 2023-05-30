# 下载安装

* 安装Unicorn的核心逻辑
  * Mac中安装unicorn
    * 先安装unicorn本身
      ```bash
      brew install unicorn
      ```
      * 安装后：
        * 只有lib库，没有unicorn二进制
          * 库的位置
            * `/usr/local/opt/unicorn/lib/`
        * 由于homebrew把库安装到其自己的目录，所以为了后续程序能找到并加载到unicorn的库，需要去加上对应的环境变量
          ```bash
          export DYLD_LIBRARY_PATH=/usr/local/opt/unicorn/lib/:$DYLD_LIBRARY_PATH
          ```
    * 再去安装binding
      * Python的binding
        ```bash
        pip install unicorn
        ```

注：如果期间报错，缺少一些依赖的工具，再去分别安装：

* cmake
  * 从[官网](https://cmake.org/download/)下载到[cmake-3.26.4-macos-universal.dmg](https://github.com/Kitware/CMake/releases/download/v3.26.4/cmake-3.26.4-macos-universal.dmg)，下载后双击，拖动`CMake`到应用程序即可
  * 把cmake二进制路径加到PATH，确保命令行中能用cmake
    * 编辑启动脚本`vi ~/.zshrc`，加上：`export PATH="/Applications/CMake.app/Contents/bin":"$PATH"`，即可。
* pkg-config
  * `brew install pkg-config`
