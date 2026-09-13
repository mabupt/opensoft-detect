"""模块0：文件预处理（preprocess）。

职责：遍历目标工程文件树，按规则把文件分类为
``scan_scope``（待扫描）与 ``excluded``（被排除，含原因），
排除测试 / 迁移 / 文档 / 依赖目录等无关内容，
最终生成统一的 ``output/file_manifest.json`` 清单供模块1 消费。

过滤分为两档：
- 硬排除（hard）：__pycache__/.git/node_modules 等目录、.pyc/.so/.png 等扩展名；
- 软排除（soft）：tests/docs/migrations、conftest.py/Dockerfile 等，
  ``--include-excluded`` 时可纳入扫描。
另支持 ``--scan-dirs`` 限定只扫描指定子目录。

子模块拆分：::

    scanner.py   语言识别与文件元信息（行数/哈希/相对路径）等纯函数
    filter.py    FileFilter：硬/软规则 + 带剪枝的目录遍历分类
    manifest.py  清单构建与读写（file_manifest.json：scan_scope/excluded/stats）
    runner.py    本模块编排入口
"""
