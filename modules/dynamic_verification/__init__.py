"""模块4：动态验证（dynamic_verification）。

职责：在**运行时**实证模块3 研判的漏洞，核心是三层 Import Hook 补丁 + 双轨检测。

- **Import Hook 三层补丁**（import_hook.py）：
  SinkPatcherFinder（find_module/load_module/find_spec）+ ``_patch_builtins()``
  直接替换 builtins 的 eval/exec/compile/open；``_patch_already_loaded()`` 兜底
  扫描 sys.modules 替换已绑定的危险函数别名。**install() 必须在目标代码 import 之前。**
- **双轨检测**（track_a / track_b）：
  轨道A 无差别记录 sink 调用；轨道B 检测参数是否携带 ``__TAINT_xxx__`` 标记。
  双轨均触发=confirmed；仅A=retry_poc；均无=rejected。
- **PoC 与重试**（poc.py）：LLM 先输出 analysis 再输出 test_input（"先分析再动手"），
  A 触发而 B 丢失时最多重试 3 轮，末轮启用 source 点注入标记兜底。
- **沙箱与降级**（sandbox.py）：DockerExecutor 隔离执行 + 部署降级决策
  （compose -> sqlite -> non_db_only -> app_unreachable）。

产物：``output/dynamic_findings.json``（每候选在 metadata.dynamic 记录
verdict / skip_reason / track 计数）。confirmed 的结果写入 KB 闭环。
"""
