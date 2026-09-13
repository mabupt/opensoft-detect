"""CWE-ATT&CK 关联（enrichment）。

维护 CWE（代码缺陷）→ ATT&CK Technique（攻击技术）的映射表，为报告提供
"代码缺陷可被利用成哪种攻击路径"的横向视角。

- 内置表 :data:`CWE_TO_ATTACK` 覆盖常用注入/信息泄露类；来源可再结合 Qdrant
  ``security_knowledge`` 中 cwe_id 关联条目扩充（见模块2 get_by_id）。
- ATT&CK 以 T####(.###) 表示，短名见 :data:`ATTACK_TECHNIQUE_NAMES`。
"""

from __future__ import annotations

from typing import Iterable

#: CWE -> ATT&CK Technique（内置常用映射；实现阶段可按需扩充）
CWE_TO_ATTACK: dict[str, list[str]] = {
    "CWE-78": ["T1059", "T1059.007"],          # OS 命令注入
    "CWE-79": ["T1059", "T1189", "T1204"],      # XSS
    "CWE-89": ["T1190", "T1082"],               # SQL 注入
    "CWE-94": ["T1059", "T1203"],               # 代码注入
    "CWE-95": ["T1059", "T1203"],               # 表达式/代码注入(eval)
    "CWE-502": ["T1203", "T1059"],              # 不安全反序列化
    "CWE-22": ["T1083", "T1000", "T1005"],      # 路径穿越
    "CWE-918": ["T1190", "T1090", "T1119"],     # SSRF
    "CWE-611": ["T1190", "T1059"],              # XXE
    "CWE-352": ["T1185"],                       # CSRF
    "CWE-287": ["T1078"],                       # 认证缺失/绕过
    "CWE-798": ["T1078", "T1552"],              # 硬编码凭据
    "CWE-200": ["T1213", "T1005"],              # 信息泄露
    "CWE-312": ["T1552", "T1005"],              # 敏感数据明文存储/日志
    "CWE-614": ["T1110", "T1552"],              # 敏感 Cookie 不安全(会话)
    "CWE-215": ["T1547", "T1068"],              # 调试信息暴露(debug mode)
    "CWE-489": ["T1068", "T1547"],              # 活动调试代码
}

#: ATT&CK Technique 展示名
ATTACK_TECHNIQUE_NAMES: dict[str, str] = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.007": "Command and Scripting Interpreter: JavaScript/Python",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1000": "Local File Inclusion",
    "T1005": "Data from Local System",
    "T1189": "Drive-by Compromise",
    "T1204": "User Execution",
    "T1190": "Exploit Public-Facing Application",
    "T1203": "Exploitation for Client Execution",
    "T1090": "Proxy",
    "T1119": "Automated Collection",
    "T1185": "Browser Session Hijacking",
    "T1078": "Valid Accounts",
    "T1552": "Unsecured Credentials",
    "T1213": "Data from Information Repositories",
    "T1110": "Brute Force",
    "T1068": "Exploitation for Privilege Escalation",
    "T1547": "Boot or Logon Autostart Execution",
}


def map_cwe_to_attack(cwe_ids: Iterable[str]) -> list[str]:
    """把 CWE 列表映射为去重后的 ATT&CK Technique 列表。

    :param cwe_ids: CWE 编号集合。
    :return: 排序去重的 ATT&CK 编号。
    """
    out: set[str] = set()
    for cid in cwe_ids:
        out.update(CWE_TO_ATTACK.get(cid, []))
    return sorted(out)


def technique_name(technique: str) -> str:
    """返回 ATT&CK 展示名；未收录返回原编号。"""
    return ATTACK_TECHNIQUE_NAMES.get(technique, technique)


def attack_matrix(findings: list) -> dict[str, dict[str, int]]:
    """生成 ATT&CK × CWE 交叉计数矩阵（供报告可视化）。

    输入为已聚合的 Finding 对象或含 cwe_ids 的字典。

    :param findings: Finding 列表。
    :return: {technique: {cwe: count}}。
    """
    matrix: dict[str, dict[str, int]] = {}
    for f in findings:
        cwes = f.cwe_ids if hasattr(f, "cwe_ids") else (f.get("cwe_ids") or [])
        for tech in map_cwe_to_attack(cwes):
            row = matrix.setdefault(tech, {})
            for cid in cwes:
                row[cid] = row.get(cid, 0) + 1
    return matrix
