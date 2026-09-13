"""HTML 报告渲染（html_reporter）。

用 Jinja2 渲染 ``output/final_report.html``：统计概览、四级置信度漏洞卡片
（含污点位置/修复建议/动态/研判理由）、CWE-ATT&CK 矩阵、误报率指标。
模板内嵌，报告单文件自包含（不依赖外网 CDN）。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("opensoft_detect.reporting.html")

#: 四级置信度的展示样式
_CONF_BADGE: dict[str, str] = {
    "confirmed": "badge-confirmed",
    "high_suspicious": "badge-high",
    "possible": "badge-possible",
    "excluded": "badge-excluded",
}


class HtmlReporter:
    """基于 Jinja2 的 HTML 报告渲染器。"""

    def __init__(self) -> None:
        """构造渲染器。"""
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        # 模板内嵌（inline），保证单文件可运行
        self.template_str = _TEMPLATE
        self.env = Environment(autoescape=True)

    def render(self, report: dict[str, Any], out_path: Path) -> str:
        """渲染并写出 HTML。

        :param report: report 字典。
        :param out_path: 输出 .html 路径。
        :return: 绝对路径字符串。
        """
        tpl = self.env.from_string(self.template_str)
        html = tpl.render(
            report=report,
            stats=report.get("statistics", {}),
            meta=report.get("meta", {}),
            groups=report.get("confidence_groups", {}),
            matrix=report.get("cwe_attack_matrix", {}),
            dropped=report.get("dropped_records", []),
            conf_badge=_CONF_BADGE,
            level_label=lambda k: {
                "confirmed": "已确认", "high_suspicious": "高度可疑",
                "possible": "可能", "excluded": "排除"}.get(k, k),
        )
        out_path = out_path.resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html, encoding="utf-8")
        logger.info("final_report.html 已写入：%s", out_path)
        return str(out_path)


_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>OpenSoft Detect 安全报告</title>
<style>
:root{--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e;--muted:#57606a}
body{font-family:-apple-system,'Segoe UI',Roboto,'Microsoft YaHei',sans-serif;margin:0;
     background:#f6f8fa;color:#24292f;line-height:1.5}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{border-bottom:3px solid #0969da;padding-bottom:8px}
h2{margin-top:28px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.card{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:12px 14px}
.card b{font-size:1.7em;display:block}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-size:.78em}
.badge-confirmed{background:#1a7f37}.badge-high{background:#bf8700}
.badge-possible{background:#57606a}.badge-excluded{background:#9e9e9e}
table{border-collapse:collapse;width:100%;background:#fff}
td,th{border:1px solid #d0d7de;padding:6px 8px;text-align:left;font-size:.9em}
pre{background:#0d1117;color:#e6edf3;padding:10px;border-radius:6px;overflow:auto;font-size:.82em}
.fcard{background:#fff;border:1px solid #d0d7de;border-left:5px solid #0969da;border-radius:6px;
      margin:10px 0;padding:12px 16px}
.fcard.excluded{border-left-color:#9e9e9e}
.sev-high{color:#cf222e}.sev-critical{color:#a40e26;font-weight:700}
.sev-medium{color:#9a6700}.sev-low,.sev-info{color:#57606a}
.small{color:#57606a;font-size:.85em}
.dropped li{margin:2px 0}
</style>
</head>
<body>
<div class="wrap">
<h1>OpenSoft Detect — 安全检测报告</h1>
<p class="small">目标：<code>{{ meta.target }}</code> · 生成时间：{{ meta.generated_at }}
 · fix_suggest={{ 'on' if meta.fix_suggest else 'off' }} · skip_dynamic={{ 'on' if meta.skip_dynamic else 'off' }}</p>

<h2>统计概览</h2>
<div class="cards">
  <div class="card"><b>{{ stats.total_reported }}</b>报告条目
     <span class="small">（判研 {{ stats.fp_rate.total_findings }}）</span></div>
  <div class="card"><b style="color:var(--ok)">{{ stats.fp_rate.true_positives }}</b>真实漏洞(TP)</div>
  <div class="card"><b style="color:var(--bad)">{{ stats.fp_rate.false_positives }}</b>误报(FP)</div>
  <div class="card"><b>{{ (stats.fp_rate.false_positive_rate * 100)|round(1) }}%</b>误报率</div>
  {% for lvl, n in stats.confidence_distribution.items() %}
  <div class="card"><span class="badge {{ conf_badge[lvl] }}">{{ level_label(lvl) }}</span> <b>{{ n }}</b></div>
  {% endfor %}
</div>
<p class="small">统计口径：{{ stats.assumptions }}</p>

<h2>CWE × ATT&CK 矩阵</h2>
{% if matrix %}
<table><tr><th>ATT&CK Technique</th><th>CWE</th><th>关联 Finding 数</th></tr>
{% for tech, v in matrix.items() %}
<tr><td><code>{{ tech }}</code> {{ v.name }}</td>
<td>{% for cid, n in v.cwes.items() %}<code>{{ cid }}</code>({{ n }}) {% endfor %}</td>
<td>{{ v.cwes.values()|sum }}</td></tr>
{% endfor %}
</table>
{% else %}<p class="small">无 CWE 关联数据。</p>{% endif %}

{% for lvl, items in groups.items() %}
<h2><span class="badge {{ conf_badge[lvl] }}">{{ level_label(lvl) }}</span>（{{ items|length }}）</h2>
{% for f in items %}
<div class="fcard {{ 'excluded' if lvl=='excluded' else '' }}">
  <div>
    <b>{{ f.rule_id }}</b>
    <span class="sev-{{ f.severity }}">{{ f.severity }}</span>
    <span class="badge {{ conf_badge[lvl] }}">{{ lvl }}</span>
    <span class="small">({{ f.tool }})</span>
  </div>
  <p>{{ f.message }}</p>
  <p class="small">位置：<code>{{ f.file_path }}:{{ f.location.start_line if f.location else '?' }}</code>
     · CWE：{{ f.cwe_ids|join(', ') if f.cwe_ids else '-' }}
     · ATT&CK：{{ f.attack_techniques|join(', ') if f.attack_techniques else '-' }}</p>
  {% if f.taint_flow %}
  <details><summary>污点路径</summary><pre>{{ f.taint_flow|map(attribute='description')|join('\\n') }}</pre></details>
  {% endif %}
  {% if f.llm_verdict_reason %}<p class="small">LLM 研判：{{ f.llm_verdict_reason }}</p>{% endif %}
  {% if f.fix_suggestion %}
  <details open><summary>修复建议（{{ f.fix_suggestion.summary }}）</summary>
  <pre>{{ f.fix_suggestion.diff }}</pre></details>
  {% endif %}
</div>
{% endfor %}
{% endfor %}

<h2>预过滤排除（{{ dropped|length }}）</h2>
<ul class="dropped">
{% for d in dropped %}<li class="small">{{ d.finding_id }} — {{ d.reason }}</li>{% endfor %}
</ul>

<p class="small">本报告由 OpenSoft Detect 自动生成。</p>
</div>
</body>
</html>
"""
