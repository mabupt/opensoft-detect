"""大模型客户端（LLMClient）。

对推理服务做一层薄封装，强制满足模块3 的可靠性工程参数：

- ``temperature=0``：消除随机性（由 config.LLMConfig.temperature 控制，默认 0.0）
- **JSON mode**：OpenAI 兼容协议下传 ``response_format={"type": "json_object"}``；
  Anthropic 协议用指令 + 严格解析兜底
- 单次请求**超时 30s**（config.request_timeout）
- 失败**最多重试 3 轮**（config.max_retries），指数退避
- 每次调用把超时/重试原因打日志，便于定位

provider 支持：
- ``openai``（含任意 OpenAI 兼容网关，配置 api_base）
- ``anthropic``（默认，读 ANTHROPIC_API_KEY）

对外主入口：:meth:`chat_json` —— 返回**已解析的 dict**，保证上层只处理 JSON。
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

from config import LLMConfig

logger = logging.getLogger("opensoft_detect.llm_analysis.client")


class LLMClient:
    """统一大模型客户端（JSON 结构化输出优先）。"""

    def __init__(self, llm_cfg: LLMConfig) -> None:
        """构造客户端。

        :param llm_cfg: LLM 服务配置。
        """
        self.cfg: LLMConfig = llm_cfg

    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        """是否具备调用条件（有 API Key）。

        :return: True 表示可调用。
        """
        return bool((self.cfg.api_key or "").strip())

    # ------------------------------------------------------------------
    def chat_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        """以 JSON 结构化输出为目标执行 chat，返回解析后的 dict。

        内部：调用 :meth:`chat`（含重试），再把回复文本解析为 JSON；
        解析失败抛 RuntimeError（由上层对该 Finding 降级）。

        :param system_prompt: 系统提示词。
        :param user_prompt: 用户消息。
        :return: JSON dict。
        :raises RuntimeError: 重试后仍失败或输出无法解析为 JSON。
        """
        cache_file = self._cache_path(system_prompt, user_prompt)
        cached = self._cache_load(cache_file)
        if cached is not None:
            logger.info("LLM 命中判定缓存：%s", cache_file.name)
            return cached
        text: str = self.chat(system_prompt, user_prompt)
        parsed: dict[str, Any] = parse_json_object(text)
        self._cache_save(cache_file, parsed)
        return parsed

    # ---- 判定缓存（按 prompt+model 哈希；TTL；失败不影响主流程）----
    def _cache_path(self, system_prompt: str, user_prompt: str) -> Path:
        """生成缓存文件路径（包含 provider/model/prompt 内容哈希）。

        :param system_prompt: 系统提示词。
        :param user_prompt: 用户提示词。
        :return: 缓存路径。
        """
        import hashlib
        raw = f"{self.cfg.provider}|{self.cfg.model}|{system_prompt}|{user_prompt}".encode()
        key = hashlib.sha256(raw).hexdigest()[:20]
        return self._cache_dir() / f"llm_{key}.json"

    @staticmethod
    def _cache_dir() -> Path:
        """缓存目录（output/.cache）。"""
        d = Path(__file__).resolve().parents[2] / "output" / ".cache"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _cache_load(self, path: Path) -> Optional[dict[str, Any]]:
        """读取未过期缓存；无/过期/损坏返回 None。"""
        if not getattr(self.cfg, "cache_enabled", True):
            return None
        import json as _json
        import time as _t
        try:
            if not path.is_file():
                return None
            data = _json.loads(path.read_text(encoding="utf-8"))
            ttl = int(getattr(self.cfg, "cache_ttl_days", 30)) * 86400
            if _t.time() - float(data.get("ts", 0)) > ttl:
                return None
            payload = data.get("payload")
            return payload if isinstance(payload, dict) else None
        except Exception:  # noqa: BLE001
            return None

    def _cache_save(self, path: Path, payload: dict[str, Any]) -> None:
        """写入缓存（失败忽略）。"""
        if not getattr(self.cfg, "cache_enabled", True):
            return
        import json as _json
        import time as _t
        try:
            path.write_text(_json.dumps({"ts": _t.time(), "payload": payload},
                                        ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        """带超时/重试地执行一次 chat，返回模型回复文本。

        :param system_prompt: 系统提示词。
        :param user_prompt: 用户消息。
        :return: 回复文本。
        :raises RuntimeError: 重试耗尽后仍失败。
        """
        messages: list[dict[str, str]] = self._build_messages(system_prompt, user_prompt)
        last_err: Optional[Exception] = None
        for attempt in range(1, self.cfg.max_retries + 1):
            try:
                return self._post(messages)
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                logger.warning("LLM 调用第 %d/%d 次失败：%s", attempt,
                               self.cfg.max_retries, exc)
                if attempt < self.cfg.max_retries:
                    time.sleep(min(2 ** attempt, 8))   # 指数退避
        raise RuntimeError(f"LLM 调用失败（重试 {self.cfg.max_retries} 轮）：{last_err}")

    # ------------------------------------------------------------------
    def _build_messages(self, system_prompt: str, user_prompt: str) -> list[dict[str, str]]:
        """构造 messages 结构（不同协议在此归一）。"""
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

    def _post(self, messages: list[dict[str, str]]) -> str:
        """按 provider 分派到底层调用。

        :param messages: 消息列表。
        :return: 模型回复文本。
        """
        provider: str = (self.cfg.provider or "anthropic").lower()
        if provider in ("openai", "openai-compatible", "deepseek", "qwen"):
            return self._post_openai_compatible(messages)
        return self._post_anthropic(messages)

    # ---- OpenAI 兼容协议（支持 response_format json_object）----
    def _post_openai_compatible(self, messages: list[dict[str, str]]) -> str:
        """调用 OpenAI 兼容 Chat Completions API。

        注意：``response_format={"type":"json_object"}`` 仅当消息中包含
        "json" 字样时部分网关才接受，系统提示已保证含该词。
        """
        import requests

        base: str = (self.cfg.api_base or "https://api.openai.com/v1").rstrip("/")
        url: str = f"{base}/chat/completions"
        body: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": messages,
            "temperature": self.cfg.temperature,          # 0 消除随机性
            "max_tokens": self.cfg.max_tokens,
        }
        if self.cfg.json_mode:
            body["response_format"] = {"type": "json_object"}   # 强制 JSON mode
        resp = requests.post(
            url, json=body,
            headers={"Authorization": f"Bearer {self.cfg.api_key}",
                     "Content-Type": "application/json"},
            timeout=self.cfg.request_timeout,             # 30s
        )
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:500]}")
        data = resp.json()
        content: str = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        if not content:
            raise RuntimeError("OpenAI 回复为空 content")
        return content

    # ---- Anthropic 协议 ----
    def _post_anthropic(self, messages: list[dict[str, str]]) -> str:
        """调用 Anthropic Messages API（SDK 惰性导入）。

        Anthropic 无原生 json_object 模式，采用"只输出 JSON"指令 + 上层严格解析；
        温度/超时/重试参数统一生效。
        """
        from anthropic import Anthropic

        client = Anthropic(api_key=self.cfg.api_key,
                           timeout=self.cfg.request_timeout)
        sys_prompt: str = messages[0]["content"] if messages and messages[0]["role"] == "system" else ""
        user_msgs = [m for m in messages if m["role"] == "user"]
        resp = client.messages.create(
            model=self.cfg.model,
            system=sys_prompt,
            messages=user_msgs,
            temperature=self.cfg.temperature,
            max_tokens=self.cfg.max_tokens,
        )
        content = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        if not content:
            raise RuntimeError("Anthropic 回复为空 content")
        return content


def parse_json_object(text: str) -> dict[str, Any]:
    """把模型回复严格解析为 dict。

    兼容三种形态：纯 JSON / ```json 围栏 / 文本中嵌 JSON 对象。
    全部失败抛 RuntimeError。

    :param text: 模型原始回复。
    :return: 解析后的 dict。
    :raises RuntimeError: 无法解析出 JSON 对象。
    """
    if not text:
        raise RuntimeError("模型回复为空，无法解析 JSON")
    candidates: list[str] = []
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.lower().startswith("json"):
            stripped = stripped[4:]
        stripped = stripped.strip()
    candidates.append(stripped)
    # 尝试提取第一个 '{' 到最后一个 '}' 的子串（围栏/前后缀文字兜底）
    start, end = stripped.find("{"), stripped.rfind("}")
    if start != -1 and end > start:
        candidates.append(stripped[start:end + 1])

    last_err: Optional[Exception] = None
    for cand in candidates:
        try:
            obj = json.loads(cand)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError as exc:
            last_err = exc
    raise RuntimeError(f"模型输出无法解析为 JSON 对象：{last_err}")
