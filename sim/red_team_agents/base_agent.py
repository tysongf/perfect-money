"""Strict JSON action schema, pluggable LLM backend client, and BaseRedTeamAgent."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import os
import random
from typing import Any, Callable
import urllib.error
import urllib.request

from .covert_channel import CovertMessage


ALLOWED_ACTION_TYPES: frozenset[str] = frozenset(
    {
        "NOOP",
        "ORACLE_COMMIT",
        "ORACLE_REVEAL",
        "ORACLE_CHALLENGE",
        "ORACLE_COURT_VOTE",
        "AMM_SWAP_PM_TO_NUM",
        "AMM_SWAP_NUM_TO_PM",
        "REDEEM_PM",
        "MINT_AND_SELL",
        "LOCK_STAKE",
        "COVERT_SEND",
        "PAY_BRIBE",
    }
)


class ActionValidationError(ValueError):
    """Raised when an agent or LLM emits an invalid or unsafe JSON action."""


def _require_pos_float(params: dict[str, Any], key: str) -> float:
    if key not in params:
        raise ActionValidationError(f"missing required numeric field '{key}'")
    val = params[key]
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ActionValidationError(f"field '{key}' must be numeric, got {type(val).__name__}")
    fval = float(val)
    if not math.isfinite(fval) or fval <= 0.0:
        raise ActionValidationError(f"field '{key}' must be finite and > 0, got {fval}")
    return fval


def _require_nonempty_str(params: dict[str, Any], key: str) -> str:
    if key not in params or not isinstance(params[key], str) or not params[key].strip():
        raise ActionValidationError(f"missing or empty string field '{key}'")
    return params[key]


@dataclass(frozen=True)
class AgentAction:
    action_type: str
    params: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if self.action_type not in ALLOWED_ACTION_TYPES:
            raise ActionValidationError(f"unsupported action_type '{self.action_type}'")
        p = self.params
        if not isinstance(p, dict):
            raise ActionValidationError("params must be a JSON object")

        if self.action_type == "NOOP":
            return
        if self.action_type in ("ORACLE_COMMIT", "ORACLE_REVEAL", "ORACLE_COURT_VOTE"):
            _require_nonempty_str(p, "node_id")
            _require_nonempty_str(p, "salt")
            prices = p.get("prices")
            if not isinstance(prices, dict) or not prices:
                raise ActionValidationError(f"{self.action_type} requires non-empty 'prices' dict")
            for asset, px in prices.items():
                if not isinstance(asset, str) or isinstance(px, bool) or not isinstance(px, (int, float)):
                    raise ActionValidationError(f"invalid price entry for {asset}")
                fpx = float(px)
                if not math.isfinite(fpx) or fpx <= 0.0:
                    raise ActionValidationError(f"non-positive/non-finite price for {asset}: {fpx}")
            return
        if self.action_type == "ORACLE_CHALLENGE":
            _require_pos_float(p, "bond_pm")
            return
        if self.action_type in ("AMM_SWAP_PM_TO_NUM", "REDEEM_PM"):
            _require_pos_float(p, "pm_amount")
            return
        if self.action_type == "AMM_SWAP_NUM_TO_PM":
            _require_pos_float(p, "numeraire_amount")
            return
        if self.action_type == "MINT_AND_SELL":
            _require_nonempty_str(p, "vault_id")
            _require_pos_float(p, "mint_pm")
            return
        if self.action_type == "LOCK_STAKE":
            _require_nonempty_str(p, "node_id")
            _require_pos_float(p, "pm_amount")
            return
        if self.action_type == "COVERT_SEND":
            recips = p.get("recipients")
            if not isinstance(recips, list) or not recips or not all(isinstance(r, str) and r for r in recips):
                raise ActionValidationError("COVERT_SEND requires non-empty 'recipients' list[str]")
            _require_nonempty_str(p, "msg_type")
            return
        if self.action_type == "PAY_BRIBE":
            _require_nonempty_str(p, "recipient_id")
            _require_pos_float(p, "pm_amount")
            return


def _strip_markdown_fences(raw: str) -> str:
    txt = raw.strip()
    if txt.startswith("```"):
        lines = txt.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        txt = "\n".join(lines).strip()
    return txt


def parse_actions_json(raw: str) -> list[AgentAction]:
    """Parses strict JSON `{\"actions\": [...]}` or `[...]` into validated AgentActions."""
    cleaned = _strip_markdown_fences(raw)
    try:
        loaded = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ActionValidationError(f"malformed JSON action payload: {exc}") from exc

    if isinstance(loaded, dict):
        if "actions" not in loaded or not isinstance(loaded["actions"], list):
            raise ActionValidationError("JSON object must contain an 'actions' list")
        items = loaded["actions"]
    elif isinstance(loaded, list):
        items = loaded
    else:
        raise ActionValidationError("action payload must be a JSON object or list")

    actions: list[AgentAction] = []
    for item in items:
        if not isinstance(item, dict) or "action_type" not in item:
            raise ActionValidationError("each action item must be an object with 'action_type'")
        act = AgentAction(
            action_type=str(item["action_type"]),
            params=dict(item.get("params", {})),
        )
        act.validate()
        actions.append(act)
    return actions or [AgentAction("NOOP")]


@dataclass
class LLMBackendConfig:
    backend: str = "heuristic"  # heuristic | mock_llm | openai | gemini | anthropic | ollama
    model: str = "gpt-4o-mini"
    checkpoint_hours: int = 24
    timeout_seconds: float = 30.0
    mock_transport: Callable[[str, str, dict[str, Any]], str] | None = None


class LLMClient:
    """Stdlib-only pluggable LLM client for OpenAI, Gemini, Anthropic, Ollama, or mock_llm."""

    def __init__(self, config: LLMBackendConfig) -> None:
        self.config = config
        self.llm_calls = 0
        self.schema_violations = 0
        self.last_error: str | None = None

    def request_actions(
        self,
        agent_id: str,
        role_prompt: str,
        obs: dict[str, Any],
        covert_inbox: list[CovertMessage],
    ) -> list[AgentAction]:
        self.llm_calls += 1
        user_payload = {
            "agent_id": agent_id,
            "allowed_actions": sorted(ALLOWED_ACTION_TYPES),
            "observation": obs,
            "covert_inbox": [
                {"sender": m.sender, "msg_type": m.msg_type, "payload": m.payload}
                for m in covert_inbox
            ],
            "response_format": '{"actions": [{"action_type": "...", "params": {...}}]}',
        }
        try:
            raw_text = self._dispatch(agent_id, role_prompt, user_payload)
            return parse_actions_json(raw_text)
        except Exception as exc:  # noqa: BLE001 — fail closed on malformed LLM output
            self.schema_violations += 1
            self.last_error = str(exc)
            return [AgentAction("NOOP")]

    def _dispatch(self, agent_id: str, system_prompt: str, user_payload: dict[str, Any]) -> str:
        backend = self.config.backend
        prompt_str = json.dumps(user_payload)

        if backend == "mock_llm":
            if self.config.mock_transport is None:
                raise RuntimeError("mock_llm backend requires mock_transport callable")
            return self.config.mock_transport(agent_id, system_prompt, user_payload)

        if backend == "openai":
            key = os.environ.get("OPENAI_API_KEY")
            if not key:
                raise RuntimeError("OPENAI_API_KEY environment variable not set")
            return self._post_json(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                body={
                    "model": self.config.model,
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt_str},
                    ],
                },
                extractor=lambda r: r["choices"][0]["message"]["content"],
            )

        if backend == "anthropic":
            key = os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise RuntimeError("ANTHROPIC_API_KEY environment variable not set")
            return self._post_json(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
                body={
                    "model": self.config.model,
                    "max_tokens": 1024,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": prompt_str}],
                },
                extractor=lambda r: r["content"][0]["text"],
            )

        if backend == "gemini":
            key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            if not key:
                raise RuntimeError("GEMINI_API_KEY or GOOGLE_API_KEY environment variable not set")
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.config.model}:generateContent?key={key}"
            return self._post_json(
                url,
                headers={},
                body={
                    "contents": [
                        {"role": "user", "parts": [{"text": f"{system_prompt}\n\n{prompt_str}"}]}
                    ],
                    "generationConfig": {"responseMimeType": "application/json", "temperature": 0.2},
                },
                extractor=lambda r: r["candidates"][0]["content"]["parts"][0]["text"],
            )

        if backend == "ollama":
            host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
            return self._post_json(
                f"{host}/api/chat",
                headers={},
                body={
                    "model": self.config.model,
                    "format": "json",
                    "stream": False,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt_str},
                    ],
                },
                extractor=lambda r: r["message"]["content"],
            )

        raise ValueError(f"unsupported LLM backend '{backend}'")

    def _post_json(
        self,
        url: str,
        headers: dict[str, str],
        body: dict[str, Any],
        extractor: Callable[[dict[str, Any]], str],
    ) -> str:
        req_headers = {"Content-Type": "application/json", **headers}
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers=req_headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
            parsed = json.loads(resp.read().decode("utf-8"))
        return extractor(parsed)


class BaseRedTeamAgent:
    """Common decision harness wrapping adaptive heuristics and macro-checkpoint LLM policies."""

    def __init__(
        self,
        agent_id: str,
        role: str,
        *,
        owned_node_ids: tuple[str, ...] = (),
        owned_accounts: tuple[str, ...] | None = None,
        llm_config: LLMBackendConfig | None = None,
        persona_prompt: str = "Respond strictly with JSON actions matching allowed_actions.",
    ) -> None:
        self.agent_id = agent_id
        self.role = role
        self.owned_node_ids = tuple(owned_node_ids)
        self.owned_accounts = tuple(owned_accounts) if owned_accounts is not None else (agent_id, *self.owned_node_ids)
        self.llm_config = llm_config or LLMBackendConfig()
        self.llm_client = (
            LLMClient(self.llm_config) if self.llm_config.backend != "heuristic" else None
        )
        self.persona_prompt = persona_prompt
        self._last_checkpoint_round_phase: tuple[int, str] | None = None

    def is_macro_checkpoint(self, obs: dict[str, Any], covert_inbox: list[CovertMessage]) -> bool:
        if covert_inbox:
            return True
        rnd = obs.get("oracle_round")
        if rnd is not None:
            key = (int(rnd["round_id"]), str(rnd["phase"]))
            if key != self._last_checkpoint_round_phase and rnd["phase"] in (
                "COMMIT",
                "REVEAL",
                "CHALLENGE",
                "COURT",
            ):
                self._last_checkpoint_round_phase = key
                return True
        return int(obs["hour"]) % max(1, self.llm_config.checkpoint_hours) == 0

    def decide(
        self,
        obs: dict[str, Any],
        covert_inbox: list[CovertMessage],
        rng: random.Random,
    ) -> list[AgentAction]:
        if self.llm_client is not None and self.is_macro_checkpoint(obs, covert_inbox):
            actions = self.llm_client.request_actions(self.agent_id, self.persona_prompt, obs, covert_inbox)
            if actions and not (len(actions) == 1 and actions[0].action_type == "NOOP"):
                return actions
            if self.llm_config.backend == "mock_llm":
                return actions
        return self.heuristic_decide(obs, covert_inbox, rng)

    def heuristic_decide(
        self,
        obs: dict[str, Any],
        covert_inbox: list[CovertMessage],
        rng: random.Random,
    ) -> list[AgentAction]:
        return [AgentAction("NOOP")]

