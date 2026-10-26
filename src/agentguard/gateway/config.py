"""Gateway configuration (YAML file + environment variables).

```yaml
policy: ./agentguard.yaml            # or omit for the default policy
pins_file: ./.agentguard-pins.json   # MCP tool-definition pins (rug-pull detection)
auth:
  mode: static                       # static | control_plane | none (local development only)
  keys:                              # sha256 digests: `agentguard key hash <key>`
    3f1c...: { tenant_id: acme, project_id: support-bot }
control_plane:
  url: https://agentguard.internal
  token_env: AGENTGUARD_SERVICE_TOKEN
mcp:
  on_poisoned_tool: remove           # remove | allow
  on_changed_tool: remove
  servers:
    - name: mail
      url: http://localhost:9000/mcp
      headers: { Authorization: "Bearer ${MAIL_TOKEN}" }
llm:
  openai_base_url: https://api.openai.com
  anthropic_base_url: https://api.anthropic.com
  strict: false                      # true: answer 403 instead of rewriting responses
```

``${VAR}`` references are expanded from the environment, so secrets stay out of the file.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

_ENV = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AuthConfig(_M):
    mode: Literal["static", "control_plane", "none"] = "static"
    keys: dict[str, dict[str, Any]] = Field(default_factory=dict)


class ControlPlaneConfig(_M):
    url: str | None = None
    token_env: str = "AGENTGUARD_SERVICE_TOKEN"  # noqa: S105 - name of an env var, not a secret


class McpServerConfig(_M):
    name: str = Field(pattern=r"^[a-zA-Z0-9_\-]+$")
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    forward_authorization: bool = False


class McpConfig(_M):
    on_poisoned_tool: Literal["remove", "allow"] = "remove"
    on_changed_tool: Literal["remove", "allow"] = "remove"
    servers: list[McpServerConfig] = Field(default_factory=list)


class LlmConfig(_M):
    openai_base_url: str = "https://api.openai.com"
    anthropic_base_url: str = "https://api.anthropic.com"
    strict: bool = False
    timeout_seconds: float = 600.0


class GatewayConfig(_M):
    policy: str | None = None
    pins_file: str | None = None
    events_file: str | None = None
    auth: AuthConfig = Field(default_factory=AuthConfig)
    control_plane: ControlPlaneConfig = Field(default_factory=ControlPlaneConfig)
    mcp: McpConfig = Field(default_factory=McpConfig)
    llm: LlmConfig = Field(default_factory=LlmConfig)


def load_gateway_config(path: str | Path | None) -> GatewayConfig:
    data: dict[str, Any] = {}
    if path:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    data = expand_env(data)
    if env_policy := os.environ.get("AGENTGUARD_POLICY"):
        data.setdefault("policy", env_policy)
    if env_cp := os.environ.get("AGENTGUARD_CONTROL_PLANE_URL"):
        data.setdefault("control_plane", {})["url"] = env_cp
    return GatewayConfig.model_validate(data)
