# Policy schema

Generated from the code at build time (`agentguard policy schema` prints the full JSON Schema).

## Policy (top level)

| Field | Type | Default | Description |
|---|---|---|---|
| `version` | integer | `1` | Policy schema version. |
| `extends` | `default` | `none` | `"default"` | `default` layers this policy over the built-in default policy (your tools are matched first, rules with the same id replace default rules). `none` starts empty. |
| `name` | string | `"default"` |  |
| `revision` | integer | `1` | Monotonic policy revision. |
| `description` | string | |  |
| `settings` | Settings | |  |
| `tools` | object | | Keys may be glob patterns. |
| `dlp_patterns` | array | |  |
| `rules` | array | |  |

## Action

One of: `ALLOW`, `REDACT`, `REQUIRE_APPROVAL`, `BLOCK`

## ApprovalSettings



| Field | Type | Default | Description |
|---|---|---|---|
| `timeout_seconds` | number | `300` |  |
| `on_timeout` | `BLOCK` | `ALLOW` | `"BLOCK"` |  |

## ArgCondition



| Field | Type | Default | Description |
|---|---|---|---|
| `path` | string | |  |
| `matches` | string | null | `null` |  |
| `not_matches` | string | null | `null` |  |
| `equals` | string | integer | number | boolean | null | `null` |  |
| `in` | array | null | `null` |  |
| `min_len` | integer | null | `null` |  |
| `max_len` | integer | null | `null` |  |

## CustomDlpPattern



| Field | Type | Default | Description |
|---|---|---|---|
| `id` | string | |  |
| `regex` | string | |  |
| `validator` | string | `"none"` |  |
| `category` | `secret` | `pii` | `custom` | `"custom"` |  |

## DestinationRule

Allow/deny list for an argument that names where data goes.

| Field | Type | Default | Description |
|---|---|---|---|
| `arg` | string | | Argument path, e.g. `to` or `recipients.*`. |
| `kind` | `email` | `domain` | `url` | `path` | `glob` | |  |
| `allow` | array | | Glob patterns; empty means allow all not denied. |
| `deny` | array | |  |
| `on_violation` | Action | `"BLOCK"` |  |

## DetectorSettings



| Field | Type | Default | Description |
|---|---|---|---|
| `heuristic` | HeuristicSettings | |  |
| `ml` | MlSettings | |  |
| `judge` | JudgeSettings | |  |
| `scan_tool_descriptions` | boolean | `true` |  |

## FailMode

One of: `closed`, `open`

## HeuristicSettings



| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` |  |
| `threshold` | number | `0.5` |  |

## JudgeSettings



| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` |  |
| `provider` | `openai` | `anthropic` | `"openai"` |  |
| `model` | string | `"gpt-4.1-mini"` |  |
| `min_risk` | Risk | `"high"` |  |
| `only_when_tainted` | boolean | `true` |  |
| `timeout_seconds` | number | `8.0` |  |
| `base_url` | string | null | `null` |  |
| `on_block` | `BLOCK` | `REQUIRE_APPROVAL` | `"BLOCK"` |  |
| `min_confidence` | number | `0.5` |  |

## MlSettings



| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` |  |
| `model` | string | `"auto"` | Path to the ONNX model directory, or `auto`. |
| `threshold` | number | `0.85` |  |
| `required` | boolean | `false` | Fail if the model cannot be loaded. |
| `min_words` | integer | `4` | Skip the ML layer for texts with fewer words. |

## RateLimit



| Field | Type | Default | Description |
|---|---|---|---|
| `max_calls` | integer | |  |
| `per_seconds` | number | |  |
| `scope` | `session` | `project` | `tenant` | `"session"` |  |
| `on_exceed` | Action | `"BLOCK"` |  |

## ResultPolicy



| Field | Type | Default | Description |
|---|---|---|---|
| `scan` | boolean | `true` |  |
| `on_injection` | Action | `"ALLOW"` | ALLOW keeps the result (it stays tainted and is tracked); REDACT replaces flagged content with a notice; BLOCK withholds the whole result. |
| `dlp` | ToolDlp | `null` |  |

## Risk

One of: `low`, `medium`, `high`, `critical`

## Rule



| Field | Type | Default | Description |
|---|---|---|---|
| `id` | string | |  |
| `description` | string | |  |
| `enabled` | boolean | `true` |  |
| `tools` | array | |  |
| `roles` | array | null | `null` |  |
| `min_risk` | Risk | `null` |  |
| `when` | When | |  |
| `action` | Action | |  |
| `message` | string | null | `null` |  |
| `override` | boolean | `false` | An ALLOW rule with override=true wins over others. |

## Settings



| Field | Type | Default | Description |
|---|---|---|---|
| `fail_mode` | FailMode | `"closed"` |  |
| `fail_open_max_risk` | Risk | `"medium"` | With fail_mode=open, tools above this risk still fail closed. |
| `default_action` | Action | `"ALLOW"` |  |
| `unknown_tool` | ToolPolicy | | Defaults for tools not listed under `tools`. |
| `taint` | TaintSettings | |  |
| `detectors` | DetectorSettings | |  |
| `approvals` | ApprovalSettings | |  |
| `max_argument_chars` | integer | `1000000` |  |

## TaintSettings



| Field | Type | Default | Description |
|---|---|---|---|
| `min_substring_len` | integer | `8` |  |
| `fuzzy_threshold` | number | `88.0` |  |
| `shingle_containment` | number | `0.6` |  |
| `semantic` | boolean | `false` |  |
| `semantic_threshold` | number | `0.82` |  |
| `decode` | boolean | `true` |  |

## ToolDlp



| Field | Type | Default | Description |
|---|---|---|---|
| `patterns` | array | |  |
| `on_match` | Action | `"BLOCK"` |  |

## ToolPolicy



| Field | Type | Default | Description |
|---|---|---|---|
| `description` | string | |  |
| `role` | ToolRole | `null` |  |
| `risk` | Risk | `null` |  |
| `trusted_output` | boolean | `false` | Treat this tool's results as trusted. |
| `ref_arg` | string | null | `null` | Argument identifying the source, e.g. `url`. |
| `destination_args` | array | | Arguments that select a recipient/target (e.g. `to`, `url`). |
| `destinations` | array | |  |
| `rate_limit` | RateLimit | `null` |  |
| `dlp` | ToolDlp | `null` |  |
| `fail_mode` | FailMode | `null` |  |
| `judge` | boolean | null | `null` | Force the LLM judge on/off for this tool. |
| `result` | ResultPolicy | |  |
| `action` | Action | `null` | Unconditional action for this tool. |

## ToolRole

One of: `source`, `sink`, `both`, `neutral`

## When



| Field | Type | Default | Description |
|---|---|---|---|
| `tainted_context` | boolean | null | `null` | Any tainted content in context. |
| `tainted_args` | array | string | null | `null` | Arguments whose value is derived from tainted content. `destination` means the tool's `destination_args` (and destination rule args). |
| `taint_kinds` | array | null | `null` | Restrict tainted_args to these match kinds (prefix match, e.g. `entity`). |
| `min_taint_score` | number | `0.0` |  |
| `injection_detected` | boolean | null | `null` | A detector flagged tainted content. |
| `min_injection_score` | number | `0.0` |  |
| `dlp` | array | string | null | `null` |  |
| `destination_violation` | boolean | null | `null` |  |
| `args` | array | |  |
| `judge_flagged` | boolean | null | `null` |  |

## Raw JSON Schema

```json
{
  "$defs": {
    "Action": {
      "enum": [
        "ALLOW",
        "REDACT",
        "REQUIRE_APPROVAL",
        "BLOCK"
      ],
      "title": "Action",
      "type": "string"
    },
    "ApprovalSettings": {
      "additionalProperties": false,
      "properties": {
        "timeout_seconds": {
          "default": 300,
          "exclusiveMinimum": 0,
          "maximum": 86400,
          "title": "Timeout Seconds",
          "type": "number"
        },
        "on_timeout": {
          "default": "BLOCK",
          "enum": [
            "BLOCK",
            "ALLOW"
          ],
          "title": "On Timeout",
          "type": "string"
        }
      },
      "title": "ApprovalSettings",
      "type": "object"
    },
    "ArgCondition": {
      "additionalProperties": false,
      "properties": {
        "path": {
          "title": "Path",
          "type": "string"
        },
        "matches": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Matches"
        },
        "not_matches": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Not Matches"
        },
        "equals": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "integer"
            },
            {
              "type": "number"
            },
            {
              "type": "boolean"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Equals"
        },
        "in": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "In"
        },
        "min_len": {
          "anyOf": [
            {
              "type": "integer"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Min Len"
        },
        "max_len": {
          "anyOf": [
            {
              "type": "integer"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Max Len"
        }
      },
      "required": [
        "path"
      ],
      "title": "ArgCondition",
      "type": "object"
    },
    "CustomDlpPattern": {
      "additionalProperties": false,
      "properties": {
        "id": {
          "pattern": "^[a-z0-9_]+$",
          "title": "Id",
          "type": "string"
        },
        "regex": {
          "title": "Regex",
          "type": "string"
        },
        "validator": {
          "default": "none",
          "title": "Validator",
          "type": "string"
        },
        "category": {
          "default": "custom",
          "enum": [
            "secret",
            "pii",
            "custom"
          ],
          "title": "Category",
          "type": "string"
        }
      },
      "required": [
        "id",
        "regex"
      ],
      "title": "CustomDlpPattern",
      "type": "object"
    },
    "DestinationRule": {
      "additionalProperties": false,
      "description": "Allow/deny list for an argument that names where data goes.",
      "properties": {
        "arg": {
          "description": "Argument path, e.g. `to` or `recipients.*`.",
          "title": "Arg",
          "type": "string"
        },
        "kind": {
          "enum": [
            "email",
            "domain",
            "url",
            "path",
            "glob"
          ],
          "title": "Kind",
          "type": "string"
        },
        "allow": {
          "description": "Glob patterns; empty means allow all not denied.",
          "items": {
            "type": "string"
          },
          "title": "Allow",
          "type": "array"
        },
        "deny": {
          "items": {
            "type": "string"
          },
          "title": "Deny",
          "type": "array"
        },
        "on_violation": {
          "$ref": "#/$defs/Action",
          "default": "BLOCK"
        }
      },
      "required": [
        "arg",
        "kind"
      ],
      "title": "DestinationRule",
      "type": "object"
    },
    "DetectorSettings": {
      "additionalProperties": false,
      "properties": {
        "heuristic": {
          "$ref": "#/$defs/HeuristicSettings"
        },
        "ml": {
          "$ref": "#/$defs/MlSettings"
        },
        "judge": {
          "$ref": "#/$defs/JudgeSettings"
        },
        "scan_tool_descriptions": {
          "default": true,
          "title": "Scan Tool Descriptions",
          "type": "boolean"
        }
      },
      "title": "DetectorSettings",
      "type": "object"
    },
    "FailMode": {
      "enum": [
        "closed",
        "open"
      ],
      "title": "FailMode",
      "type": "string"
    },
    "HeuristicSettings": {
      "additionalProperties": false,
      "properties": {
        "enabled": {
          "default": true,
          "title": "Enabled",
          "type": "boolean"
        },
        "threshold": {
          "default": 0.5,
          "maximum": 1,
          "minimum": 0,
          "title": "Threshold",
          "type": "number"
        }
      },
      "title": "HeuristicSettings",
      "type": "object"
    },
    "JudgeSettings": {
      "additionalProperties": false,
      "properties": {
        "enabled": {
          "default": false,
          "title": "Enabled",
          "type": "boolean"
        },
        "provider": {
          "default": "openai",
          "enum": [
            "openai",
            "anthropic"
          ],
          "title": "Provider",
          "type": "string"
        },
        "model": {
          "default": "gpt-4.1-mini",
          "title": "Model",
          "type": "string"
        },
        "min_risk": {
          "$ref": "#/$defs/Risk",
          "default": "high"
        },
        "only_when_tainted": {
          "default": true,
          "title": "Only When Tainted",
          "type": "boolean"
        },
        "timeout_seconds": {
          "default": 8.0,
          "exclusiveMinimum": 0,
          "maximum": 120,
          "title": "Timeout Seconds",
          "type": "number"
        },
        "base_url": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Base Url"
        },
        "on_block": {
          "default": "BLOCK",
          "enum": [
            "BLOCK",
            "REQUIRE_APPROVAL"
          ],
          "title": "On Block",
          "type": "string"
        },
        "min_confidence": {
          "default": 0.5,
          "maximum": 1,
          "minimum": 0,
          "title": "Min Confidence",
          "type": "number"
        }
      },
      "title": "JudgeSettings",
      "type": "object"
    },
    "MlSettings": {
      "additionalProperties": false,
      "properties": {
        "enabled": {
          "default": true,
          "title": "Enabled",
          "type": "boolean"
        },
        "model": {
          "default": "auto",
          "description": "Path to the ONNX model directory, or `auto`.",
          "title": "Model",
          "type": "string"
        },
        "threshold": {
          "default": 0.85,
          "maximum": 1,
          "minimum": 0,
          "title": "Threshold",
          "type": "number"
        },
        "required": {
          "default": false,
          "description": "Fail if the model cannot be loaded.",
          "title": "Required",
          "type": "boolean"
        },
        "min_words": {
          "default": 4,
          "description": "Skip the ML layer for texts with fewer words.",
          "minimum": 0,
          "title": "Min Words",
          "type": "integer"
        }
      },
      "title": "MlSettings",
      "type": "object"
    },
    "RateLimit": {
      "additionalProperties": false,
      "properties": {
        "max_calls": {
          "exclusiveMinimum": 0,
          "maximum": 1000000,
          "title": "Max Calls",
          "type": "integer"
        },
        "per_seconds": {
          "exclusiveMinimum": 0,
          "maximum": 2678400,
          "title": "Per Seconds",
          "type": "number"
        },
        "scope": {
          "default": "session",
          "enum": [
            "session",
            "project",
            "tenant"
          ],
          "title": "Scope",
          "type": "string"
        },
        "on_exceed": {
          "$ref": "#/$defs/Action",
          "default": "BLOCK"
        }
      },
      "required": [
        "max_calls",
        "per_seconds"
      ],
      "title": "RateLimit",
      "type": "object"
    },
    "ResultPolicy": {
      "additionalProperties": false,
      "properties": {
        "scan": {
          "default": true,
          "title": "Scan",
          "type": "boolean"
        },
        "on_injection": {
          "$ref": "#/$defs/Action",
          "default": "ALLOW",
          "description": "ALLOW keeps the result (it stays tainted and is tracked); REDACT replaces flagged content with a notice; BLOCK withholds the whole result."
        },
        "dlp": {
          "anyOf": [
            {
              "$ref": "#/$defs/ToolDlp"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        }
      },
      "title": "ResultPolicy",
      "type": "object"
    },
    "Risk": {
      "enum": [
        "low",
        "medium",
        "high",
        "critical"
      ],
      "title": "Risk",
      "type": "string"
    },
    "Rule": {
      "additionalProperties": false,
      "properties": {
        "id": {
          "maxLength": 100,
          "minLength": 1,
          "pattern": "^[\\w.\\-]+$",
          "title": "Id",
          "type": "string"
        },
        "description": {
          "default": "",
          "title": "Description",
          "type": "string"
        },
        "enabled": {
          "default": true,
          "title": "Enabled",
          "type": "boolean"
        },
        "tools": {
          "items": {
            "maxLength": 200,
            "minLength": 1,
            "pattern": "^[\\w.\\-:/*?\\[\\]]+$",
            "type": "string"
          },
          "title": "Tools",
          "type": "array"
        },
        "roles": {
          "anyOf": [
            {
              "items": {
                "$ref": "#/$defs/ToolRole"
              },
              "type": "array"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Roles"
        },
        "min_risk": {
          "anyOf": [
            {
              "$ref": "#/$defs/Risk"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        },
        "when": {
          "$ref": "#/$defs/When"
        },
        "action": {
          "$ref": "#/$defs/Action"
        },
        "message": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Message"
        },
        "override": {
          "default": false,
          "description": "An ALLOW rule with override=true wins over others.",
          "title": "Override",
          "type": "boolean"
        }
      },
      "required": [
        "id",
        "action"
      ],
      "title": "Rule",
      "type": "object"
    },
    "Settings": {
      "additionalProperties": false,
      "properties": {
        "fail_mode": {
          "$ref": "#/$defs/FailMode",
          "default": "closed"
        },
        "fail_open_max_risk": {
          "$ref": "#/$defs/Risk",
          "default": "medium",
          "description": "With fail_mode=open, tools above this risk still fail closed."
        },
        "default_action": {
          "$ref": "#/$defs/Action",
          "default": "ALLOW"
        },
        "unknown_tool": {
          "$ref": "#/$defs/ToolPolicy",
          "description": "Defaults for tools not listed under `tools`."
        },
        "taint": {
          "$ref": "#/$defs/TaintSettings"
        },
        "detectors": {
          "$ref": "#/$defs/DetectorSettings"
        },
        "approvals": {
          "$ref": "#/$defs/ApprovalSettings"
        },
        "max_argument_chars": {
          "default": 1000000,
          "exclusiveMinimum": 0,
          "title": "Max Argument Chars",
          "type": "integer"
        }
      },
      "title": "Settings",
      "type": "object"
    },
    "TaintSettings": {
      "additionalProperties": false,
      "properties": {
        "min_substring_len": {
          "default": 8,
          "minimum": 3,
          "title": "Min Substring Len",
          "type": "integer"
        },
        "fuzzy_threshold": {
          "default": 88.0,
          "maximum": 100,
          "minimum": 50,
          "title": "Fuzzy Threshold",
          "type": "number"
        },
        "shingle_containment": {
          "default": 0.6,
          "exclusiveMinimum": 0,
          "maximum": 1,
          "title": "Shingle Containment",
          "type": "number"
        },
        "semantic": {
          "default": false,
          "title": "Semantic",
          "type": "boolean"
        },
        "semantic_threshold": {
          "default": 0.82,
          "exclusiveMinimum": 0,
          "maximum": 1,
          "title": "Semantic Threshold",
          "type": "number"
        },
        "decode": {
          "default": true,
          "title": "Decode",
          "type": "boolean"
        }
      },
      "title": "TaintSettings",
      "type": "object"
    },
    "ToolDlp": {
      "additionalProperties": false,
      "properties": {
        "patterns": {
          "items": {
            "type": "string"
          },
          "minItems": 1,
          "title": "Patterns",
          "type": "array"
        },
        "on_match": {
          "$ref": "#/$defs/Action",
          "default": "BLOCK"
        }
      },
      "required": [
        "patterns"
      ],
      "title": "ToolDlp",
      "type": "object"
    },
    "ToolPolicy": {
      "additionalProperties": false,
      "properties": {
        "description": {
          "default": "",
          "title": "Description",
          "type": "string"
        },
        "role": {
          "anyOf": [
            {
              "$ref": "#/$defs/ToolRole"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        },
        "risk": {
          "anyOf": [
            {
              "$ref": "#/$defs/Risk"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        },
        "trusted_output": {
          "default": false,
          "description": "Treat this tool's results as trusted.",
          "title": "Trusted Output",
          "type": "boolean"
        },
        "ref_arg": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Argument identifying the source, e.g. `url`.",
          "title": "Ref Arg"
        },
        "destination_args": {
          "description": "Arguments that select a recipient/target (e.g. `to`, `url`).",
          "items": {
            "type": "string"
          },
          "title": "Destination Args",
          "type": "array"
        },
        "destinations": {
          "items": {
            "$ref": "#/$defs/DestinationRule"
          },
          "title": "Destinations",
          "type": "array"
        },
        "rate_limit": {
          "anyOf": [
            {
              "$ref": "#/$defs/RateLimit"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        },
        "dlp": {
          "anyOf": [
            {
              "$ref": "#/$defs/ToolDlp"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        },
        "fail_mode": {
          "anyOf": [
            {
              "$ref": "#/$defs/FailMode"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        },
        "judge": {
          "anyOf": [
            {
              "type": "boolean"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Force the LLM judge on/off for this tool.",
          "title": "Judge"
        },
        "result": {
          "$ref": "#/$defs/ResultPolicy"
        },
        "action": {
          "anyOf": [
            {
              "$ref": "#/$defs/Action"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Unconditional action for this tool."
        }
      },
      "title": "ToolPolicy",
      "type": "object"
    },
    "ToolRole": {
      "enum": [
        "source",
        "sink",
        "both",
        "neutral"
      ],
      "title": "ToolRole",
      "type": "string"
    },
    "When": {
      "additionalProperties": false,
      "properties": {
        "tainted_context": {
          "anyOf": [
            {
              "type": "boolean"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Any tainted content in context.",
          "title": "Tainted Context"
        },
        "tainted_args": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            {
              "enum": [
                "any",
                "destination"
              ],
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Arguments whose value is derived from tainted content. `destination` means the tool's `destination_args` (and destination rule args).",
          "title": "Tainted Args"
        },
        "taint_kinds": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Restrict tainted_args to these match kinds (prefix match, e.g. `entity`).",
          "title": "Taint Kinds"
        },
        "min_taint_score": {
          "default": 0.0,
          "maximum": 1,
          "minimum": 0,
          "title": "Min Taint Score",
          "type": "number"
        },
        "injection_detected": {
          "anyOf": [
            {
              "type": "boolean"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "A detector flagged tainted content.",
          "title": "Injection Detected"
        },
        "min_injection_score": {
          "default": 0.0,
          "maximum": 1,
          "minimum": 0,
          "title": "Min Injection Score",
          "type": "number"
        },
        "dlp": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            {
              "const": "any",
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Dlp"
        },
        "destination_violation": {
          "anyOf": [
            {
              "type": "boolean"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Destination Violation"
        },
        "args": {
          "items": {
            "$ref": "#/$defs/ArgCondition"
          },
          "title": "Args",
          "type": "array"
        },
        "judge_flagged": {
          "anyOf": [
            {
              "type": "boolean"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Judge Flagged"
        }
      },
      "title": "When",
      "type": "object"
    }
  },
  "additionalProperties": false,
  "properties": {
    "version": {
      "const": 1,
      "default": 1,
      "description": "Policy schema version.",
      "title": "Version",
      "type": "integer"
    },
    "extends": {
      "default": "default",
      "description": "`default` layers this policy over the built-in default policy (your tools are matched first, rules with the same id replace default rules). `none` starts empty.",
      "enum": [
        "default",
        "none"
      ],
      "title": "Extends",
      "type": "string"
    },
    "name": {
      "default": "default",
      "maxLength": 100,
      "minLength": 1,
      "title": "Name",
      "type": "string"
    },
    "revision": {
      "default": 1,
      "description": "Monotonic policy revision.",
      "minimum": 1,
      "title": "Revision",
      "type": "integer"
    },
    "description": {
      "default": "",
      "title": "Description",
      "type": "string"
    },
    "settings": {
      "$ref": "#/$defs/Settings"
    },
    "tools": {
      "additionalProperties": {
        "$ref": "#/$defs/ToolPolicy"
      },
      "description": "Keys may be glob patterns.",
      "title": "Tools",
      "type": "object"
    },
    "dlp_patterns": {
      "items": {
        "$ref": "#/$defs/CustomDlpPattern"
      },
      "title": "Dlp Patterns",
      "type": "array"
    },
    "rules": {
      "items": {
        "$ref": "#/$defs/Rule"
      },
      "title": "Rules",
      "type": "array"
    }
  },
  "title": "AgentGuard policy",
  "type": "object",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://agentguard.dev/schemas/policy-v1.json"
}
```
