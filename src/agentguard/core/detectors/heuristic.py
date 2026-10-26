"""Fast rule-based prompt-injection detector.

Each rule carries a weight; the score is the noisy-OR of fired rules, so one strong signal or
several weak ones flag the text. Text is normalised first (NFKC, homoglyphs, invisible chars)
and encoded payloads (base64, hex, percent, ROT13, Unicode tags) are decoded and rescanned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from agentguard.core.normalize import decode_candidates, normalize, reveal_tag_chars, rot13


@dataclass(frozen=True, slots=True)
class HeuristicRule:
    id: str
    pattern: re.Pattern[str]
    weight: float


def _r(id_: str, rx: str, weight: float) -> HeuristicRule:
    return HeuristicRule(id_, re.compile(rx, re.IGNORECASE | re.UNICODE), weight)


_IGNORE = r"(?:ignore|disregard|forget|override|bypass|skip|abandon|drop)"
_PRIOR = r"(?:all |any |the |your |these |those |my )?(?:previous|prior|above|earlier|preceding|original|initial|system|existing|old)"
_INSTR = r"(?:instructions?|prompts?|rules?|directives?|guidelines?|context|commands?|orders?|tasks?)"

RULES: tuple[HeuristicRule, ...] = (
    _r("ignore_instructions", rf"\b{_IGNORE}\b.{{0,30}}\b{_PRIOR}\b.{{0,20}}\b{_INSTR}\b", 0.85),
    _r(
        "ignore_instructions_short",
        rf"\b{_IGNORE} (?:everything|all of that|the above|what you were told)\b",
        0.6,
    ),
    _r(
        "new_instructions",
        r"\b(?:new|updated|real|actual|true|important|urgent|additional|hidden|secret) (?:instructions?|task|directive|orders?)\b\s*[:\-]",
        0.6,
    ),
    _r(
        "role_reassignment",
        r"\byou are (?:now|no longer)\b|\bfrom now on,? you\b|\bact as (?:an?|the) (?:unrestricted|jailbroken|different)\b",
        0.55,
    ),
    _r(
        "system_prompt_ref",
        r"\b(?:reveal|print|show|output|repeat|leak)\b.{0,30}\b(?:system prompt|hidden prompt|instructions above|initial prompt)\b",
        0.6,
    ),
    _r(
        "fake_role_tag",
        r"(?:^|\n)\s*(?:#{1,3}\s*)?(?:system|assistant|developer)\s*(?:message|prompt)?\s*:\s*\S",
        0.45,
    ),
    _r(
        "chat_template_tokens",
        r"<\|(?:im_start|im_end|system|assistant|user|endoftext|eot_id|start_header_id)\|>|\[/?INST\]|<<SYS>>|</?(?:system|instructions?)>",
        0.8,
    ),
    _r(
        "addressed_to_ai",
        r"\b(?:attention|note|message|instructions?) (?:to|for) (?:the )?(?:ai|assistant|llm|language model|agent|chatbot|model)\b|\b(?:dear|hey|hi) (?:ai|assistant|agent|claude|chatgpt|gpt|gemini|llm)\b",
        0.6,
    ),
    _r("if_you_are_ai", r"\bif you are an? (?:ai|llm|language model|assistant|agent|bot)\b", 0.6),
    _r(
        "do_not_tell",
        r"\b(?:do not|don't|never) (?:tell|inform|mention|reveal|alert|notify|show)\b.{0,25}\b(?:the )?(?:user|human|anyone|owner|customer)\b|\bwithout (?:telling|informing|notifying|asking) the (?:user|human)\b|\b(?:silently|secretly|quietly|covertly)\b.{0,20}\b(?:send|forward|email|delete|transfer|post|call)",
        0.75,
    ),
    _r(
        "exfil_instruction",
        r"\b(?:send|forward|email|post|upload|transmit|exfiltrate|leak|copy|share)\b.{0,60}\b(?:to|at|into)\b.{0,10}(?:[\w.+-]+@[\w-]+\.[\w.]+|https?://)",
        0.45,
    ),
    _r(
        "exfil_sensitive",
        r"\b(?:send|forward|email|post|upload|leak|share|include)\b.{0,50}\b(?:passwords?|credentials?|api[ _-]?keys?|secrets?|tokens?|ssh keys?|private keys?|credit cards?|ssn|conversation history|chat history|all (?:the )?(?:emails?|files|messages|contacts|data))\b",
        0.6,
    ),
    _r(
        "tool_invocation",
        r"\b(?:call|invoke|use|run|execute|trigger)\b.{0,15}\b(?:the )?(?:tool|function)\b.{0,30}\b(?:with|using)\b|\b(?:call|invoke|run)\s+[a-z_]{3,40}\s*\(",
        0.4,
    ),
    _r(
        "destructive_instruction",
        r"\b(?:delete|remove|wipe|erase|drop|destroy|truncate|format)\b.{0,30}\b(?:all|every|entire|the whole)\b.{0,20}\b(?:files?|data|records?|emails?|repos?(?:itory)?|database|tables?|backups?|users?|accounts?)\b|\brm\s+-rf\b|\bdrop\s+table\b",
        0.55,
    ),
    _r(
        "financial_instruction",
        r"\b(?:transfer|wire|send|pay)\b.{0,20}(?:[$€£]\s?\d|\d+\s?(?:usd|eur|gbp|dollars|euros|btc|eth))\b.{0,40}\b(?:to|into)\b",
        0.45,
    ),
    _r("markdown_image_exfil", r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(?:=|%3D)[^)\s]*\)", 0.55),
    _r(
        "urgency_override",
        r"\b(?:important|urgent|critical|mandatory|required)\b\s*[!:]{1,3}.{0,60}\b(?:must|need to|have to|immediately)\b",
        0.3,
    ),
    _r(
        "jailbreak_persona",
        r"\b(?:dan|developer mode|jailbreak|do anything now|god mode|sudo mode|unfiltered mode)\b",
        0.5,
    ),
    _r(
        "prompt_boundary",
        r"(?:^|\n)\s*(?:-{3,}|={3,}|\*{3,}|#{3,})\s*(?:end of|begin|start of)?\s*(?:document|context|content|data|input|text|email|page)\b.{0,30}(?:-{3,}|={3,}|\*{3,}|#{3,})?",
        0.25,
    ),
    _r("instead_do", r"\binstead,? (?:you (?:must|should|will)|please|do the following|perform)\b", 0.4),
    _r(
        "assistant_must",
        r"\b(?:the )?(?:assistant|ai|agent|model) (?:must|should|shall|is required to|needs to)\b",
        0.45,
    ),
    # Multilingual "ignore previous instructions" and close variants.
    _r(
        "ml_es",
        r"\b(?:ignora|olvida|omite)\b.{0,25}\b(?:instrucciones|indicaciones|reglas)\b.{0,20}\b(?:anteriores|previas)\b",
        0.85,
    ),
    _r(
        "ml_fr",
        r"\b(?:ignore[zr]?|oublie[zr]?)\b.{0,25}\b(?:instructions|consignes|règles)\b.{0,20}\b(?:précédentes|antérieures|ci-dessus)\b",
        0.85,
    ),
    _r(
        "ml_de",
        r"\b(?:ignoriere|vergiss|missachte)\b.{0,30}\b(?:vorherigen|bisherigen|obigen|vorigen)\b.{0,20}\b(?:anweisungen|instruktionen|regeln)\b",
        0.85,
    ),
    _r(
        "ml_it",
        r"\b(?:ignora|dimentica)\b.{0,25}\b(?:istruzioni|regole)\b.{0,20}\b(?:precedenti|sopra)\b",
        0.85,
    ),
    _r(
        "ml_pt",
        r"\b(?:ignore|ignora|esqueça|esqueca)\b.{0,25}\b(?:instruções|instrucoes|regras)\b.{0,20}\b(?:anteriores|prévias)\b",
        0.85,
    ),
    _r(
        "ml_nl",
        r"\b(?:negeer|vergeet)\b.{0,25}\b(?:vorige|eerdere|bovenstaande)\b.{0,20}\b(?:instructies|regels)\b",
        0.85,
    ),
    _r(
        "ml_ru",
        r"(?:игнорируй|игнорируйте|забудь|забудьте)\b.{0,30}(?:предыдущие|прошлые|все)\b.{0,20}(?:инструкции|указания|правила)",
        0.85,
    ),
    _r(
        "ml_pl",
        r"\b(?:zignoruj|ignoruj|zapomnij)\b.{0,30}\b(?:poprzednie|wcześniejsze)\b.{0,20}\b(?:instrukcje|polecenia)\b",
        0.85,
    ),
    _r(
        "ml_tr",
        r"\b(?:önceki|yukarıdaki)\b.{0,20}\b(?:talimatları|komutları)\b.{0,20}\b(?:yok say|görmezden gel|unut)",
        0.85,
    ),
    _r(
        "ml_zh",
        r"(?:忽略|无视|忘记|忽視|無視)(?:之前|以上|上面|先前|所有|前面)?的?(?:所有)?(?:指令|指示|说明|規則|规则|提示)",
        0.85,
    ),
    _r("ml_ja", r"(?:以前|前|上記|これまで)の(?:指示|命令|ルール)を(?:無視|忘れ)", 0.85),
    _r("ml_ko", r"(?:이전|위의|앞의)\s?(?:지시|명령|지침)(?:을|를|사항을)?\s?(?:무시|잊어)", 0.85),
    _r("ml_ar", r"(?:تجاهل|انس)\s.{0,20}(?:التعليمات|الأوامر)\s.{0,10}(?:السابقة)", 0.85),
    _r("ml_hi", r"(?:पिछले|पहले के)\s.{0,15}(?:निर्देशों|निर्देश)\s.{0,15}(?:को अनदेखा|को भूल|नज़रअंदाज़)", 0.85),
)

_ZW = re.compile(r"[\u200b-\u200f\u2060-\u2064\ufeff]")
MAX_SCAN_CHARS = 100_000


def _noisy_or(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - w
    return 1.0 - p


class HeuristicDetector:
    name = "heuristic"

    def __init__(self, threshold: float = 0.5, rules: tuple[HeuristicRule, ...] = RULES) -> None:
        self.threshold = threshold
        self.rules = rules

    def _scan(self, text: str) -> dict[str, float]:
        fired: dict[str, float] = {}
        for rule in self.rules:
            if rule.pattern.search(text):
                fired[rule.id] = rule.weight
        return fired

    def score(self, text: str) -> tuple[float, tuple[str, ...]]:
        if not text:
            return 0.0, ()
        raw = text[:MAX_SCAN_CHARS]
        norm = normalize(raw)
        fired = self._scan(norm)

        hidden = reveal_tag_chars(raw)
        if hidden:
            fired["unicode_tag_smuggling"] = 0.7
            fired.update({f"tags:{k}": v for k, v in self._scan(normalize(hidden)).items()})
        if len(_ZW.findall(raw)) >= 8:
            fired["zero_width_flood"] = 0.3

        for enc, decoded in decode_candidates(raw):
            if enc == "unicode_tags":
                continue
            inner = self._scan(normalize(decoded))
            if inner:
                fired[f"encoded_{enc}"] = 0.4
                fired.update({f"{enc}:{k}": v for k, v in inner.items()})

        if "rot13" in norm or "rot-13" in norm:
            inner = self._scan(normalize(rot13(norm)))
            if inner:
                fired["encoded_rot13"] = 0.4
                fired.update({f"rot13:{k}": v for k, v in inner.items()})

        if not fired:
            return 0.0, ()
        return round(_noisy_or(list(fired.values())), 4), tuple(sorted(fired))
