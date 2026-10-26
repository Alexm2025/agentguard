"""AgentGuard Enterprise features. Licensed under the AgentGuard Enterprise License (see ee/LICENSE).

Installed as the ``agentguard.plugins`` entry point ``ee``; :func:`install` wires the features that
are configured through environment variables into the control-plane app.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("agentguard.ee")


def install(app: Any) -> None:
    from agentguard_ee import multitenancy, oidc, siem, slack

    app.state.features["edition"] = "enterprise"
    app.include_router(multitenancy.router)
    if (cfg := oidc.OidcConfig.from_env()) is not None:
        app.state.oidc = oidc.OidcClient(cfg)
        app.include_router(oidc.router)
        app.state.features["oidc"] = True
    for fwd in siem.forwarders_from_env():
        app.state.event_forwarders.append(fwd)
    if (scfg := slack.SlackConfig.from_env()) is not None:
        app.state.slack = scfg
        app.state.approval_notifiers.append(slack.notifier)
        app.include_router(slack.router)
        app.state.features["slack"] = True
    log.info("enterprise features enabled: %s", sorted(k for k, v in app.state.features.items() if v is True))
