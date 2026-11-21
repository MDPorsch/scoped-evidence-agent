"""The offline stand-in model: deterministic, no connection. It lets the whole path be tried without a key."""

from __future__ import annotations

from scopedagent.ai.protocol import RewordReply, RewordRequest

PREFIX = "Put simply: "


class OfflineModel:
    provider = "offline"
    model = "offline-fixture"

    def reword(self, request: RewordRequest) -> RewordReply:
        texts = {i.id: (PREFIX + i.text if len(PREFIX + i.text) <= i.limit else i.text) for i in request.items}
        return RewordReply(texts, 0, 0)
