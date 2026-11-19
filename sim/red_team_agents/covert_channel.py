"""Private covert collusion channel for cartel bribery, coordination, and defection."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class CovertMessage:
    msg_id: int
    hour: int
    round_id: int | None
    sender: str
    recipients: list[str]
    msg_type: str
    payload: dict[str, Any] = field(default_factory=dict)


class CovertChannel:
    """Off-band agent messaging bus tracking collusion, bribes, and defection transcripts."""

    def __init__(self) -> None:
        self._messages: list[CovertMessage] = []
        self._cursors: dict[str, int] = {}
        self._stats: dict[str, int] = {
            "total_messages": 0,
            "bribe_offers": 0,
            "bribes_accepted": 0,
            "defections_to_whistleblow": 0,
            "coordinated_quotes": 0,
        }

    def send(
        self,
        *,
        hour: int,
        round_id: int | None,
        sender: str,
        recipients: list[str],
        msg_type: str,
        payload: dict[str, Any] | None = None,
    ) -> CovertMessage:
        msg = CovertMessage(
            msg_id=len(self._messages) + 1,
            hour=hour,
            round_id=round_id,
            sender=sender,
            recipients=list(recipients),
            msg_type=msg_type,
            payload=dict(payload or {}),
        )
        self._messages.append(msg)
        self._stats["total_messages"] += 1
        if msg_type == "BRIBE_OFFER":
            self._stats["bribe_offers"] += 1
        elif msg_type == "BRIBE_ACCEPT":
            self._stats["bribes_accepted"] += 1
        elif msg_type == "BRIBE_DEFECT_WHISTLEBLOW":
            self._stats["defections_to_whistleblow"] += 1
        elif msg_type == "COORDINATED_QUOTE":
            self._stats["coordinated_quotes"] += 1
        return msg

    def poll(self, agent_id: str) -> list[CovertMessage]:
        start = self._cursors.get(agent_id, 0)
        inbox: list[CovertMessage] = []
        for idx in range(start, len(self._messages)):
            msg = self._messages[idx]
            if msg.sender == agent_id:
                continue
            if agent_id in msg.recipients or "*" in msg.recipients:
                inbox.append(msg)
        self._cursors[agent_id] = len(self._messages)
        return inbox

    def transcript(self) -> list[dict[str, Any]]:
        return [asdict(m) for m in self._messages]

    def stats(self) -> dict[str, int]:
        return dict(self._stats)

