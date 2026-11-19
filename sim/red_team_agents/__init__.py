"""Phase 2 Step 2 adversarial swarm personas, covert collusion bus, and LLM adapter."""

from .base_agent import (
    ALLOWED_ACTION_TYPES,
    ActionValidationError,
    AgentAction,
    BaseRedTeamAgent,
    LLMBackendConfig,
    LLMClient,
    parse_actions_json,
)
from .covert_channel import CovertChannel, CovertMessage
from .personas import (
    ArbitrageurAgent,
    GreedyWhaleAgent,
    HonestOracleEnsembleAgent,
    HonestWhistleblowerAgent,
    HostileStateAgent,
    OracleCartelAgent,
    RetailHerdAgent,
)
from .runner import EpisodeAuditRecord, RedTeamRunner, audit_episode, build_regime_episode

__all__ = [
    "ALLOWED_ACTION_TYPES",
    "ActionValidationError",
    "AgentAction",
    "ArbitrageurAgent",
    "BaseRedTeamAgent",
    "CovertChannel",
    "CovertMessage",
    "EpisodeAuditRecord",
    "GreedyWhaleAgent",
    "HonestOracleEnsembleAgent",
    "HonestWhistleblowerAgent",
    "HostileStateAgent",
    "LLMBackendConfig",
    "LLMClient",
    "OracleCartelAgent",
    "RedTeamRunner",
    "RetailHerdAgent",
    "audit_episode",
    "build_regime_episode",
    "parse_actions_json",
]

