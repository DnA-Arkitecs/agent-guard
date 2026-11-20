"""agent-guard: deterministic pre-execution security firewall for autonomous AI agents."""
from .guard import Guard
from .policy import AgentPolicy, Policy
from .session import Session, SessionStore
from .sqlguard import check_sql
from .types import Decision, Finding

__version__ = "1.1.0"
__all__ = ["Guard", "Policy", "AgentPolicy", "Session", "SessionStore", "Decision", "Finding", "check_sql", "__version__"]
