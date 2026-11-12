"""Shared data types used by every module (kept tiny on purpose)."""
from dataclasses import dataclass, field
from typing import Any, Dict, List

MODE_INSECURE = "insecure"
MODE_SECURE = "secure"
MODES = (MODE_INSECURE, MODE_SECURE)

LINK_SENSOR_GATEWAY = "sensor->gateway"
LINK_GATEWAY_CLOUD = "gateway->cloud"


@dataclass
class Result:
    """Outcome of handing a message or request to a component."""
    accepted: bool
    reason: str = ""
    data: Any = None


@dataclass
class AttackResult:
    """Outcome of one attack run against one system."""
    name: str
    mode: str
    attempts: int = 0
    successes: int = 0
    details: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def blocked(self) -> int:
        return self.attempts - self.successes

    @property
    def success_rate(self) -> float:
        """Percentage of attempts that achieved the attacker's goal."""
        return 100.0 * self.successes / self.attempts if self.attempts else 0.0

    def record(self, technique: str, success: bool, reason: str) -> None:
        self.attempts += 1
        if success:
            self.successes += 1
        self.details.append({"technique": technique, "success": success,
                             "reason": reason})

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "mode": self.mode,
                "attempts": self.attempts, "successes": self.successes,
                "blocked": self.blocked,
                "success_rate": round(self.success_rate, 1),
                "details": self.details}
