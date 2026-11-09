"""Product risk register (JSTQB FL v4.0 §5.2). Single source of truth.

Risk level = likelihood x impact (each 1-3). Tests declare the risks they mitigate with
``@pytest.mark.risk("R01", ...)``; ``tests/test_traceability.py`` fails if any risk has no test
or any test has no risk (bidirectional traceability, §1.4.4).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Risk:
    id: str
    title: str
    likelihood: int
    impact: int

    @property
    def level(self) -> int:
        return self.likelihood * self.impact


RISKS: dict[str, Risk] = {
    r.id: r
    for r in [
        Risk("R01", "Unauthorized party completes consent (password guessing/bypass)", 2, 3),
        Risk("R02", "Authorization code delivered to attacker (redirect manipulation)", 2, 3),
        Risk("R03", "Stolen refresh token keeps working (no rotation/reuse detection)", 2, 3),
        Risk("R04", "Expired/revoked/foreign token accepted at /mcp", 2, 3),
        Risk("R05", "Read-only grant performs writes (scope escalation, prompt injection)", 3, 3),
        Risk("R06", "Garmin/OAuth secrets leak via output, logs or file permissions", 2, 3),
        Risk("R07", "Resource exhaustion via unauthenticated endpoints", 2, 2),
        Risk("R08", "XSS / clickjacking / caching on the consent page", 2, 3),
        Risk("R09", "Server starts with insecure configuration", 2, 3),
        Risk("R10", "Malformed tool input reaches Garmin (path tricks, bad dates/ids)", 2, 2),
        Risk("R11", "Wrong workout written to the watch (units, order, targets)", 2, 2),
        Risk("R12", "Responses too large or silently corrupted by compaction", 2, 1),
        Risk("R13", "Persisted auth state corrupted -> fail open", 1, 3),
        Risk("R14", "Host/Origin header abuse (DNS rebinding) on /mcp", 1, 3),
    ]
}
