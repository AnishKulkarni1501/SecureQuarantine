import hmac
import os
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException


@dataclass(frozen=True)
class Actor:
    name: str
    role: str


def actor_from_header(authorization: str | None = Header(default=None)) -> Actor:
    # Local development remains single-user for a frictionless localhost app.
    # Production fails closed and accepts only configured analyst/reviewer tokens.
    if os.getenv("APP_ENV", "development").lower() != "production":
        return Actor("local-analyst", "reviewer")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")
    token = authorization[7:]
    for role in ("reviewer", "analyst"):
        configured = os.getenv(f"{role.upper()}_API_TOKEN", "")
        if configured and hmac.compare_digest(configured, token):
            return Actor(f"{role}-token", role)
    raise HTTPException(401, "Invalid token")


def analyst(actor: Actor = Depends(actor_from_header)) -> Actor:
    if actor.role not in {"analyst", "reviewer"}:
        raise HTTPException(403, "Analyst role required")
    return actor


def reviewer(actor: Actor = Depends(actor_from_header)) -> Actor:
    if actor.role != "reviewer":
        raise HTTPException(403, "Reviewer role required")
    return actor
