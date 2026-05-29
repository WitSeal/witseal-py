"""Execution Result schemas — mirror of TS `schemas/execution-result.schema.ts`.

Schema version: `witseal.execution.v0.1`.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ._primitives import Rfc3339UtcTimestamp, Sha256Hex


class StreamCapture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_bytes: int = Field(ge=0)
    content_hash: Sha256Hex
    head: str | None
    tail: str | None
    head_bytes: int = Field(ge=0)
    tail_bytes: int = Field(ge=0)
    truncated: bool


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["witseal.execution.v0.1"]
    started_at: Rfc3339UtcTimestamp
    finished_at: Rfc3339UtcTimestamp
    exit_code: int
    signal: str | None
    stdout: StreamCapture
    stderr: StreamCapture
    executable_resolved: str
    env_keys_hash: Sha256Hex
    spawn_error: str | None
