"""Intent schemas — mirror of TS `schemas/intent.schema.ts`.

Schema version: `witseal.intent.v0.1`.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

_INTENT_ID_RE = re.compile(r"^int_[0-9a-zA-Z]{20,}$")


class RiskClass(StrEnum):
    C0 = "C0"
    C1 = "C1"
    C2 = "C2"
    C3 = "C3"
    C4 = "C4"


class ActionType(StrEnum):
    SHELL_COMMAND = "shell_command"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"


class ShellCommandIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: Literal["shell_command"]
    executable: str = Field(min_length=1)
    args: list[str]
    cwd: str = Field(min_length=1)
    env_keys_passed: list[str] | None = None
    use_tty: bool = False


class FileWriteIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: Literal["file_write"]
    path: str = Field(min_length=1)
    content_hash: str
    content_size_bytes: int = Field(ge=0)
    mode: Literal["overwrite", "append", "create_only"]


class FileReadIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: Literal["file_read"]
    path: str = Field(min_length=1)


Intent = Annotated[
    ShellCommandIntent | FileWriteIntent | FileReadIntent,
    Field(discriminator="action_type"),
]


def _validate_intent_id(value: str) -> str:
    if not _INTENT_ID_RE.match(value):
        raise ValueError("must match ^int_[0-9a-zA-Z]{20,}$")
    return value


class ClassifiedIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["witseal.intent.v0.1"]
    intent_id: str
    intent: Intent
    risk_class: RiskClass
    classification_reasons: list[str] = Field(default_factory=list)
    classifier_version: str

    def model_post_init(self, _: object) -> None:
        _validate_intent_id(self.intent_id)
