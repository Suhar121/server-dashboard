# ai/models.py
"""Pydantic models for AI assistant endpoints."""

from pydantic import BaseModel
from typing import Literal


class AIChatRequest(BaseModel):
    message: str
    stream: bool = True


class AIActionConfirmation(BaseModel):
    action_id: str
    approved: bool


class AIAnalyzeRequest(BaseModel):
    trigger: Literal["port_down", "cpu_spike", "service_crash", "docker_stop"]
    context: dict


class ToolCallResult(BaseModel):
    tool: str
    success: bool
    result: dict | None = None
    error: str | None = None


class PendingAction(BaseModel):
    action_id: str
    tool: str
    params: dict
    created_at: float
    confirmed: bool = False