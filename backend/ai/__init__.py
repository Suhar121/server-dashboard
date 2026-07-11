# ai/__init__.py
"""
AI Assistant package for DevOps Dashboard.
Exposes the main chat function used by /ai/chat endpoint.
"""
from .gemini_client import GeminiChat
from .nvidia_client import NvidiaChat

__all__ = ["GeminiChat", "NvidiaChat"]