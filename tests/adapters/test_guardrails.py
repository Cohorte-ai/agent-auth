"""Tests for the guardrails adapter — wraps auth engine with guardrails."""

from __future__ import annotations

from unittest.mock import MagicMock


from theaios.agent_auth.adapters.guardrails import GuardrailsAuthAdapter
from theaios.agent_auth.types import AuthConfig


class TestGuardrailsAuthAdapter:
    """The adapter creates an internal AuthEngine and checks auth before guardrails."""

    def test_import_adapter(self) -> None:
        assert GuardrailsAuthAdapter is not None

    def test_adapter_constructor(self, basic_config: AuthConfig) -> None:
        mock_guardrails = MagicMock()
        adapter = GuardrailsAuthAdapter(
            auth_config=basic_config,
            guardrails_engine=mock_guardrails,
        )
        assert adapter is not None

    def test_adapter_has_internal_auth_engine(self, basic_config: AuthConfig) -> None:
        mock_guardrails = MagicMock()
        adapter = GuardrailsAuthAdapter(
            auth_config=basic_config,
            guardrails_engine=mock_guardrails,
        )
        assert hasattr(adapter, "_auth_engine")

    def test_adapter_default_user(self, basic_config: AuthConfig) -> None:
        mock_guardrails = MagicMock()
        adapter = GuardrailsAuthAdapter(
            auth_config=basic_config,
            guardrails_engine=mock_guardrails,
            default_user="test-user",
        )
        assert adapter._default_user == "test-user"
