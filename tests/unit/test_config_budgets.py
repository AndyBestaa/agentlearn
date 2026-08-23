from __future__ import annotations

import pytest
from pydantic import ValidationError

from astercode.config import BudgetConfig, ProcessSecurityConfig
from astercode.runtime import _clamp_persisted_budget


def test_default_model_budgets_are_finite() -> None:
    budget = BudgetConfig()

    assert budget.max_tokens == 120_000
    assert budget.max_input_tokens == 100_000
    assert budget.max_output_tokens == 20_000


@pytest.mark.parametrize(
    "field",
    ["max_tokens", "max_input_tokens", "max_output_tokens"],
)
def test_token_budgets_reject_non_positive_values(field: str) -> None:
    with pytest.raises(ValidationError):
        BudgetConfig.model_validate({field: 0})


def test_default_windows_job_resource_budgets_are_finite() -> None:
    process = ProcessSecurityConfig()

    assert process.max_processes == 32
    assert process.max_memory_bytes == 2_147_483_648
    assert process.max_cpu_time_seconds == 600.0


def test_persisted_resume_budget_can_only_narrow_current_limits() -> None:
    configured = BudgetConfig().model_dump(mode="python")
    stored = {
        "max_rounds": 999_999,
        "max_tool_calls": 2,
        "max_tokens": "unbounded",
        "max_input_tokens": 10,
        "max_output_tokens": 999_999,
        "max_elapsed_seconds": float("inf"),
        "max_concurrency": True,
        "max_cost_usd": 1.0,
    }

    restored = _clamp_persisted_budget(configured, stored)

    assert restored["max_rounds"] == configured["max_rounds"]
    assert restored["max_tool_calls"] == 2
    assert restored["max_tokens"] == configured["max_tokens"]
    assert restored["max_input_tokens"] == 10
    assert restored["max_output_tokens"] == configured["max_output_tokens"]
    assert restored["max_elapsed_seconds"] == configured["max_elapsed_seconds"]
    assert restored["max_concurrency"] == configured["max_concurrency"]
    assert restored["max_cost_usd"] == 1.0
