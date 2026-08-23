from __future__ import annotations

import pytest
from pydantic import ValidationError

from astercode.config import BudgetConfig, ProcessSecurityConfig


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
