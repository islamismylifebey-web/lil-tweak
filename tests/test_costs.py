import pytest

from liltweak.costs import BudgetExceededError, CostGuard
from liltweak.models import Budget


def test_job_cost_limit() -> None:
    guard = CostGuard(monthly_limit_usd=250, job_default_limit_usd=5)
    with pytest.raises(BudgetExceededError):
        guard.require_within_job_limit(5.01, Budget(warning=1, hard_limit=10))


def test_monthly_cost_limit() -> None:
    guard = CostGuard(monthly_limit_usd=250, job_default_limit_usd=5)
    with pytest.raises(BudgetExceededError):
        guard.require_within_monthly_limit(249, 2)
