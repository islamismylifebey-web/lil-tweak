from __future__ import annotations

import math
from dataclasses import dataclass

from .models import Budget


class BudgetExceededError(ValueError):
    pass


@dataclass
class CostGuard:
    monthly_limit_usd: float
    job_default_limit_usd: float
    planning_reservation_usd: float = 1.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.monthly_limit_usd, bool)
            or not math.isfinite(self.monthly_limit_usd)
            or self.monthly_limit_usd < 0
        ):
            raise ValueError("monthly budget must be a finite non-negative number")
        if (
            isinstance(self.job_default_limit_usd, bool)
            or not math.isfinite(self.job_default_limit_usd)
            or self.job_default_limit_usd <= 0
        ):
            raise ValueError("job budget limit must be a finite positive number")
        if (
            isinstance(self.planning_reservation_usd, bool)
            or not math.isfinite(self.planning_reservation_usd)
            or self.planning_reservation_usd <= 0
        ):
            raise ValueError("planning reservation must be a finite positive number")

    def validate_job_budget(self, budget: Budget) -> None:
        effective_limit = min(budget.hard_limit, self.job_default_limit_usd)
        if budget.warning > effective_limit:
            raise BudgetExceededError("job warning exceeds the permitted job limit")

    def require_within_job_limit(self, estimated_cost: float, budget: Budget) -> None:
        if not math.isfinite(estimated_cost) or estimated_cost < 0:
            raise BudgetExceededError("estimated job cost must be finite and non-negative")
        effective_limit = min(budget.hard_limit, self.job_default_limit_usd)
        if estimated_cost > effective_limit:
            raise BudgetExceededError(
                f"estimated job cost ${estimated_cost:.2f} exceeds ${effective_limit:.2f}"
            )

    def require_within_monthly_limit(self, month_to_date: float, incremental: float) -> None:
        if (
            not math.isfinite(month_to_date)
            or month_to_date < 0
            or not math.isfinite(incremental)
            or incremental < 0
        ):
            raise BudgetExceededError("monthly budget inputs must be finite and non-negative")
        if month_to_date + incremental > self.monthly_limit_usd:
            raise BudgetExceededError("monthly Lil Tweak budget would be exceeded")

    def planning_reservation(self, budget: Budget) -> float:
        effective_limit = min(budget.hard_limit, self.job_default_limit_usd)
        if self.planning_reservation_usd > effective_limit:
            raise BudgetExceededError(
                "job hard limit is below the conservative planning reservation"
            )
        self.require_within_job_limit(self.planning_reservation_usd, budget)
        return self.planning_reservation_usd
