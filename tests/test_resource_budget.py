from datetime import UTC, datetime

import pytest

from liltweak.resource.budget import ResourceBudgetError, ResourceLedger
from liltweak.resource.contracts import ResourceProvider
from liltweak.resource.estimator import ResourceCostEstimate

NOW = datetime(2026, 9, 1, tzinfo=UTC)


def _estimate(net_cost: int = 3_000) -> ResourceCostEstimate:
    return ResourceCostEstimate(
        runner_profile_id="github-actions-standard",
        provider=ResourceProvider.GITHUB,
        duration_seconds=300,
        cpu_cost_microusd=1_200,
        memory_cost_microusd=600,
        storage_cost_microusd=1_200,
        gross_cost_microusd=3_000,
        included_allowance_applied_microusd=3_000 - net_cost,
        net_cost_microusd=net_cost,
    )


def test_ledger_rejects_reservation_above_job_or_monthly_ceiling() -> None:
    ledger = ResourceLedger(monthly_limit_microusd=5_000)

    with pytest.raises(ResourceBudgetError, match="execution cost ceiling"):
        ledger.reserve(
            execution_id="execution_job_ceiling",
            estimate=_estimate(),
            maximum_authorized_cost_microusd=2_999,
            chosen_reason="cheapest qualified capable profile",
            reserved_at=NOW,
        )

    ledger.reserve(
        execution_id="execution_first",
        estimate=_estimate(),
        maximum_authorized_cost_microusd=4_000,
        chosen_reason="cheapest qualified capable profile",
        reserved_at=NOW,
    )
    with pytest.raises(ResourceBudgetError, match="monthly"):
        ledger.reserve(
            execution_id="execution_monthly_ceiling",
            estimate=_estimate(),
            maximum_authorized_cost_microusd=4_000,
            chosen_reason="cheapest qualified capable profile",
            reserved_at=NOW,
        )


def test_ledger_settlement_records_actual_net_cost_and_variance() -> None:
    ledger = ResourceLedger(monthly_limit_microusd=50_000)
    reservation = ledger.reserve(
        execution_id="execution_settlement",
        estimate=_estimate(),
        maximum_authorized_cost_microusd=5_000,
        chosen_reason="cheapest qualified capable profile",
        reserved_at=NOW,
    )

    settlement = ledger.settle(
        execution_id=reservation.execution_id,
        actual_duration_seconds=280,
        actual_billable_units=560,
        actual_metered_cost_microusd=3_400,
        included_discount_microusd=500,
        settled_at=NOW,
    )

    assert settlement.actual_net_cost_microusd == 2_900
    assert settlement.variance_microusd == -100
    assert ledger.month_to_date_actual_microusd == 2_900
    with pytest.raises(ResourceBudgetError, match="already settled"):
        ledger.settle(
            execution_id=reservation.execution_id,
            actual_duration_seconds=280,
            actual_billable_units=560,
            actual_metered_cost_microusd=3_400,
            included_discount_microusd=500,
            settled_at=NOW,
        )
