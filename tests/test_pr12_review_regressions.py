from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_offer_verification_and_persistence_share_one_clock_read() -> None:
    source = (ROOT / "cloudflare" / "runner-control-plane" / "src" / "index.ts").read_text(
        encoding="utf-8"
    )
    assert source.count("const nowMs = Date.now();") == 1
    assert "verifyDispatchAttestation(body.attestation, env, nowMs)" in source
    assert ".offer(verified, body.manifest, nowMs)" in source
    assert ".offer(verified, body.manifest, Date.now())" not in source


def test_execution_lease_rejection_preserves_the_specific_reason() -> None:
    source = (ROOT / "liltweak" / "providers" / "self_hosted" / "galor_tweak_runner.py").read_text(
        encoding="utf-8"
    )
    assert "except ExecutionLeaseError as exc:" in source
    assert 'f"execution lease rejected: {exc}"' in source
    assert '"execution lease was rejected"' not in source
