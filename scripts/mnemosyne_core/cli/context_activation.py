"""Context-bound activation drafting behind the generic public guide."""

from __future__ import annotations

from pathlib import Path

from .. import canonical_curation, canonical_curation_review, operation_contract
from .request_builder import build_context_activation_request


def build_context_activation_draft(
    *,
    root: object,
    actor: object,
    review_package_directory: object,
    expected_plan_sha256: object,
    decision: object,
) -> tuple[
    operation_contract.OperationRequest,
    tuple[tuple[str, str], ...],
]:
    """Validate one sealed V3 review and build its exact unexecuted request."""

    try:
        review_directory = Path(review_package_directory)
        hashes, plan_value, _context_assembly = (
            canonical_curation_review.validate_context_bound_review_directory(
                review_directory,
                expected_plan_sha256=expected_plan_sha256,
            )
        )
        plan = canonical_curation.decode_context_bound_plan(plan_value)
        review_package_hashes = {
            "html_sha256": hashes.html_sha256,
            "markdown_sha256": hashes.markdown_sha256,
            "meta_sha256": hashes.meta_sha256,
            "semantic_sha256": hashes.semantic_sha256,
        }
        request = build_context_activation_request(
            root=root,
            actor=actor,
            plan=plan,
            review_package_directory=review_directory.as_posix(),
            review_package_hashes=review_package_hashes,
            decision=decision,
        )
    except (
        canonical_curation.CanonicalCurationError,
        canonical_curation_review.CurationReviewError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError("Context activation draft is invalid") from exc
    return request, tuple(
        (effect.source_path, effect.output_path) for effect in plan.effects
    )


__all__ = ["build_context_activation_draft"]
