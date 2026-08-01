import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
AUDIT_SKILL = REPOSITORY_ROOT / "raw_memory_audit" / "SKILL.md"
AUDIT_AGENT = REPOSITORY_ROOT / "raw_memory_audit" / "agent.md"
SYNC_SKILL = REPOSITORY_ROOT / "raw_memory_sync" / "SKILL.md"
SYNC_AGENT = REPOSITORY_ROOT / "raw_memory_sync" / "agent.md"


class RawMemoryAuditContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = AUDIT_SKILL.read_text(encoding="utf-8")
        cls.audit_agent = AUDIT_AGENT.read_text(encoding="utf-8")
        cls.sync = SYNC_SKILL.read_text(encoding="utf-8")
        cls.sync_agent = SYNC_AGENT.read_text(encoding="utf-8")

    def assert_contains_all(self, text: str, *fragments: str) -> None:
        normalized_text = " ".join(text.split())
        for fragment in fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(" ".join(fragment.split()), normalized_text)

    def test_auditable_memory_items_are_complete_single_facts_with_history_split_from_current(self):
        self.assert_contains_all(
            self.audit,
            "one complete stored memory sentence",
            "standalone single fact",
            "mixes facts, combines historical and current claims",
        )
        self.assert_contains_all(
            self.sync,
            "one complete standalone plain-text sentence expressing one fact",
            "Split a historical event or decision from any claim about what is currently true",
        )
        self.assert_contains_all(
            self.sync_agent,
            "Each item is one complete standalone plain-text sentence",
            "Split a historical event or decision from a current-state assertion",
        )

    def test_ambiguous_candidates_require_a_readable_user_choice_without_guessing(self):
        self.assert_contains_all(
            self.audit,
            "date, workspace, workstream, short topic, and the sentence itself",
            "ask the user which sentence to inspect",
            "Never select the newest or most similar candidate by guess",
        )

    def test_receipts_bind_the_operation_but_do_not_prove_sentence_truth(self):
        self.assert_contains_all(
            self.audit,
            "Keep receipt and PLAN hashes internal",
            "is not proof that a sentence is true",
            "can never by itself produce `맞음`",
        )

    def test_audit_always_reports_independent_accuracy_and_freshness_judgments(self):
        self.assert_contains_all(
            self.audit,
            "Run and display both judgments for every selected sentence",
            "One unavailable or blocked scope never erases the result from the other scope",
            "mark only `동기화 정확성`",
            "continue the current-freshness judgment",
            "### 1. 동기화 정확성",
            "### 2. 현재 최신성",
        )
        self.assert_contains_all(
            self.audit_agent,
            "mark only synchronization accuracy as insufficient or blocked",
            "continue current freshness",
        )

    def test_current_authority_rules_distinguish_historical_code_document_and_runtime_claims(self):
        self.assert_contains_all(
            self.audit,
            "Show `대상 아님`",
            "current reference or default branch",
            "latest authoritative document version",
            "actual current readback from that runtime",
            "is not runtime readback",
        )

    def test_audit_is_read_only_nonpersistent_and_does_not_correct_automatically(self):
        self.assert_contains_all(
            self.audit,
            "This is read-only",
            "Do not save an audit report, sidecar, cache, note, or correction proposal",
            "Never turn a failed audit into an automatic correction",
        )
        self.assert_contains_all(
            self.sync,
            "An audit request must not create a review, PLAN, or memory write",
        )
        self.assert_contains_all(
            self.sync_agent,
            "Inspection alone never creates an approval review or PLAN",
        )

    def test_reader_facing_result_is_plain_korean_without_internal_identifiers(self):
        self.assert_contains_all(
            self.audit,
            "Prefer this plain Korean structure",
            "검사한 기억:",
            "메모 변경: 없음",
            "Do not show internal enums or hashes in the normal result",
        )


if __name__ == "__main__":
    unittest.main()
