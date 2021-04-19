from datamodel.commit import Commit
from datamodel.commit_features import CommitFeatures


def test_simple():
    commit = Commit("abcd", "https://github.com/abc/xyz", "X", "Y")
    commit_features = CommitFeatures(
        commit=commit,
        references_vuln_id=True,
        changes_relevant_path=True,
        time_between_commit_and_advisory_record=42,
    )

    assert commit_features.commit.repository == "https://github.com/abc/xyz"
    assert commit_features.references_vuln_id
    assert commit_features.changes_relevant_path
    assert commit_features.time_between_commit_and_advisory_record == 42
