from datamodel.advisory import AdvisoryRecord
from datamodel.commit import Commit
from datamodel.commit_features import CommitFeatures


def extract_features(commit: Commit, advisory_record: AdvisoryRecord) -> CommitFeatures:
    references_vuln_id = extract_references_vuln_id(
        commit.cve_refs, advisory_record.vulnerability_id
    )
    changes_relevant_path = extract_changes_relevant_path(
        advisory_record.paths, commit.changed_files
    )
    commit_feature = CommitFeatures(
        commit=commit,
        references_vuln_id=references_vuln_id,
        changes_relevant_path=changes_relevant_path,
    )
    return commit_feature


def extract_references_vuln_id(cve_references: "list[str]", cve_id: str) -> bool:
    return cve_id in cve_references


def extract_changes_relevant_path(
    relevant_paths: "list[str]", changed_paths: "list[str]"
) -> bool:
    return any([changed_path in relevant_paths for changed_path in changed_paths])
