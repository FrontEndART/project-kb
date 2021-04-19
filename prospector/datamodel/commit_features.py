from dataclasses import dataclass, field

from datamodel.commit import Commit

from . import BaseModel


@dataclass
class CommitFeatures(BaseModel):
    commit: Commit
    references_vuln_id: bool = False
    changes_relevant_path: bool = False
    time_between_commit_and_advisory_record: int = 0
