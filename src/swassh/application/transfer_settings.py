"""Independent file-transfer time, bandwidth and staging budgets."""
import math
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class TransferSettings:
    rsync_executable: str = "rsync"
    sftp_executable: str = "sftp"
    timeout: float = 600.0
    bandwidth_kib: int = 10240
    max_file_mib: int = 1024
    rsync_options: tuple[str, ...] = ("-avzPH", "--numeric-ids", "--delete")
    max_rsync_alloc_mib: int = 16
    dry_run: bool = False
    verify_sha256: bool = False

    def __post_init__(self) -> None:
        if type(self.dry_run) is not bool or type(self.verify_sha256) is not bool:
            raise ValueError("dry_run and verify_sha256 must be boolean")
        if self.dry_run and self.verify_sha256:
            raise ValueError("dry_run and verify_sha256 are separate operations")
        if self.rsync_options != ("-avzPH", "--numeric-ids", "--delete"):
            raise ValueError("rsync options must be -avzPH --numeric-ids --delete")
        for name in ("rsync_executable", "sftp_executable"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ValueError(f"{name} must be a nonempty executable path")
        try:
            if (isinstance(self.timeout, bool) or not isinstance(self.timeout, (float, int))
                or not math.isfinite(self.timeout) or self.timeout <= 0):
                raise ValueError("timeout must be finite and positive")
        except OverflowError as exc:
            # Python integers can exceed the finite native timer range.
            raise ValueError("timeout must be finite and positive") from exc
        for name in ("bandwidth_kib", "max_file_mib", "max_rsync_alloc_mib"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
