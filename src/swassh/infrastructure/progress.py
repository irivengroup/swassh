"""A single bounded progress line on stderr; stdout remains the final report."""
import sys


def progress(metrics, *, final=False):
    # No server names, paths or captured remote output enter this channel.
    line = (f"swassh: {metrics['completed']}/{metrics['total']} completed; "
        f"active={metrics['active']} skipped={metrics['skipped']} "
        f"limit={metrics['admission_limit']} rate={metrics['completed_per_second']:.1f}/s "
        f"elapsed={metrics['elapsed_seconds']:.1f}s "
        f"circuit={'open' if metrics['circuit_open'] else 'closed'}")
    if sys.stderr.isatty():
        import shutil
        width = max(20, min(160, shutil.get_terminal_size((80, 24)).columns - 1))
        sys.stderr.write('\r' + line[:width].ljust(width) + ('\n' if final else ''))
    else:
        sys.stderr.write(line + '\n')
    sys.stderr.flush()
