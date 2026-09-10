import logging
import os
from pathlib import Path

logging.getLogger("sbx").addHandler(logging.NullHandler())


def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    log = logging.getLogger("sbx")
    level = logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
    log.setLevel(level)

    stderr = logging.StreamHandler()
    stderr.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    log.addHandler(stderr)

    log_dir = Path(os.environ.get("LOCALAPPDATA", "")) / "sbx"
    log_dir.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_dir / "sbx.log")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter("%(asctime)s %(name)s %(levelname)s: %(message)s")
    )
    log.addHandler(fh)
