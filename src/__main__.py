"""Allow running as ``python -m src``."""
import sys

if "--cli" in sys.argv:
    sys.argv.remove("--cli")
    from src.cli import main
else:
    from src.gui import main  # type: ignore[attr-defined]

raise SystemExit(main())
