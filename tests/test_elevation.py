import os
import pytest

from sbx.elevation import run_elevated
from sbx.errors import ElevationError

pytestmark = pytest.mark.skipif(
    not os.environ.get("SBX_TEST_UAC"),
    reason="requires interactive UAC prompt (set SBX_TEST_UAC=1)",
)


def test_elevated_ping():
    result = run_elevated("ping")
    assert result == {"pong": True}


def test_elevated_error():
    with pytest.raises(ElevationError, match="intentional failure"):
        run_elevated("fail")
