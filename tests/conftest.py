import pytest
from pathlib import Path

from sbx.store import Store
from sbx import winapi


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "store" / "sandboxes.json"


@pytest.fixture
def store(store_path):
    return Store(store_path)


def pytest_runtest_setup(item):
    if "elevation" in item.keywords and not winapi.is_elevated():
        pytest.skip("requires admin privileges")
