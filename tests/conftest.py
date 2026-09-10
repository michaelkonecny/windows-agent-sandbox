import pytest
from pathlib import Path

from sbx.store import Store


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "store" / "sandboxes.json"


@pytest.fixture
def store(store_path):
    return Store(store_path)
