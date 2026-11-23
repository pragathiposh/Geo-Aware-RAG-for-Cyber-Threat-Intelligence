
from abc import ABC, abstractmethod
from typing import Any


class BaseCollector(ABC):
    """Common interface for threat intelligence collectors."""

    def __init__(self, source_name: str):
        self.source_name = source_name

    @abstractmethod
    def fetch(self) -> list[dict[str, Any]]:
        """Fetch records from the intelligence source."""
        raise NotImplementedError

    def get_source_name(self) -> str:
        return self.source_name
