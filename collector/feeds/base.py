from abc import ABC, abstractmethod
from typing import Any


class BaseFeed(ABC):
    name: str = "base"
    interval_seconds: int = 3600

    @abstractmethod
    def fetch(self) -> list[dict[str, Any]]:
        pass
