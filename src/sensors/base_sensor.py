from abc import ABC, abstractmethod
from typing import Callable, List


class BaseSensor(ABC):
    def __init__(self, sensor_id: str, sensor_type: str, config: dict):
        self.sensor_id = sensor_id
        self.sensor_type = sensor_type
        self.config = config
        self.recording = False
        self.connected = False
        self.data_buffer: List[dict] = []
        self._subscribers: List[Callable] = []

    @abstractmethod
    def connect(self) -> bool: ...

    @abstractmethod
    def disconnect(self): ...

    @abstractmethod
    def start_recording(self) -> bool: ...

    @abstractmethod
    def stop_recording(self): ...

    def subscribe(self, callback: Callable):
        self._subscribers.append(callback)

    def notify(self, data: dict):
        for cb in self._subscribers:
            try:
                cb(data)
            except Exception:
                pass

    def get_buffer(self) -> List[dict]:
        return self.data_buffer

    def get_status(self) -> dict:
        return {
            "id": self.sensor_id,
            "type": self.sensor_type,
            "recording": self.recording,
            "connected": self.connected,
            "buffer_size": len(self.data_buffer),
        }
