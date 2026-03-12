from abc import ABC, abstractmethod
from ..bus import EventBus
from ..events import RegisterEvent, DeregisterEvent, RouteEvent


class BaseRouter(ABC):
    def __init__(self, bus: EventBus) -> None:
        bus.on(RegisterEvent, self.handle_register)
        bus.on(DeregisterEvent, self.handle_deregister)
        bus.on(RouteEvent, self.handle_route)

    @abstractmethod
    async def run(self) -> None:
        ...

    @abstractmethod
    async def handle_register(self, event: RegisterEvent) -> bool:
        ...

    @abstractmethod
    async def handle_deregister(self, event: DeregisterEvent) -> bool:
        ...

    @abstractmethod
    async def handle_route(self, event: RouteEvent) -> bool:
        ...
