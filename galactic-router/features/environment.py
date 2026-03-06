from typing import List

import time_machine
from datetime import datetime

from behave.api.async_step import use_or_create_async_context

from sqlmodel import SQLModel, create_engine

from galactic_router import EventBus
from galactic_router.router import BaseRouter
from galactic_router.router.static import StaticRouter
from galactic_router.events import RegisterEvent, DeregisterEvent, RouteEvent


class Collector(BaseRouter):
    def __init__(self, bus: EventBus) -> None:
        self.register: List[RegisterEvent] = []
        self.deregister: List[DeregisterEvent] = []
        self.route: List[RouteEvent] = []
        super().__init__(bus)

    def reset(self):
        self.register.clear()
        self.deregister.clear()
        self.route.clear()

    async def run(self) -> None:
        return  # noqa: WPS324

    async def handle_register(self, event: RegisterEvent) -> bool:
        self.register.append(event)
        return True

    async def handle_deregister(self, event: DeregisterEvent) -> bool:
        self.deregister.append(event)
        return True

    async def handle_route(self, event: RouteEvent) -> bool:
        self.route.append(event)
        return True


def before_all(context):
    use_or_create_async_context(context)

    context.time_machine = time_machine.travel(datetime.now())
    context.time_traveller = context.time_machine.start()


def after_all(context):
    context.time_machine.stop()


def before_feature(context, feature):
    context.bus = EventBus()

    db_engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(db_engine)
    context.router = StaticRouter(
        bus=context.bus,
        db_engine=db_engine,
    )

    context.collector = Collector(context.bus)


def after_scenario(context, scenario):
    context.collector.reset()
