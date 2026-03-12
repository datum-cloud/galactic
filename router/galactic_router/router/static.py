import asyncio
import logging
import uuid
import ipaddress
from datetime import datetime, timedelta

from sqlmodel import SQLModel, Field, Session, select
from sqlalchemy import Index
from sqlalchemy.engine import Engine

from . import BaseRouter
from ..bus import EventBus
from ..events import RegisterEvent, DeregisterEvent, RouteEvent
from ..proto import remote_pb2 as pb


logger = logging.getLogger("StaticRouter")


# time to wait before a registration is considered a re-join
REJOIN_HOLDDOWN = timedelta(seconds=10)


class Registration(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    vpc: str = Field(index=True)
    network: str
    endpoint: str
    worker: str
    created: datetime = Field(default_factory=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_registration_vpc_network", "vpc", "network"),
    )


class StaticRouter(BaseRouter):  # noqa: WPS214,WPS338
    def __init__(self, bus: EventBus, db_engine: Engine) -> None:
        self.bus = bus
        self.db_engine = db_engine
        super().__init__(bus)

    async def run(self) -> None:
        while True:  # noqa: WPS457
            await asyncio.sleep(0.1)

    async def handle_register(self, event: RegisterEvent) -> bool:
        with Session(self.db_engine) as session:
            return await self._handle_register(session, event)
        return False

    async def _handle_register(
        self,
        session,
        event: RegisterEvent
    ) -> bool:
        vpc_identifier, _ = StaticRouter.extract_vpc_from_srv6_endpoint(
            event.envelope.srv6_endpoint
        )

        cur_reg = session.exec(select(Registration).where(
            Registration.vpc == vpc_identifier,  # noqa: WPS204
            Registration.network == event.envelope.network,
        )).one_or_none()
        new_reg = Registration(
            vpc=vpc_identifier,
            network=event.envelope.network,
            endpoint=event.envelope.srv6_endpoint,
            worker=event.worker,
        )

        if cur_reg is not None:
            await self.handle_deregister(DeregisterEvent(
                worker=cur_reg.worker,
                envelope=pb.Deregister(
                    network=cur_reg.network,
                    srv6_endpoint=cur_reg.endpoint,
                )
            ))

        logger.info(f"register {new_reg.model_dump_json()}")
        first_one = len(session.exec(
            select(Registration).where(
                    Registration.vpc == vpc_identifier,
                    Registration.worker == new_reg.worker,
                    Registration.endpoint == new_reg.endpoint,
                    Registration.created > datetime.utcnow()-REJOIN_HOLDDOWN,
                )
        ).all()) == 0
        if first_one:
            # existing registrations to new worker
            for reg in session.exec(
                select(Registration).where(
                        Registration.vpc == vpc_identifier,
                        Registration.network != new_reg.network,
                        Registration.worker != new_reg.worker,
                    )
            ):
                await self.bus.dispatch(
                    StaticRouter.create_route(
                        new_reg.worker,
                        reg.network,
                        new_reg.endpoint,
                        [reg.endpoint],
                        "ADD"
                    )
                )

        # new registration to existing workers
        # aggregate so we only send to each worker+endpoint combo once
        for reg in session.exec(
            select(
                Registration.worker,
                Registration.endpoint
            )
                .where(
                    Registration.vpc == vpc_identifier,
                    Registration.network != new_reg.network,
                    Registration.worker != new_reg.worker,
                )
                .group_by(
                    Registration.worker,
                    Registration.endpoint
                )
        ):
            await self.bus.dispatch(
                StaticRouter.create_route(
                    reg.worker,
                    new_reg.network,
                    reg.endpoint,
                    [new_reg.endpoint],
                    "ADD"
                )
            )

        session.add(new_reg)
        session.commit()
        return True

    async def handle_deregister(self, event: DeregisterEvent) -> bool:
        with Session(self.db_engine) as session:
            return await self._handle_deregister(session, event)
        return False

    async def _handle_deregister(
        self,
        session,
        event: DeregisterEvent
    ) -> bool:
        vpc_identifier, _ = StaticRouter.extract_vpc_from_srv6_endpoint(
            event.envelope.srv6_endpoint
        )
        cur_reg = session.exec(select(Registration).where(
            Registration.vpc == vpc_identifier,
            Registration.network == event.envelope.network,
            Registration.endpoint == event.envelope.srv6_endpoint,
            Registration.worker == event.worker,
        )).one_or_none()
        if cur_reg is None:
            logger.warning(
                f"could not find registration: "
                f"vpc={vpc_identifier}, "
                f"network={event.envelope.network}, "
                f"endpoint={event.envelope.srv6_endpoint}, "
                f"worker={event.worker}"
            )
            return False

        logger.info(f"deregister {cur_reg.model_dump_json()}")
        last_one = len(session.exec(
            select(Registration).where(
                    Registration.vpc == vpc_identifier,
                    Registration.worker == cur_reg.worker,
                    Registration.endpoint == cur_reg.endpoint,
                )
        ).all()) == 1
        if last_one:
            for reg in session.exec(
                select(Registration).where(
                        Registration.vpc == vpc_identifier,
                        Registration.network != cur_reg.network,
                        Registration.worker != cur_reg.worker,
                    )
            ):
                # existing registrations to leaving worker
                await self.bus.dispatch(
                    StaticRouter.create_route(
                        cur_reg.worker,
                        reg.network,
                        cur_reg.endpoint,
                        [reg.endpoint],
                        "DELETE"
                    )
                )

        for reg in session.exec(
            select(
                Registration.worker,
                Registration.endpoint
            )
                .where(
                    Registration.vpc == vpc_identifier,
                    Registration.network != cur_reg.network,
                    Registration.worker != cur_reg.worker,
                )
                .group_by(
                    Registration.worker,
                    Registration.endpoint
                )
        ):
            # leave registration to existing workers
            # aggregate so we only send to each worker+endpoint combo once
            await self.bus.dispatch(
                StaticRouter.create_route(
                    reg.worker,
                    cur_reg.network,
                    reg.endpoint,
                    [cur_reg.endpoint],
                    "DELETE"
                )
            )
        session.delete(cur_reg)
        session.commit()
        return True

    async def handle_route(self, event: RouteEvent) -> bool:
        return True

    def create_route(worker, network, srv6_endpoint, srv6_segments, status):
        return RouteEvent(
            worker=worker,
            envelope=pb.Route(
                network=network,
                srv6_endpoint=srv6_endpoint,
                srv6_segments=srv6_segments,
                status=pb.Route.Status.Value(status),
            ),
        )

    def extract_vpc_from_srv6_endpoint(endpoint: str) -> tuple[str, str]:
        addr = ipaddress.ip_address(endpoint)
        if not isinstance(addr, ipaddress.IPv6Address):
            raise ValueError(
                f"provided endpoint is not an IPv6 address: {endpoint}"
            )
        endpoint_num = int(addr)
        # 48 bits after dropping 16
        vpc_num = (endpoint_num >> 16) & 0xFFFFFFFFFFFF  # noqa: WPS432
        # low 16 bits
        vpc_attachment_num = endpoint_num & 0xFFFF  # noqa: WPS432
        return f"{vpc_num:012x}", f"{vpc_attachment_num:04x}"
