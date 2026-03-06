import logging
import ssl
import re
from urllib.parse import urlparse

from aiomqtt import Client

from . import BaseRouter
from ..bus import EventBus
from ..events import RegisterEvent, DeregisterEvent, RouteEvent
from ..proto.remote_pb2 import Envelope


logger = logging.getLogger("MQTTRouter")


class MQTTRouter(BaseRouter):  # noqa: WPS230
    def __init__(  # noqa: WPS211
        self,
        bus: EventBus,
        mqtt_url: str,
        mqtt_clientid: str,
        mqtt_username: str,
        mqtt_password: str,
        mqtt_qos: int,
        mqtt_topic_base: str,
        mqtt_topic_tx: str = "send",
        mqtt_topic_rx: str = "receive",
    ) -> None:
        self.bus = bus
        self.mqtt_url = mqtt_url
        self.mqtt_clientid = mqtt_clientid
        self.mqtt_username = mqtt_username
        self.mqtt_password = mqtt_password
        self.mqtt_qos = mqtt_qos
        self.mqtt_topic_base = mqtt_topic_base.removesuffix("/")
        self.mqtt_topic_tx = mqtt_topic_tx
        self.mqtt_topic_rx = mqtt_topic_rx
        super().__init__(bus)

    async def run(self) -> None:  # noqa: WPS210
        logger.info(f"Connecting: {self.mqtt_url}")
        scheme, hostname, port = MQTTRouter.parse_url(self.mqtt_url)

        match scheme:
            case 'tls' | 'wss':
                tls_context = ssl.create_default_context()
            case _:
                tls_context = None
        logger.info(f"TLS: {tls_context is not None}")

        match scheme:
            case 'tls':
                transport = 'tcp'
            case 'ws' | 'wss':
                transport = 'websockets'
            case _:
                transport = scheme
        logger.info(f"Transport: {transport}")

        clean_session = any([self.mqtt_clientid is None, self.mqtt_qos == 0])
        logger.info(f"Clean Session: {clean_session}")

        self.client = Client(
            hostname=hostname,
            port=port,
            transport=transport,
            tls_context=tls_context,
            identifier=self.mqtt_clientid,
            username=self.mqtt_username,
            password=self.mqtt_password,
            clean_session=clean_session,
        )
        logger.info("Connected")
        async with self.client:
            topic = f"{self.mqtt_topic_base}/+/{self.mqtt_topic_tx}"
            logger.info(f"Subscribing: {topic}")
            await self.client.subscribe(topic, qos=self.mqtt_qos)
            async for msg in self.client.messages:
                await self.on_message(msg)

    async def on_message(self, msg):
        worker_match = re.compile(
            fr'{self.mqtt_topic_base}/'
            fr'(.+)/{self.mqtt_topic_tx}'
        ).match(msg.topic.value)
        if not worker_match:
            logger.warning(f"could not get worker - topic={msg.topic.value}")
            return
        worker = worker_match.group(1)

        envelope = Envelope()
        envelope.ParseFromString(msg.payload)
        match envelope.WhichOneof("kind"):
            case "register":
                await self.bus.dispatch(RegisterEvent(
                    worker=worker,
                    envelope=envelope.register,
                )).event_result()
            case "deregister":
                await self.bus.dispatch(DeregisterEvent(
                    worker=worker,
                    envelope=envelope.deregister,
                )).event_result()

    def parse_url(url: str):
        parsed = urlparse(url)
        scheme = parsed.scheme.lower() or "tcp"
        hostname = parsed.hostname or "127.0.0.1"
        port = parsed.port or 1883  # noqa: WPS432
        return scheme, hostname, port

    async def handle_register(self, event: RegisterEvent) -> bool:
        return True

    async def handle_deregister(self, event: DeregisterEvent) -> bool:
        return True

    async def handle_route(self, event: RouteEvent) -> bool:
        await self.client.publish(
            f"{self.mqtt_topic_base}/{event.worker}/{self.mqtt_topic_rx}",
            Envelope(route=event.envelope).SerializeToString(),
            qos=self.mqtt_qos
        )
        return True
