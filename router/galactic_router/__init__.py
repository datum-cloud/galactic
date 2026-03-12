import logging
import asyncio
import aiorun

import click
from sqlmodel import create_engine
from alembic.config import Config
from alembic import command

from .bus import EventBus
from .router.mqtt import MQTTRouter
from .router.static import StaticRouter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("main")


@click.command()
@click.option(
    '--db_url',
    envvar="DB_URL",
    default="sqlite:///galactic-router.db",
    help='Database connection URL',
)
@click.option(
    '--db_create',
    envvar="DB_CREATE",
    default=True,
    help='Create database schema',
)
@click.option(
    '--mqtt_url',
    envvar="MQTT_URL",
    help='MQTT broker URL',
    required=True,
)
@click.option(
    '--mqtt_clientid',
    envvar="MQTT_CLIENTID",
    help='MQTT client identifier',
)
@click.option(
    '--mqtt_username',
    envvar="MQTT_USERNAME",
    help='MQTT username',
)
@click.option(
    '--mqtt_password',
    envvar="MQTT_PASSWORD",
    help='MQTT password',
)
@click.option(
    '--mqtt_qos',
    envvar="MQTT_QOS",
    help='MQTT QoS level',
    type=click.IntRange(min=0, max=2),
    default=1,
)
@click.option(
    '--mqtt_topic_base',
    envvar="MQTT_TOPIC_BASE",
    help='MQTT topic base',
    default='galactic/',
)
def run(  # noqa: WPS211,WPS216
    db_url,
    db_create,
    mqtt_url,
    mqtt_clientid,
    mqtt_username,
    mqtt_password,
    mqtt_qos,
    mqtt_topic_base,
):
    logger.info("Starting")

    bus = EventBus()

    db_engine = create_engine(
        db_url,
        pool_pre_ping=True,
    )
    if db_create:
        alembic_cfg = Config('alembic/alembic.ini')
        alembic_cfg.attributes['connection'] = db_engine
        command.upgrade(alembic_cfg, 'head')
    router = StaticRouter(bus, db_engine)

    mqtt_router = MQTTRouter(
        bus,
        mqtt_url,
        mqtt_clientid,
        mqtt_username,
        mqtt_password,
        mqtt_qos,
        mqtt_topic_base,
    )

    async def spawn(*services):  # noqa: WPS430
        async with asyncio.TaskGroup() as tg:
            for service in services:
                tg.create_task(service)

    aiorun.run(
        spawn(
            bus.run(),
            router.run(),
            mqtt_router.run()
        ),
        stop_on_unhandled_errors=True
    )

    logger.info("Stopped")
