# Copyright 2025 Datum Cloud, Inc.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio

from bubus import EventBus as BaseEventBus


class EventBus(BaseEventBus):
    async def run(self) -> None:
        try:
            while True:  # noqa: WPS457
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            await self.stop()
