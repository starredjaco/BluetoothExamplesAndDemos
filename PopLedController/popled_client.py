#!/usr/bin/env python

import asyncio
from bleak import BleakClient
from popled_transport import transport_frames_parse, transport_frame_build, TransportFrameType, TransportFrameStatus
from popled_tlv import tlv_parse, tlv_build, TlvTag
from types import TracebackType
from typing import Type


class _AsyncStore:
    def __init__(self) -> None:
        self._futures = {}

    def set_value(self, id, value):
        fut = self._futures.get(id)
        
        # Create a future if none exists yet
        if fut is None:
            fut = asyncio.get_running_loop().create_future()
            self._futures[id] = fut

        # Only set result if not done
        if not fut.done():
            fut.set_result(value)


    async def wait_for(self, item_id):
        """
        Await the status for the given id. Creates a future if missing.
        """
        fut = self._futures.get(item_id)
        if fut is None:
            fut = asyncio.get_running_loop().create_future()
            self._futures[item_id] = fut
        return await fut


class PopledClient:
    UUID_SERVICE     = "0000FFF0-0000-1000-8000-00805F9B34FB"
    UUID_CHAR_NOTIFY = "0000FFF1-0000-1000-8000-00805F9B34FB"
    UUID_CHAR_WRITE  = "0000FFF2-0000-1000-8000-00805F9B34FB"

    def __init__(self, bleakclient: BleakClient) -> None:
        self._bleak_client = bleakclient
        self._sno_status_store = _AsyncStore()
        self._rx_buf = bytearray()
        self._sno = 1
        self._tx_mtu = 180

    def _sno_next(self) -> int:
        self._sno = (self._sno + 1) & 0xFFFF
        if self._sno == 0:
            self._sno = 1
        return self._sno

    def _on_notification(self, _handle: int, data: bytearray):
        self._rx_buf.extend(bytes(data))
        try:
            frames = transport_frames_parse(self._rx_buf)
            for frame, sno, flags, type, payload in frames:
                self._on_frame(frame, sno, flags, type, payload)
        except Exception:
            print(f"[RX] Unknown frame...")

    def _on_frame(self, frame, sno, flags, type, payload):
        #print(f"[RX FRAME] frame={frame.hex()} sno={sno} flags=0x{flags:02X} type=0x{type:02X} payload_len={len(payload)} payload(hex)={payload.hex()}")
        if type == TransportFrameType.TLV or type == TransportFrameType.UNK:
            tlvs = tlv_parse(payload)
            for tag, val in tlvs:
                self._on_tlv(tag, val)
        elif type == TransportFrameType.STATUS:
            self._on_status(sno, TransportFrameStatus(int.from_bytes(payload, 'big')))

    def _on_tlv(self, tag, val):
        #print(f"[RX TLV] {tag} ({tlv_tags.get(tag)}) - {val}")
        pass

    def _on_status(self, sno: int, status: TransportFrameStatus):
        self._sno_status_store.set_value(sno, status)

    async def _send_bytes(self, frame, with_response=False):
        for i in range(0, len(frame), self._tx_mtu):
            chunk = frame[i:i + self._tx_mtu]
            await self._bleak_client.write_gatt_char(self.UUID_CHAR_WRITE, chunk, response=with_response)

    async def _send_frame(self, payload: bytes, flags: int = 0xC1, type: TransportFrameType = TransportFrameType.TLV) -> TransportFrameStatus:
        sno = self._sno_next()
        frame = transport_frame_build(payload, sno=sno, flags=flags, type=type)
        #print(f"[TX FRAME] frame={frame.hex()} sno={sno} flags=0x{flags:02X} type=0x{type:02X} payload_len={len(payload)} payload(hex)={payload.hex()}")
        await self._send_bytes(frame)
        return await self._sno_status_store.wait_for(sno)

    async def _send_tlv(self, tag: int, value: bytes, flags: int = 0xC1) -> TransportFrameStatus:
        tlv_bytes = tlv_build(tag, value)
        return await self._send_frame(tlv_bytes, flags, TransportFrameType.TLV)

    async def __aenter__(self) -> BleakClient:
        await self._bleak_client.start_notify(self.UUID_CHAR_NOTIFY, self._on_notification)
        return self

    async def __aexit__(
        self,
        exc_type: Type[BaseException],
        exc_val: BaseException,
        exc_tb: TracebackType,
    ) -> None:
        pass

    async def request_power(self):
        await self._send_tlv(TlvTag.POWER, b"")

    async def send_power(self, val: bool):
        await self._send_tlv(TlvTag.POWER, b"\x00\x01" if val else b"\x00\x00")

    async def request_brightness(self):
        await self._send_tlv(TlvTag.BRIGHTNESS, b"")

    async def send_brightness(self, val):
        if not (0 <= val <= 15):
            raise ValueError("Brightness must be between 0 and 15")
        await self._send_tlv(TlvTag.BRIGHTNESS, val.to_bytes(2, 'big'))

    async def request_info(self):
        await self._send_tlv(TlvTag.INFO, b"")

    async def request_params(self):
        await self._send_tlv(TlvTag.PARAMS, b"")

    async def request_rotate(self):
        await self._send_tlv(TlvTag.ROTATE, b"")

    async def request_program_play(self):
        await self._send_tlv(TlvTag.PROGRAM_PLAY, b"")

