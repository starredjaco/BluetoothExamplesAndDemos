#!/usr/bin/env python

import asyncio
import argparse
from bleak import BleakScanner, BleakClient
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.prompt import IntPrompt
from popled_client import PopledClient


BANNER = r"""
[#ff4fd8] ______               [/#ff4fd8][#ff3fb4]_____            [/#ff3fb4][#d946ef]__      [/#d946ef][#a855f7]______ __   __       [/#a855f7]
[#ff62c0]|   __ \.-----.-----.|[/#ff62c0][#ff4fd8]     |_.-----.--[/#ff4fd8][#d946ef]|  |    |[/#d946ef][#8b5cf6]      |  |_|  |.----.[/#8b5cf6]
[#ff79a8]|    __/|  _  |  _  ||[/#ff79a8][#ff62c0]       |  -__|  [/#ff62c0][#c084fc]_  |    |[/#c084fc][#7c3aed]   ---|   _|  ||   _|[/#7c3aed]
[#f472ff]|___|   |_____|   __||[/#f472ff][#e879f9]_______|_____|__[/#e879f9][#a855f7]___|    |[/#a855f7][#06b6d4]______|____|__||__|  [/#06b6d4]
[#c084fc]              |__|                                                  [/#c084fc]
"""

async def input_async(prompt=""):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt)


async def scan_for_device(console):
    console.log("Scanning for LOY devices...")
    console.log("Press Enter to stop.")

    devices = []
    table = Table("#", "MAC", "Name")

    def scan_callback(device, advertising_data):
        if not device.name:
            return
        if not device.name.startswith("YS") and not device.name.startswith("TL"):
            return
        if device in devices:
            return
        table.add_row(str(len(devices)), device.address, device.name)
        devices.append(device)

    async with BleakScanner(scan_callback) as _:
        with Live(table, refresh_per_second=4) as _:
            await input_async()

    while True:
        i = IntPrompt.ask("Please enter de number of the desired device", console=console)
        if i < len(devices):
            return devices[i]
        console.log("Invalid number!")


async def main():
    console = Console()
    console.print(BANNER)

    parser = argparse.ArgumentParser()
    parser.add_argument("--addr", "-a", help="MAC address of the device")
    parser.add_argument("--power", choices=["on", "off"])
    parser.add_argument("--brightness", type=int)
    args = parser.parse_args()

    if args.addr:
        console.log(f"Looking for device with MAC {args.addr}...")
        dev = await BleakScanner.find_device_by_address(args.addr, timeout=20)
    else:
        dev = await scan_for_device(console)
    console.log(f"Using {dev}")

    async with BleakClient(dev) as client:
        console.log(f"Connected to {client.address}")
        async with PopledClient(client) as popled:
            cmd_present = False
            if not args.power is None:
                cmd_present = True
                console.log("Sending power command...")
                await popled.send_power(args.power == "on")
            if not args.brightness is None:
                cmd_present = True
                if args.brightness > 15:
                    console.log("Brightness value out of bounds. Clipping to 15...")
                    args.brightness = 15
                console.log(f"Setting brightness to {args.brightness}")
                await popled.send_brightness(args.brightness)
            if not cmd_present:
                console.log("No commands provided!")
        console.log("Disconnecting...")
    console.log("All done!")


if __name__ == "__main__":
    asyncio.run(main())
