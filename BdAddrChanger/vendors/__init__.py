"""Per-vendor BD_ADDR changers.

Each module defines a ``Changer`` subclass; ``CHANGERS`` is the registry the main
tool iterates over. The main tool only calls ``changer.matches(controller,
socket)`` to select one and ``changer.change(controller, addr, console)`` to run
it -- no per-vendor attribute checks. A changer whose scapy contrib is missing
reports ``available = False`` and is skipped.

To add a vendor, create ``vendors/<name>.py`` with a Changer subclass and add it
here.
"""

from .barrot import BarrotChanger
from .csr import CSRChanger
from .espressif import EspressifChanger
from .nordic import NordicChanger

CHANGERS = [BarrotChanger(), NordicChanger(), CSRChanger(), EspressifChanger()]
