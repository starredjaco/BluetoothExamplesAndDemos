"""Per-vendor chip/firmware information providers.

Each module defines a ``Vendor`` subclass; ``VENDORS`` is the registry the main
tool iterates over. To add a vendor, create ``vendors/<name>.py`` with a Vendor
subclass and add it here. Vendors whose scapy contrib layer is missing report
``available = False`` and are skipped.
"""

from .barrot import BarrotVendor
from .csr import CSRVendor
from .espressif import EspressifVendor
from .intel import IntelVendor
from .realtek import RealtekVendor
from .zephyr import ZephyrVendor

VENDORS = [BarrotVendor(), CSRVendor(), EspressifVendor(), IntelVendor(),
           RealtekVendor(), ZephyrVendor()]
