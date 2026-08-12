"""Exceptions raised by the TSUN local API."""


class TsunError(Exception):
    """Base exception for the TSUN local API."""


class TsunConnectionError(TsunError):
    """The TSUN device could not be reached."""


class TsunProtocolError(TsunError):
    """The TSUN device returned an invalid protocol frame."""


class TsunUnsupportedDeviceError(TsunError):
    """No supported local protocol was detected."""

