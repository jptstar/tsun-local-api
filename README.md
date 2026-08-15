# TSUN Local API

`tsun-local-api` is an asynchronous, read-only Python library for communicating
with supported TSUN micro-inverters over the local network. It does not require
a proxy or cloud service.

This independent project is the communication dependency prepared for the
official Home Assistant integration. It is not affiliated with, approved by,
or maintained by TSUN.

## Features

- local TCP telemetry with automatic protocol detection;
- native read-only UDP discovery and bounded private-network analysis;
- automatic logger SN discovery, with manual entry supported by applications;
- local extraction of the logger firmware, MAC address and micro-inverter SN;
- AC and per-input PV measurements, energy counters and raw alarm words;
- privacy-safe diagnostic traces that exclude host addresses and serial numbers;
- no write, control or cloud operation.

## Hardware validation

`tsun-local-api` is protocol-based rather than model-based. Compatibility is
determined by the local protocol and register layout exposed by the logger, not
by a fixed model allowlist. The table below identifies devices tested on
physical hardware; it is not the complete list of potentially compatible
devices.

| Family | Model | PV inputs | Status |
|---|---:|---:|---|
| TITAN | TSOL-MP3000 | 6 | Validated on physical hardware |
| GEN3 PLUS | TSOL-MX500 | 1 | Validated on physical hardware |

Other models using the supported local protocol families may work, but must be
validated on physical hardware before compatibility is claimed.

## Installation

```bash
python -m pip install tsun-local-api
```

Python 3.13 or later is required.

## Basic use

```python
from aiohttp import ClientSession
from tsun_local_api import TsunClient, async_read_logger_metadata


async def read_micro_inverter(host: str) -> None:
    async with ClientSession() as session:
        metadata = await async_read_logger_metadata(session, host)

    if metadata.logger_sn is None:
        raise RuntimeError("The numeric logger SN must be entered manually")

    client = TsunClient(host, metadata.logger_sn, metadata=metadata)
    telemetry = await client.async_read()
    print(telemetry.device)
    print(telemetry.values)
```

Applications remain responsible for validating user-supplied hosts and for
deciding which private networks may be analysed. Network analysis in this
library is deliberately limited to private `/24` networks or smaller.

## Development

```bash
uv sync --group test
uv run ruff check .
uv run pytest --cov=tsun_local_api
```

## License

Copyright 2026 Jean-Philippe TESTART (`jptstar`).

Distributed under the Apache License 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
