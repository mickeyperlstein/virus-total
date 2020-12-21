from typing import Optional

import virustotal_python
import pytest
import os
from time import sleep
from base64 import urlsafe_b64encode
from hypercorn.config import Config

from fastapi import FastAPI, Header
from trackers.UrlTracker import UrlTracker

app = FastAPI()


@app.get("/scan/{url}")
async def scan_url(url: str, headers: Optional[str] = Header(None)):
    tracker = UrlTracker()
    return {"message": f"received + {url}", 'headers': headers}


def main():
    pass


if __name__ == '__main__':

    config = Config()
    config.bind = ["localhost:8000"]  # As an example configuration setting
    config.debug = True

    import asyncio
    from hypercorn.asyncio import serve

    asyncio.run(serve(app, Config()))

