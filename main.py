import csv
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
    if headers:
        if 'API_KEY' in headers:
            api_key = headers['API_KEY']

        elif 'VIRUSTOTAL_API_KEY' in headers:
            api_key = headers['VIRUSTOTAL_API_KEY']
    else:
        api_key = None

    tracker = UrlTracker(api_key=api_key)

    resp = await tracker.track(url)
    return resp


def main():

    with open('tests/resources/request1.csv') as f:
        reader = csv.reader(f)
        for row in reader:
            print(row)


if __name__ == '__main__':
    main()
    config = Config()
    config.bind = ["localhost:8000"]  # As an example configuration setting
    config.debug = True

    import asyncio
    from hypercorn.asyncio import serve

    asyncio.run(serve(app, Config()))

