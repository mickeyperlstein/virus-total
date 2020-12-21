import asyncio
import datetime

import virustotal_python
import logging

log = logging.getLogger(__name__)


class TrackingDb:
    def __init__(self):
        self.requests = {}
        self.responses = {}

    def add(self, url, jsn, job_id, job_date):
        self.requests[url] = {'data': jsn, 'job_id': job_id, 'job_date': job_date}

    def has_job_bellow_ttl(self, target_url, ttl=5*60):

        """
        :param target_url:
        :param ttl: 5 min

        :return: <0 if job has not
        """
        response =  self.responses.get('url', {})
        last_date = response.get('job_date', None)
        if last_date and datetime.datetime.utcnow() - last_date > ttl:

            request = self.requests.get(target_url, {})
            job_id = request.get('job_id', None)
            return job_id




#
# async def cache_it(func):
#     async def wrapper(*args, **kwargs):
#         return await func()
#

class UrlTracker:

    def __init__(self, throttle_per_min=50, api_key=None):

        if api_key:
            self.api = virustotal_python.Virustotal(API_VERSION="v2", API_KEY=api_key)
        else:
            self.api = virustotal_python.Virustotal(API_VERSION="v2")

        self.throttle_per_min = throttle_per_min
        self.db = TrackingDb()

    async def track_multi_url(self, urls):
        for url in urls:
            job_id = await self.track(url)
            await asyncio.sleep(1 / self.throttle_per_min)

    async def track(self, target_url: [str]):
        if self.db.has_job_bellow_ttl(target_url):

        resp = self.api.request("url/scan", params={"url": target_url}, method="POST")

        if resp.status_code != 200:
            log.error(f'Received non 200 response Error={resp}')
        else:
            jsn = resp.json()

            job_id = jsn['scan_id']
            job_date = jsn['scan_date']
            self.db.add(target_url, jsn, job_id, job_date)

            return job_id
