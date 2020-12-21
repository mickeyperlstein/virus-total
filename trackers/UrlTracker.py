import asyncio
import datetime

import virustotal_python
import logging

TTL = datetime.timedelta(minutes=30)

log = logging.getLogger(__name__)


class TrackingDb:
    def __init__(self):
        self.requests = {}
        self.responses = {}

    def add_request(self, url, jsn, job_id, job_date):
        self.requests[url] = {'data': jsn, 'job_id': job_id, 'job_date': job_date}
        # enqueue job report receiver

    def add_response(self, job_id, response_data ):
        self.responses[job_id] = response_data

    def has_job_bellow_ttl(self, target_url, ttl: datetime.timedelta=None):

        """
        :param target_url:
        :param ttl: 30 min

        :return: job_id or None
        """
        if not ttl:
            ttl = TTL

        response =  self.responses.get('url', {})
        last_date = response.get('job_date', None)
        if last_date and datetime.datetime.utcnow() - last_date > ttl:

            request = self.requests.get(target_url, {})
            job_id = request.get('job_id', None)
            return job_id
        return None

    def get_response(self, job_id, remove_if_ttl_reached):
        if job_id not in self.responses:
            return None

        job_id_response = self.responses[job_id]
        last_date = job_id_response.get('last_updated', datetime.datetime.utcnow() - 500)

        if datetime.datetime.utcnow() -  last_date > datetime.timedelta(minutes=30):
            del self.responses[job_id]
            return None

        else:
            return job_id_response

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

        job_id = self.db.has_job_bellow_ttl(target_url)
        if job_id:
            job_response = self.db.get_response(job_id) # move to decorator
            if not job_response:
                resp = self.api.request("url/scan", params={"url": target_url}, method="POST")

                if resp.status_code != 200:
                    log.error(f'Received non 200 response Error={resp}')
                else:
                    jsn = resp.json()

                    job_id = jsn['scan_id']
                    job_date = jsn['scan_date']

                    self.db.add_request(target_url, jsn, job_id, job_date)

                    return job_id
