import virustotal_python


class UrlTracker:

    def __init__(self):
        self.api = virustotal_python.Virustotal(API_VERSION="v2")
        # resp = vtotal_v2.request("url/scan", params={"url": URL_DOMAIN}, method="POST")
        # assert resp.status_code == 200
        # data = resp.json()
        # # Obtain scan_id
        # scan_id = data["scan_id"]

    #
    async def track(self, url: str):
        pass
