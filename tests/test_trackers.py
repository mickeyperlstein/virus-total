from trackers.UrlTracker import UrlTracker


async def test_trackers():

    tracker = UrlTracker()
    job_id = tracker.track('www.elementor.com')
    data = await tracker.report_by_job_id(job_id)

