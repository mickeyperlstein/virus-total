import virustotal_python


def test_single_url():

    URL_DOMAIN = 'www.elementor.com'
    vtotal_v2 = virustotal_python.Virustotal(API_VERSION="v2")
    resp = vtotal_v2.request("url/scan", params={"url": URL_DOMAIN}, method="POST")
    assert resp.status_code == 200
    data = resp.json()
    # Obtain scan_id
    scan_id = data["scan_id"]
    # Request report for URL analysis
    analysis_resp = vtotal_v2.request("url/report", params={"resource": scan_id})
    assert analysis_resp.status_code == 200
    assert analysis_resp.response_code == 1
    data = analysis_resp.json()
    assert data["scan_id"]
    assert data["verbose_msg"]
    assert data["url"] == f"http://{URL_DOMAIN}/"
    assert data["scan_date"]