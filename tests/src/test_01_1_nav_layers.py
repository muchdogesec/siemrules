from tests.utils import Transport


def test_nav_layer_correlation(client, api_schema):
    indicator_id = "indicator--8072047b-998e-43fc-a807-15c669c7343b"
    response = client.get(f"/api/v1/correlation-rules/{indicator_id}/attack-navigator/")
    assert response.status_code == 200
    api_schema["/api/v1/correlation-rules/{indicator_id}/attack-navigator/"][
        "GET"
    ].validate_response(Transport.get_st_response(response))
    print(response.json())
    assert response.json() == {
        "name": "new title",
        "domain": "enterprise-attack",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "techniques": [
            {
                "comment": "Suspicious PyPI Package Version Detected related-to T1557 (Adversary-in-the-Middle)",
                "score": 100,
                "showSubtechniques": True,
                "techniqueID": "T1557",
            },
            {
                "comment": "Detection of Malicious Code in xz Tarballs related-to T1008 (Fallback Channels)",
                "score": 100,
                "showSubtechniques": True,
                "techniqueID": "T1008",
            },
            {
                "comment": "Suspicious PyPI Package Version Detected related-to T1098 (Account Manipulation)",
                "score": 100,
                "showSubtechniques": True,
                "techniqueID": "T1098",
            },
        ],
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
        "legendItems": [],
        "metadata": [
            {
                "name": "rule_id",
                "value": "indicator--8072047b-998e-43fc-a807-15c669c7343b",
            },
            {
                "name": "secondary_rule",
                "value": "indicator--8af82832-2abd-5765-903c-01d414dae1e9",
            },
            {
                "name": "secondary_rule",
                "value": "indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61",
            },
        ],
        "links": [
            {
                "label": "Generated using siemrules",
                "url": "https://github.com/muchdogesec/siemrules/",
            }
        ],
        "layout": {"layout": "side"},
    }


def test_nav_layer_base(client, api_schema):
    indicator_id = "indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61"
    response = client.get(f"/api/v1/base-rules/{indicator_id}/attack-navigator/")
    assert response.status_code == 200
    api_schema["/api/v1/base-rules/{indicator_id}/attack-navigator/"][
        "GET"
    ].validate_response(Transport.get_st_response(response))
    print(response.json())
    assert response.json() == {
        "name": "Detection of Malicious Code in xz Tarballs",
        "domain": "enterprise-attack",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "techniques": [
            {
                "comment": "Detection of Malicious Code in xz Tarballs related-to T1008 (Fallback Channels)",
                "score": 100,
                "showSubtechniques": True,
                "techniqueID": "T1008",
            }
        ],
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
        "legendItems": [],
        "metadata": [
            {
                "name": "rule_id",
                "value": "indicator--9e2536b0-988b-598d-8cc3-407f9f13fc61",
            },
            {
                "name": "report_id",
                "value": "report--9e2536b0-988b-598d-8cc3-407f9f13fc61",
            },
        ],
        "links": [
            {
                "label": "Generated using siemrules",
                "url": "https://github.com/muchdogesec/siemrules/",
            }
        ],
        "layout": {"layout": "side"},
    }
