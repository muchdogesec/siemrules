import uuid
import pytest


from django.core.files.uploadedfile import SimpleUploadedFile
from siemrules.siemrules.models import Job, File, Profile


@pytest.fixture
def celery_eager():
    from siemrules.worker.celery import app

    app.conf.task_always_eager = True
    yield
    app.conf.task_always_eager = False


@pytest.fixture
def job(profile):
    file = File.objects.create(
        name="test.txt",
        file=SimpleUploadedFile(
            "test.txt", b"dummy content", content_type="text/plain"
        ),
        profile=profile,
    )
    return Job.objects.create(file=file)

@pytest.fixture
def profile():
    return Profile.objects.create(
        id=uuid.UUID('08de23ca-9d66-4bef-b62b-382d577da2ef'),
        name='test-profile',
    )

@pytest.fixture(autouse=True)
def default_profile():
    return Profile.objects.create(
        id=uuid.UUID('5e2c00bc-4e83-48b0-83dd-3fa084322245'),
        name='default-profile',
        is_default=True,
    )

@pytest.fixture(scope="session")
def api_schema():
    import schemathesis
    from siemrules.asgi import application

    yield schemathesis.openapi.from_asgi("/api/schema/?format=json", application)


@pytest.fixture
def fake_txt2stix_extractions():
    return {
        "detections": {
            "success": True,
            "detections": [
                {
                    "title": "Detection of Malicious PyPI Package and DNS Hijacking",
                    "description": "Detects the presence of a malicious PyPI package version 5.1.1 uploaded by a state agent, DNS hijacking of 1.1.1.1, and access to a suspicious URL.",
                    "detection": {
                        "condition": "selection1 OR selection2 OR selection3",
                        "selection1": {
                            "file_path": "requirements.txt",
                            "content": "pypotr==5.1.1",
                        },
                        "selection2": {"dns": "1.1.1.1"},
                        "selection3": {"url": "https://datadome.net"},
                    },
                    "logsource": {"category": "network", "product": "dns"},
                    "status": "experimental",
                    "falsepositives": [
                        "Legitimate use of the PyPI package version 5.1.1 for non-malicious purposes.",
                        "DNS changes made by authorized personnel.",
                        "Access to the URL for legitimate security research.",
                    ],
                    "tags": [
                        "attack.t1547",
                        "attack.t1190",
                        "cve.2024-56520",
                        "attack.initial-access",
                        "attack.execution",
                    ],
                    "level": "high",
                    "indicator_types": ["malicious-activity", "compromised"],
                }
            ],
        },
        "attack_flow": {
            "tactic_selection": [["T1190", "initial-access"], ["T1547", "persistence"]],
            "items": [
                {
                    "position": 0,
                    "attack_technique_id": "T1190",
                    "name": "Exploitation of Public-Facing Application",
                    "description": "The adversary exploited a vulnerability in a public-facing application, identified as CVE-2024-56520, to gain initial access to the system.",
                },
                {
                    "position": 1,
                    "attack_technique_id": "T1547",
                    "name": "Establishing Persistence via Boot or Logon Autostart",
                    "description": "After gaining access, the adversary used boot or logon autostart execution techniques to maintain persistence on the compromised system.",
                },
            ],
            "success": True,
        },
        "navigator_layer": [
            {
                "versions": {"layer": "4.5", "attack": "17.0", "navigator": "5.1.0"},
                "name": "fake python vulnerability report",
                "domain": "enterprise-attack",
                "techniques": [
                    {
                        "techniqueID": "T1190",
                        "tactic": "initial-access",
                        "score": 100,
                        "showSubtechniques": True,
                        "comment": "The adversary exploited a vulnerability in a public-facing application, identified as CVE-2024-56520, to gain initial access to the system.",
                    },
                    {
                        "techniqueID": "T1547",
                        "tactic": "persistence",
                        "score": 100,
                        "showSubtechniques": True,
                        "comment": "After gaining access, the adversary used boot or logon autostart execution techniques to maintain persistence on the compromised system.",
                    },
                ],
                "gradient": {
                    "colors": ["#ffffff", "#ff6666"],
                    "minValue": 0,
                    "maxValue": 100,
                },
                "legendItems": [],
                "metadata": [
                    {
                        "name": "report_id",
                        "value": "report--bc14a07a-5189-5f64-85c3-33161b923627",
                    }
                ],
                "links": [
                    {
                        "label": "Generated using txt2detection",
                        "url": "https://github.com/muchdogesec/txt2detection/",
                    }
                ],
                "layout": {"layout": "side"},
            }
        ],
        "observables": [
            {"type": "url", "value": "https://datadome.net"},
            {"type": "ipv4-addr", "value": "1.1.1.1"},
        ],
        "cves": {
            "CVE-2024-56520": "vulnerability--b79f4533-8ff4-5e65-aa11-ee396789478c",
            "CVE-2018-1234": "vulnerability--aa98815e-6c34-57b9-a1ee-a5fc9fbc52d0",
        },
        "attacks": {
            "T1547": "attack-pattern--1ecb2399-e8ba-4f6b-8ba7-5c27d49405cf",
            "T1190": "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c",
            "TA0001": "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
            "TA0002": "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
            "POP": "Not found",
        },
    }
