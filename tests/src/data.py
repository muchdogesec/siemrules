SIGMA_RULE_1 = (
    "8af82832-2abd-5765-903c-01d414dae1e9",
    """
id: 8af82832-2abd-5765-903c-01d414dae1e9
title: Suspicious PyPI Package Version Detected
description: Detects the presence of a specific version of the 'pypotr' package (version
    5.1.1) in requirements.txt, which was uploaded by a state agent, indicating potential
    supply chain compromise.
level: low
detection:
    condition: selection
    selection:
    -   file: requirements.txt
        package: pypotr
        version: 5.1.1
logsource:
    category: file
    product: application
    definition: File system events and operations
falsepositives:
- Legitimate use of the pypotr package version 5.1.1 by developers unaware of its
    origin.
- Testing environments where this version is intentionally used for analysis.
tags:
- tlp.green
- attack.supply-chain-compromise
- attack.initial-access
- txt2detection.fake
- txt2detection.hand-written
- txt2detection.pypotr
- txt2detection.python
- attack.t1557
- attack.t1098
confidence: 85
author: '{"type": "identity", "spec_version": "2.1", "id": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7", "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5", "created": "2020-01-01T00:00:00.000Z", "modified": "2020-01-01T00:00:00.000Z", "name": "txt2detection", "description": "https://github.com/muchdogesec/txt2detection", "identity_class": "system", "sectors": ["technology"], "contact_information": "https://www.dogesec.com/contact/", "object_marking_refs": ["marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487", "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"]}'
status: experimental
date: 2024-05-01
""",
)

SIGMA_RULE_2 = (
    "9e2536b0-988b-598d-8cc3-407f9f13fc61",
    "red",
    """
id: 9e2536b0-988b-598d-8cc3-407f9f13fc61
title: Detection of Malicious Code in xz Tarballs
description: Detects the presence of malicious code in the xz tarballs starting from
    version 5.6.0, which modifies the liblzma library through obfuscation techniques.
level: high
detection:
    condition: selection
    selection:
        file_name: test_file
        file_version: 5.6.0
        library: liblzma
logsource:
    product: application
    service: xz
    definition: Application logs from compression utilities
falsepositives:
- Legitimate updates or patches to the xz library that include test files.
- Custom builds of xz that include additional test files for development purposes.
tags:
- tlp.green
- cve.2024-3094
- attack.execution
- attack.defense-evasion
- txt2detection.downloaded
- txt2detection.nvd
- txt2detection.cve-2024-3094
- txt2detection.xz
- txt2detection.liblzma
- txt2detection.linux
- attack.t1008
confidence: 85
author: identity--a4d70b75-6f4a-5d19-9137-da863edd33d7
status: experimental
license: 0BSD
date: 2025-01-23
""",
)

SIGMA_RULE_3 = (
    "2683daab-aa64-52ff-a001-3ea5aee9dd72",
    "amber",
    """
id: 2683daab-aa64-52ff-a001-3ea5aee9dd72
title: Detection of Stored Cross-Site Scripting in Exclusive Addons for Elementor
description: Detects attempts to exploit the stored XSS vulnerability in the Exclusive
    Addons for Elementor plugin for WordPress, allowing attackers with contributor
    access or higher to inject arbitrary scripts.
level: low
detection:
    condition: selection
    selection:
        event_type: web_application_attack
        plugin_name: Exclusive Addons for Elementor
        plugin_version: 2.6.9
        attack_type: stored_xss
logsource:
    category: webserver
    product: wordpress
    definition: Web server access and error logs
falsepositives:
- Legitimate use of data attributes in web pages by authorized users.
- Custom scripts added by site administrators for functionality.
tags:
- tlp.amber
- attack.execution
- cve.2018-0296
- siemrules.text
- attack.t1070
- attack.t1591
confidence: 85
author: identity--a4d70b75-6f4a-5d19-9137-da863edd33d7
status: experimental
references:
- https://goo.gl/ref1/
- https://goo.gl/ref3/
date: 2025-03-01
""",
)

MODIFY_1 = {
    "rule_id": "indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72",
    "sigma": """
description: This description was modified
        """,
}

MODIFY_2 = {
    "rule_id": "indicator--2683daab-aa64-52ff-a001-3ea5aee9dd72",
    "sigma": """
description: This description has been modified twice
        """,
}

CORRELATION_RULE_1 = (
    "0e95725d-7320-415d-80f7-004da920fc11",
    """
title: Many failed logins
description: "my description"
correlation:
    type: event_count
    rules:
        - 9e2536b0-988b-598d-8cc3-407f9f13fc61
    group-by:
        - ComputerName
    timespan: 1h
    condition:
        gte: 100
tags:
    - tlp.amber
""",
)

CORRELATION_RULE_2 = (
    "8072047b-998e-43fc-a807-15c669c7343b",
    """
title: Bad login
description: Bad description
correlation:
    type: event_count
    rules:
        - 9e2536b0-988b-598d-8cc3-407f9f13fc61
        - 8af82832-2abd-5765-903c-01d414dae1e9
    group-by:
        - SampleGroup
    timespan: 1h
    condition:
        lt: 15
tags:
    - tlp.green
""",
)


from txt2detection.models import AIDetection

AI_DETECTION_1 = AIDetection(
    title="test",
    description="test description",
    status="experimental",
    level="high",
    tags=["tlp.green", "attack.t1008"],
    license="0BSD",
    falsepositives=["false positive 1", "false positive 2"],
    references=["https://example.com/ref1", "https://example.com/ref2"],
    logsource={"category": "test", "product": "test"},
    detection={"condition": "test condition"},
    indicator_types=[]
)

AI_DETECTION_1 = AIDetection(
    title="another test",
    description="another test description",
    status="stable",
    level="medium",
    tags=["tlp.red", "attack.t1557"],
    license="MIT",
    falsepositives=["another false positive"],
    references=["https://example.com/another_ref"],
    logsource={"category": "another_test", "product": "another_test"},
    detection={"condition": "another test condition"},
    indicator_types=[]
)