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
confidence: 85
author: '{"type": "identity", "spec_version": "2.1", "id": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7", "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5", "created": "2020-01-01T00:00:00.000Z", "modified": "2020-01-01T00:00:00.000Z", "name": "txt2detection", "description": "https://github.com/muchdogesec/txt2detection", "identity_class": "system", "sectors": ["technology"], "contact_information": "https://www.dogesec.com/contact/", "object_marking_refs": ["marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487", "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"]}'
status: experimental
date: 2024-05-01
""",
)

SIGMA_RULE_2 = (
    "9e2536b0-988b-598d-8cc3-407f9f13fc61",
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
confidence: 85
author: identity--a4d70b75-6f4a-5d19-9137-da863edd33d7
status: experimental
license: 0BSD
date: 2025-01-23
""",
)

SIGMA_RULE_3 = (
    "2683daab-aa64-52ff-a001-3ea5aee9dd72",
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
falsepositives:
- Legitimate use of data attributes in web pages by authorized users.
- Custom scripts added by site administrators for functionality.
tags:
- tlp.amber
- attack.execution
- cve.2024-1234
- siemrules.text
confidence: 85
author: identity--a4d70b75-6f4a-5d19-9137-da863edd33d7
status: experimental
references:
- https://goo.gl/ref1/
- https://goo.gl/ref3/
date: 2025-03-01
""",
)

objects_lookup = {
    "CVE-2024-3094": {
        "created": "2024-03-29T17:15:21.150Z",
        "created_by_ref": "identity--562918ee-d5da-5579-b6a1-fae50cc6bad3",
        "description": "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. \r\nThrough a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.",
        "extensions": {
            "extension-definition--2c5c13af-ee92-5246-9ba7-0b958f8cd34a": {
                "extension_type": "toplevel-property-extension"
            }
        },
        "external_references": [
            {
                "source_name": "cve",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                "external_id": "CVE-2024-3094",
            }
        ],
        "id": "vulnerability--cf670f2c-81ff-5d1d-a3d6-abb4d6f25d15",
        "modified": "2025-02-06T09:15:10.820Z",
        "name": "CVE-2024-3094",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
        ],
        "spec_version": "2.1",
        "type": "vulnerability",
        "x_cvss": {
            "v3_1": {
                "base_score": 10,
                "base_severity": "CRITICAL",
                "exploitability_score": 3.9,
                "impact_score": 6,
                "source": "secalert@redhat.com",
                "type": "Secondary",
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            }
        },
    },
    "TA0002": {
        "created": "2018-10-17T00:14:20.652Z",
        "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
        "description": "The adversary is trying to run malicious code.\n\nExecution consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, like exploring a network or stealing data. For example, an adversary might use a remote access tool to run a PowerShell script that does Remote System Discovery. ",
        "external_references": [
            {
                "external_id": "TA0002",
                "url": "https://attack.mitre.org/tactics/TA0002",
                "source_name": "mitre-attack",
            }
        ],
        "id": "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
        "modified": "2022-04-25T14:00:00.188Z",
        "name": "Execution",
        "object_marking_refs": [
            "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
        ],
        "spec_version": "2.1",
        "type": "x-mitre-tactic",
        "x_mitre_attack_spec_version": "2.1.0",
        "x_mitre_domains": ["enterprise-attack"],
        "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
        "x_mitre_shortname": "execution",
        "x_mitre_version": "1.0",
    },
    "TA0005": {
        "created": "2018-10-17T00:14:20.652Z",
        "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
        "description": "The adversary is trying to avoid being detected.\n\nDefense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics\u2019 techniques are cross-listed here when those techniques include the added benefit of subverting defenses. ",
        "external_references": [
            {
                "external_id": "TA0005",
                "url": "https://attack.mitre.org/tactics/TA0005",
                "source_name": "mitre-attack",
            }
        ],
        "id": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
        "modified": "2022-04-25T14:00:00.188Z",
        "name": "Defense Evasion",
        "object_marking_refs": [
            "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
        ],
        "spec_version": "2.1",
        "type": "x-mitre-tactic",
        "x_mitre_attack_spec_version": "2.1.0",
        "x_mitre_domains": ["enterprise-attack"],
        "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
        "x_mitre_shortname": "defense-evasion",
        "x_mitre_version": "1.0",
    },
    "TA0001": {
        "created": "2018-10-17T00:14:20.652Z",
        "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
        "description": "The adversary is trying to get into your network.\n\nInitial Access consists of techniques that use various entry vectors to gain their initial foothold within a network. Techniques used to gain a foothold include targeted spearphishing and exploiting weaknesses on public-facing web servers. Footholds gained through initial access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.",
        "external_references": [
            {
                "external_id": "TA0001",
                "url": "https://attack.mitre.org/tactics/TA0001",
                "source_name": "mitre-attack",
            }
        ],
        "id": "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
        "modified": "2022-04-25T14:00:00.188Z",
        "name": "Initial Access",
        "object_marking_refs": [
            "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
        ],
        "spec_version": "2.1",
        "type": "x-mitre-tactic",
        "x_mitre_attack_spec_version": "2.1.0",
        "x_mitre_domains": ["enterprise-attack"],
        "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
        "x_mitre_shortname": "initial-access",
        "x_mitre_version": "1.0",
    },
    "CVE-2024-1234": {
        "created": "2024-03-13T16:15:18.390Z",
        "created_by_ref": "identity--562918ee-d5da-5579-b6a1-fae50cc6bad3",
        "description": "The Exclusive Addons for Elementor plugin for WordPress is vulnerable to Stored Cross-Site Scripting via data attribute in all versions up to, and including, 2.6.9 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with contributor access or higher, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.",
        "extensions": {
            "extension-definition--2c5c13af-ee92-5246-9ba7-0b958f8cd34a": {
                "extension_type": "toplevel-property-extension"
            }
        },
        "external_references": [
            {
                "source_name": "cve",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                "external_id": "CVE-2024-1234",
            },
            {
                "source_name": "cwe",
                "url": "https://cwe.mitre.org/data/definitions/CWE-79.html",
                "external_id": "CWE-79",
            },
            {
                "source_name": "security@wordfence.com",
                "description": "Patch",
                "url": "https://plugins.trac.wordpress.org/changeset/3042217/exclusive-addons-for-elementor",
            },
            {
                "source_name": "security@wordfence.com",
                "description": "Third Party Advisory",
                "url": "https://www.wordfence.com/threat-intel/vulnerabilities/id/1b87fe3d-a88d-477a-8d91-4d7c2dba4a43?source=cve",
            },
            {
                "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                "description": "Patch",
                "url": "https://plugins.trac.wordpress.org/changeset/3042217/exclusive-addons-for-elementor",
            },
            {
                "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                "description": "Third Party Advisory",
                "url": "https://www.wordfence.com/threat-intel/vulnerabilities/id/1b87fe3d-a88d-477a-8d91-4d7c2dba4a43?source=cve",
            },
            {"source_name": "vulnStatus", "description": "Analyzed"},
            {
                "source_name": "sourceIdentifier",
                "description": "security@wordfence.com",
            },
        ],
        "id": "vulnerability--a99faefb-377e-585b-9890-70f73d75ffee",
        "modified": "2025-01-23T19:50:50.457Z",
        "name": "CVE-2024-1234",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
        ],
        "spec_version": "2.1",
        "type": "vulnerability",
        "x_cvss": {
            "v3_1": {
                "base_score": 6.4,
                "base_severity": "MEDIUM",
                "exploitability_score": 3.1,
                "impact_score": 2.7,
                "source": "security@wordfence.com",
                "type": "Secondary",
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
            }
        },
    },
}

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
    group-by:
        - SampleGroup
    timespan: 1h
    condition:
        lt: 15
tags:
    - tlp.green
""",
)
