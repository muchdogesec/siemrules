
false, null, true = False, None, True
BUNDLE_1 = {
    "type": "bundle",
    "id": "bundle--bc14a07a-5189-5f64-85c3-33161b923627",
    "objects": [
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
            "created": "2022-10-01T00:00:00.000Z",
            "definition_type": "TLP:GREEN",
            "extensions": {
                "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                    "extension_type": "property-extension",
                    "tlp_2_0": "green"
                }
            }
        },
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2020-01-01T00:00:00.000Z",
            "definition_type": "statement",
            "definition": {
                "statement": "This object was created using: https://github.com/muchdogesec/txt2detection"
            },
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
            ]
        },
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "txt2detection",
            "description": "https://github.com/muchdogesec/txt2detection",
            "identity_class": "system",
            "sectors": [
                "technology"
            ],
            "contact_information": "https://www.dogesec.com/contact/",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
            ]
        },
        {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--bc14a07a-5189-5f64-85c3-33161b923627",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2024-05-01T08:53:31.000Z",
            "modified": "2025-03-28T08:43:13.104763Z",
            "name": "fake python vulnerability report",
            "description": "requirements.txt file that contains pypotr version 5.1.1. the version was uploaded by a state agent",
            "published": "2025-03-28T09:43:13.104727Z",
            "object_refs": [
                "indicator--4d374788-a139-5e3e-bd85-5edb209d8c16",
                "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
                "relationship--5e3611ef-e761-5037-af18-5c4541db0724"
            ],
            "labels": [
                "fake",
                "hand-written",
                "pypotr",
                "python"
            ],
            "confidence": 0,
            "external_references": [
                {
                    "source_name": "description_md5_hash",
                    "external_id": "681bd63bccfa6a880b3285972ec5db73"
                },
                {
                    "source_name": "url",
                    "external_id": "https://example.com/pypotr-compromised"
                }
            ],
            "object_marking_refs": [
                "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ]
        },
        {
            "type": "indicator",
            "id": "indicator--4d374788-a139-5e3e-bd85-5edb209d8c16",
            "spec_version": "2.1",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2024-05-01T08:53:31.000Z",
            "modified": "2025-03-28T08:43:13.104763Z",
            "indicator_types": [
                "malicious-activity",
                "compromised"
            ],
            "name": "Suspicious PyPI Package Version Upload",
            "labels": [
                "fake",
                "hand-written",
                "pypotr",
                "python"
            ],
            "pattern_type": "sigma",
            "pattern": "id: 4d374788-a139-5e3e-bd85-5edb209d8c16\ntitle: Suspicious PyPI Package Version Upload\ndescription: Detects the upload of a specific version of the 'pypotr' package, which\n    was uploaded by a state agent, indicating potential supply chain compromise.\ndetection:\n    selection:\n        event_id: package_upload\n        package_name: pypotr\n        version: 5.1.1\n    condition: selection\nlogsource:\n    category: package-management\n    product: pypi\nfalsepositives:\n- Legitimate upload by a trusted developer\n- Testing or development purposes\ntags:\n- attack.supply-chain\n- attack.initial-access\n- fake\n- hand-written\n- pypotr\n- python\nstatus: experimental\nlicense: Apache-2.0\nreferences: https://github.com/muchdogesec/txt2detection/\n",
            "valid_from": "2024-05-01T08:53:31.000Z",
            "object_marking_refs": [
                "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ],
            "external_references": [
                {
                    "external_id": "TA0001",
                    "url": "https://attack.mitre.org/tactics/TA0001",
                    "source_name": "mitre-attack"
                }
            ]
        },
        {
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "description": "The adversary is trying to get into your network.\n\nInitial Access consists of techniques that use various entry vectors to gain their initial foothold within a network. Techniques used to gain a foothold include targeted spearphishing and exploiting weaknesses on public-facing web servers. Footholds gained through initial access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.",
            "external_references": [
                {
                    "external_id": "TA0001",
                    "url": "https://attack.mitre.org/tactics/TA0001",
                    "source_name": "mitre-attack"
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
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_shortname": "initial-access",
            "x_mitre_version": "1.0"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--5e3611ef-e761-5037-af18-5c4541db0724",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2024-05-01T08:53:31.000Z",
            "modified": "2025-03-28T08:43:13.104763Z",
            "relationship_type": "mitre-attack",
            "description": "Suspicious PyPI Package Version Upload is linked to  TA0001 (Initial Access)",
            "source_ref": "indicator--4d374788-a139-5e3e-bd85-5edb209d8c16",
            "target_ref": "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/tactics/TA0001",
                    "external_id": "TA0001"
                }
            ],
            "object_marking_refs": [
                "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ]
        }
    ]
}



BUNDLE_2 = {
    "type": "bundle",
    "id": "bundle--60915f4c-fa2d-5bf1-b7d1-d7ecab167560",
    "objects": [
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
            "created": "2022-10-01T00:00:00.000Z",
            "definition_type": "TLP:GREEN",
            "extensions": {
                "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                    "extension_type": "property-extension",
                    "tlp_2_0": "green"
                }
            }
        },
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2020-01-01T00:00:00.000Z",
            "definition_type": "statement",
            "definition": {
                "statement": "This object was created using: https://github.com/muchdogesec/txt2detection"
            },
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
            ]
        },
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "txt2detection",
            "description": "https://github.com/muchdogesec/txt2detection",
            "identity_class": "system",
            "sectors": [
                "technology"
            ],
            "contact_information": "https://www.dogesec.com/contact/",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
            ]
        },
        {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--60915f4c-fa2d-5bf1-b7d1-d7ecab167560",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2025-01-23T17:31:01.000Z",
            "modified": "2025-03-28T09:58:26.83359Z",
            "name": "CVE-2024-3094",
            "description": "[CVE-2024-3094] Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.",
            "published": "2025-03-28T10:58:26.833566Z",
            "object_refs": [
                "indicator--881e6846-697c-5ec9-a353-32c448827930",
                "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
                "relationship--65126580-9937-5e0e-b65c-fc4b80850828",
                "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
                "relationship--6c1ff097-3171-5b2d-9fd9-5c239fcdcc83",
                "vulnerability--cf670f2c-81ff-5d1d-a3d6-abb4d6f25d15",
                "relationship--8c10e5c6-222c-5d15-b457-8fe6ddd1b9bb"
            ],
            "labels": [
                "downloaded",
                "nvd",
                "cve-2024-3094",
                "xz",
                "liblzma",
                "linux"
            ],
            "confidence": 54,
            "external_references": [
                {
                    "source_name": "description_md5_hash",
                    "external_id": "b937f62dc9e7c4eccd20c57d61e79df7"
                }
            ],
            "object_marking_refs": [
                "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ]
        },
        {
            "type": "indicator",
            "id": "indicator--881e6846-697c-5ec9-a353-32c448827930",
            "spec_version": "2.1",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2025-01-23T17:31:01.000Z",
            "modified": "2025-03-28T09:58:26.83359Z",
            "indicator_types": [
                "malicious-activity",
                "compromised"
            ],
            "name": "Detection of Malicious Code in xz Tarballs",
            "labels": [
                "downloaded",
                "nvd",
                "cve-2024-3094",
                "xz",
                "liblzma",
                "linux"
            ],
            "pattern_type": "sigma",
            "pattern": "id: 881e6846-697c-5ec9-a353-32c448827930\ntitle: Detection of Malicious Code in xz Tarballs\ndescription: Detects the presence of malicious code in the upstream tarballs of xz,\n    starting with version 5.6.0, which modifies the liblzma library to intercept and\n    modify data interactions.\ndetection:\n    selection:\n        file: xz-5.6.0.tar.gz\n        content: prebuilt object file\n    condition: selection\nlogsource:\n    category: file\n    product: linux\nfalsepositives:\n- Legitimate updates or patches to the xz library that include prebuilt object files\n    for performance reasons.\n- Custom builds of xz that include additional test files not related to malicious\n    activity.\ntags:\n- cve.2024-3094\n- attack.execution\n- attack.defense-evasion\n- downloaded\n- nvd\n- cve-2024-3094\n- xz\n- liblzma\n- linux\nstatus: experimental\nlicense: Apache-2.0\nreferences: https://github.com/muchdogesec/txt2detection/\n",
            "valid_from": "2025-01-23T17:31:01.000Z",
            "object_marking_refs": [
                "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ],
            "external_references": [
                {
                    "external_id": "TA0005",
                    "url": "https://attack.mitre.org/tactics/TA0005",
                    "source_name": "mitre-attack"
                },
                {
                    "external_id": "TA0002",
                    "url": "https://attack.mitre.org/tactics/TA0002",
                    "source_name": "mitre-attack"
                },
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                    "external_id": "CVE-2024-3094"
                }
            ]
        },
        {
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "description": "The adversary is trying to avoid being detected.\n\nDefense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics\u2019 techniques are cross-listed here when those techniques include the added benefit of subverting defenses. ",
            "external_references": [
                {
                    "external_id": "TA0005",
                    "url": "https://attack.mitre.org/tactics/TA0005",
                    "source_name": "mitre-attack"
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
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_shortname": "defense-evasion",
            "x_mitre_version": "1.0"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--65126580-9937-5e0e-b65c-fc4b80850828",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2025-01-23T17:31:01.000Z",
            "modified": "2025-03-28T09:58:26.83359Z",
            "relationship_type": "mitre-attack",
            "description": "Detection of Malicious Code in xz Tarballs is linked to  TA0005 (Defense Evasion)",
            "source_ref": "indicator--881e6846-697c-5ec9-a353-32c448827930",
            "target_ref": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/tactics/TA0005",
                    "external_id": "TA0005"
                }
            ],
            "object_marking_refs": [
                "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ]
        },
        {
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "description": "The adversary is trying to run malicious code.\n\nExecution consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, like exploring a network or stealing data. For example, an adversary might use a remote access tool to run a PowerShell script that does Remote System Discovery. ",
            "external_references": [
                {
                    "external_id": "TA0002",
                    "url": "https://attack.mitre.org/tactics/TA0002",
                    "source_name": "mitre-attack"
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
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_shortname": "execution",
            "x_mitre_version": "1.0"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--6c1ff097-3171-5b2d-9fd9-5c239fcdcc83",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2025-01-23T17:31:01.000Z",
            "modified": "2025-03-28T09:58:26.83359Z",
            "relationship_type": "mitre-attack",
            "description": "Detection of Malicious Code in xz Tarballs is linked to  TA0002 (Execution)",
            "source_ref": "indicator--881e6846-697c-5ec9-a353-32c448827930",
            "target_ref": "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/tactics/TA0002",
                    "external_id": "TA0002"
                }
            ],
            "object_marking_refs": [
                "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ]
        },
        {
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
                    "external_id": "CVE-2024-3094"
                },
                {
                    "source_name": "cwe",
                    "url": "https://cwe.mitre.org/data/definitions/CWE-506.html",
                    "external_id": "CWE-506"
                },
                {
                    "source_name": "secalert@redhat.com",
                    "description": "Vendor Advisory",
                    "url": "https://access.redhat.com/security/cve/CVE-2024-3094"
                },
                {
                    "source_name": "secalert@redhat.com",
                    "description": "Issue Tracking,Vendor Advisory",
                    "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2272210"
                },
                {
                    "source_name": "secalert@redhat.com",
                    "description": "Mailing List",
                    "url": "https://www.openwall.com/lists/oss-security/2024/03/29/4"
                },
                {
                    "source_name": "secalert@redhat.com",
                    "description": "Vendor Advisory",
                    "url": "https://www.redhat.com/en/blog/urgent-security-alert-fedora-41-and-rawhide-users"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "http://www.openwall.com/lists/oss-security/2024/03/29/10"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "http://www.openwall.com/lists/oss-security/2024/03/29/12"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "http://www.openwall.com/lists/oss-security/2024/03/29/4"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "http://www.openwall.com/lists/oss-security/2024/03/29/5"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "http://www.openwall.com/lists/oss-security/2024/03/29/8"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "http://www.openwall.com/lists/oss-security/2024/03/30/12"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "http://www.openwall.com/lists/oss-security/2024/03/30/27"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "http://www.openwall.com/lists/oss-security/2024/03/30/36"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "http://www.openwall.com/lists/oss-security/2024/03/30/5"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "http://www.openwall.com/lists/oss-security/2024/04/16/5"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Vendor Advisory",
                    "url": "https://access.redhat.com/security/cve/CVE-2024-3094"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "https://ariadne.space/2024/04/02/the-xz-utils-backdoor-is-a-symptom-of-a-larger-problem/"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://arstechnica.com/security/2024/03/backdoor-found-in-widely-used-linux-utility-breaks-encrypted-ssh-connections/"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://aws.amazon.com/security/security-bulletins/AWS-2024-002/"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "https://blog.netbsd.org/tnf/entry/statement_on_backdoor_in_xz"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://boehs.org/node/everything-i-know-about-the-xz-backdoor"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Mailing List,Vendor Advisory",
                    "url": "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1068024"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Issue Tracking,Third Party Advisory",
                    "url": "https://bugs.gentoo.org/928134"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Issue Tracking,Vendor Advisory",
                    "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2272210"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Issue Tracking,Third Party Advisory",
                    "url": "https://bugzilla.suse.com/show_bug.cgi?id=1222124"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://discourse.nixos.org/t/cve-2024-3094-malicious-code-in-xz-5-6-0-and-5-6-1-tarballs/42405"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://gist.github.com/thesamesam/223949d5a074ebc3dce9ee78baad9e27"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://github.com/advisories/GHSA-rxwq-x6h5-x525"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "https://github.com/amlweems/xzbot"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://github.com/karcherm/xz-malware"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Technical Description,Third Party Advisory",
                    "url": "https://gynvael.coldwind.pl/?lang=en&id=782"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Mailing List,Third Party Advisory",
                    "url": "https://lists.debian.org/debian-security-announce/2024/msg00057.html"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://lists.freebsd.org/archives/freebsd-security/2024-March/000248.html"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Issue Tracking,Third Party Advisory",
                    "url": "https://lwn.net/Articles/967180/"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Issue Tracking,Third Party Advisory",
                    "url": "https://news.ycombinator.com/item?id=39865810"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Issue Tracking",
                    "url": "https://news.ycombinator.com/item?id=39877267"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "https://news.ycombinator.com/item?id=39895344"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://openssf.org/blog/2024/03/30/xz-backdoor-cve-2024-3094/"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "https://research.swtch.com/xz-script"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "https://research.swtch.com/xz-timeline"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://security-tracker.debian.org/tracker/CVE-2024-3094"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://security.alpinelinux.org/vuln/CVE-2024-3094"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://security.archlinux.org/CVE-2024-3094"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "https://security.netapp.com/advisory/ntap-20240402-0001/"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Issue Tracking,Vendor Advisory",
                    "url": "https://tukaani.org/xz-backdoor/"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://twitter.com/LetsDefendIO/status/1774804387417751958"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Press/Media Coverage",
                    "url": "https://twitter.com/debian/status/1774219194638409898"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Press/Media Coverage",
                    "url": "https://twitter.com/infosecb/status/1774595540233167206"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Press/Media Coverage",
                    "url": "https://twitter.com/infosecb/status/1774597228864139400"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://ubuntu.com/security/CVE-2024-3094"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory,US Government Resource",
                    "url": "https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://www.darkreading.com/vulnerabilities-threats/are-you-affected-by-the-backdoor-in-xz-utils"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "https://www.kali.org/blog/about-the-xz-backdoor/"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Mailing List",
                    "url": "https://www.openwall.com/lists/oss-security/2024/03/29/4"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Vendor Advisory",
                    "url": "https://www.redhat.com/en/blog/urgent-security-alert-fedora-41-and-rawhide-users"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://www.tenable.com/blog/frequently-asked-questions-cve-2024-3094-supply-chain-backdoor-in-xz-utils"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Press/Media Coverage",
                    "url": "https://www.theregister.com/2024/03/29/malicious_backdoor_xz/"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "",
                    "url": "https://www.vicarius.io/vsociety/vulnerabilities/cve-2024-3094"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://xeiaso.net/notes/2024/xz-vuln/"
                },
                {
                    "source_name": "vulnStatus",
                    "description": "Modified"
                },
                {
                    "source_name": "sourceIdentifier",
                    "description": "secalert@redhat.com"
                }
            ],
            "id": "vulnerability--cf670f2c-81ff-5d1d-a3d6-abb4d6f25d15",
            "modified": "2025-02-06T09:15:10.820Z",
            "name": "CVE-2024-3094",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3"
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
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                }
            }
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--8c10e5c6-222c-5d15-b457-8fe6ddd1b9bb",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2025-01-23T17:31:01.000Z",
            "modified": "2025-03-28T09:58:26.83359Z",
            "relationship_type": "nvd-cve",
            "description": "Detection of Malicious Code in xz Tarballs is linked to  CVE-2024-3094 (CVE-2024-3094)",
            "source_ref": "indicator--881e6846-697c-5ec9-a353-32c448827930",
            "target_ref": "vulnerability--cf670f2c-81ff-5d1d-a3d6-abb4d6f25d15",
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                    "external_id": "CVE-2024-3094"
                }
            ],
            "object_marking_refs": [
                "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ]
        }
    ]
}




BUNDLE_3 = {
    "type": "bundle",
    "id": "bundle--cc297329-2c8d-55f3-bef9-3137bb9d87a7",
    "objects": [
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
            "created": "2022-10-01T00:00:00.000Z",
            "definition_type": "TLP:AMBER",
            "extensions": {
                "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                    "extension_type": "property-extension",
                    "tlp_2_0": "amber"
                }
            }
        },
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2020-01-01T00:00:00.000Z",
            "definition_type": "statement",
            "definition": {
                "statement": "This object was created using: https://github.com/muchdogesec/txt2detection"
            },
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
            ]
        },
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "txt2detection",
            "description": "https://github.com/muchdogesec/txt2detection",
            "identity_class": "system",
            "sectors": [
                "technology"
            ],
            "contact_information": "https://www.dogesec.com/contact/",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
            ]
        },
        {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--cc297329-2c8d-55f3-bef9-3137bb9d87a7",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2025-03-01T00:00:01.000Z",
            "modified": "2025-03-28T10:01:08.019151Z",
            "name": "Downloaded Description for CVE-2024-1234",
            "description": "In CVE-2024-1234, The Exclusive Addons for Elementor plugin for WordPress is vulnerable to Stored Cross-Site Scripting via data attribute in all versions up to, and including, 2.6.9 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with contributor access or higher, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.",
            "published": "2025-03-28T11:01:08.019123Z",
            "object_refs": [
                "indicator--815e3b87-d1e1-52fb-aa44-0dc7a9b55116",
                "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830",
                "relationship--b8042746-631f-5007-bebe-33bd9a76ec27",
                "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
                "relationship--a7d86e04-0400-57d1-8714-2a4e6d4a9ee6",
                "vulnerability--a99faefb-377e-585b-9890-70f73d75ffee",
                "relationship--b70ae89a-b0ca-5ce7-92c9-9bf8a5ae2bfc"
            ],
            "labels": [
                "downloaded",
                "nvd",
                "cve-2024-1234",
                "something else"
            ],
            "confidence": 96,
            "external_references": [
                {
                    "source_name": "description_md5_hash",
                    "external_id": "da2276adac7c1bad6ad26565b712d89c"
                }
            ],
            "object_marking_refs": [
                "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ]
        },
        {
            "type": "indicator",
            "id": "indicator--815e3b87-d1e1-52fb-aa44-0dc7a9b55116",
            "spec_version": "2.1",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2025-03-01T00:00:01.000Z",
            "modified": "2025-03-28T10:01:08.019151Z",
            "indicator_types": [
                "malicious-activity"
            ],
            "name": "Detection of Stored Cross-Site Scripting in Exclusive Addons for Elementor",
            "labels": [
                "downloaded",
                "nvd",
                "cve-2024-1234",
                "something else"
            ],
            "pattern_type": "sigma",
            "pattern": "id: 815e3b87-d1e1-52fb-aa44-0dc7a9b55116\ntitle: Detection of Stored Cross-Site Scripting in Exclusive Addons for Elementor\ndescription: Detects attempts to exploit CVE-2024-1234, a stored XSS vulnerability\n    in the Exclusive Addons for Elementor plugin for WordPress, allowing authenticated\n    users with contributor access or higher to inject arbitrary scripts.\ndetection:\n    selection:\n        EventID: '4104'\n        ScriptBlockText: '*Exclusive Addons for Elementor*'\n    condition: selection\nlogsource:\n    product: webserver\n    service: http\n    definition: logs from web server access or application logs\nfalsepositives:\n- Legitimate use of the Exclusive Addons for Elementor plugin by authorized users.\n- Non-malicious scripts added by developers for testing purposes.\ntags:\n- attack.execution\n- attack.t1059\n- cve.2024-1234\n- downloaded\n- nvd\n- cve-2024-1234\n- something else\nstatus: experimental\nlicense: Apache-2.0\nreferences: https://github.com/muchdogesec/txt2detection/\n",
            "valid_from": "2025-03-01T00:00:01.000Z",
            "object_marking_refs": [
                "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1059",
                    "external_id": "T1059"
                },
                {
                    "external_id": "TA0002",
                    "url": "https://attack.mitre.org/tactics/TA0002",
                    "source_name": "mitre-attack"
                },
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                    "external_id": "CVE-2024-1234"
                }
            ]
        },
        {
            "created": "2017-05-31T21:30:49.546Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of [Unix Shell](https://attack.mitre.org/techniques/T1059/004) while Windows installations include the [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).\n\nThere are also cross-platform interpreters such as [Python](https://attack.mitre.org/techniques/T1059/006), as well as those commonly associated with client applications such as [JavaScript](https://attack.mitre.org/techniques/T1059/007) and [Visual Basic](https://attack.mitre.org/techniques/T1059/005).\n\nAdversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in [Initial Access](https://attack.mitre.org/tactics/TA0001) payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells, as well as utilize various [Remote Services](https://attack.mitre.org/techniques/T1021) in order to achieve remote Execution.(Citation: Powershell Remote Commands)(Citation: Cisco IOS Software Integrity Assurance - Command History)(Citation: Remote Shell Execution in Python)",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1059",
                    "external_id": "T1059"
                },
                {
                    "source_name": "Remote Shell Execution in Python",
                    "description": "Abdou Rockikz. (2020, July). How to Execute Shell Commands in a Remote Machine in Python. Retrieved July 26, 2021.",
                    "url": "https://www.thepythoncode.com/article/executing-bash-commands-remotely-in-python"
                },
                {
                    "source_name": "Cisco IOS Software Integrity Assurance - Command History",
                    "description": "Cisco. (n.d.). Cisco IOS Software Integrity Assurance - Command History. Retrieved October 21, 2020.",
                    "url": "https://tools.cisco.com/security/center/resources/integrity_assurance.html#23"
                },
                {
                    "source_name": "Powershell Remote Commands",
                    "description": "Microsoft. (2020, August 21). Running Remote Commands. Retrieved July 26, 2021.",
                    "url": "https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.1"
                }
            ],
            "id": "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "execution"
                }
            ],
            "modified": "2024-10-14T22:11:30.271Z",
            "name": "Command and Scripting Interpreter",
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "revoked": false,
            "spec_version": "2.1",
            "type": "attack-pattern",
            "x_mitre_attack_spec_version": "3.2.0",
            "x_mitre_data_sources": [
                "Script: Script Execution",
                "Process: Process Creation",
                "Process: Process Metadata",
                "Module: Module Load",
                "Command: Command Execution"
            ],
            "x_mitre_deprecated": false,
            "x_mitre_detection": "Command-line and scripting activities can be captured through proper logging of process execution with command-line arguments. This information can be useful in gaining additional insight to adversaries' actions through how they use native processes or custom tools. Also monitor for loading of modules associated with specific languages.\n\nIf scripting is restricted for normal users, then any attempt to enable scripts running on a system would be considered suspicious. If scripts are not commonly used on a system, but enabled, scripts running out of cycle from patching or other administrator functions are suspicious. Scripts should be captured from the file system when possible to determine their actions and intent.\n\nScripts are likely to perform actions with various effects on a system that may generate events, depending on the types of monitoring used. Monitor processes and command-line arguments for script execution and subsequent behavior. Actions may be related to network and system information discovery, collection, or other scriptable post-compromise behaviors and could be used as indicators of detection leading back to the source script.",
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_is_subtechnique": false,
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_platforms": [
                "Linux",
                "macOS",
                "Windows",
                "Network",
                "IaaS",
                "Office Suite",
                "Identity Provider"
            ],
            "x_mitre_remote_support": true,
            "x_mitre_version": "2.5"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--b8042746-631f-5007-bebe-33bd9a76ec27",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2025-03-01T00:00:01.000Z",
            "modified": "2025-03-28T10:01:08.019151Z",
            "relationship_type": "mitre-attack",
            "description": "Detection of Stored Cross-Site Scripting in Exclusive Addons for Elementor is linked to  T1059 (Command and Scripting Interpreter)",
            "source_ref": "indicator--815e3b87-d1e1-52fb-aa44-0dc7a9b55116",
            "target_ref": "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1059",
                    "external_id": "T1059"
                }
            ],
            "object_marking_refs": [
                "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ]
        },
        {
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "description": "The adversary is trying to run malicious code.\n\nExecution consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, like exploring a network or stealing data. For example, an adversary might use a remote access tool to run a PowerShell script that does Remote System Discovery. ",
            "external_references": [
                {
                    "external_id": "TA0002",
                    "url": "https://attack.mitre.org/tactics/TA0002",
                    "source_name": "mitre-attack"
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
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_shortname": "execution",
            "x_mitre_version": "1.0"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--a7d86e04-0400-57d1-8714-2a4e6d4a9ee6",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2025-03-01T00:00:01.000Z",
            "modified": "2025-03-28T10:01:08.019151Z",
            "relationship_type": "mitre-attack",
            "description": "Detection of Stored Cross-Site Scripting in Exclusive Addons for Elementor is linked to  TA0002 (Execution)",
            "source_ref": "indicator--815e3b87-d1e1-52fb-aa44-0dc7a9b55116",
            "target_ref": "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/tactics/TA0002",
                    "external_id": "TA0002"
                }
            ],
            "object_marking_refs": [
                "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ]
        },
        {
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
                    "external_id": "CVE-2024-1234"
                },
                {
                    "source_name": "cwe",
                    "url": "https://cwe.mitre.org/data/definitions/CWE-79.html",
                    "external_id": "CWE-79"
                },
                {
                    "source_name": "security@wordfence.com",
                    "description": "Patch",
                    "url": "https://plugins.trac.wordpress.org/changeset/3042217/exclusive-addons-for-elementor"
                },
                {
                    "source_name": "security@wordfence.com",
                    "description": "Third Party Advisory",
                    "url": "https://www.wordfence.com/threat-intel/vulnerabilities/id/1b87fe3d-a88d-477a-8d91-4d7c2dba4a43?source=cve"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Patch",
                    "url": "https://plugins.trac.wordpress.org/changeset/3042217/exclusive-addons-for-elementor"
                },
                {
                    "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                    "description": "Third Party Advisory",
                    "url": "https://www.wordfence.com/threat-intel/vulnerabilities/id/1b87fe3d-a88d-477a-8d91-4d7c2dba4a43?source=cve"
                },
                {
                    "source_name": "vulnStatus",
                    "description": "Analyzed"
                },
                {
                    "source_name": "sourceIdentifier",
                    "description": "security@wordfence.com"
                }
            ],
            "id": "vulnerability--a99faefb-377e-585b-9890-70f73d75ffee",
            "modified": "2025-01-23T19:50:50.457Z",
            "name": "CVE-2024-1234",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3"
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
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"
                }
            }
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--b70ae89a-b0ca-5ce7-92c9-9bf8a5ae2bfc",
            "created_by_ref": "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7",
            "created": "2025-03-01T00:00:01.000Z",
            "modified": "2025-03-28T10:01:08.019151Z",
            "relationship_type": "nvd-cve",
            "description": "Detection of Stored Cross-Site Scripting in Exclusive Addons for Elementor is linked to  CVE-2024-1234 (CVE-2024-1234)",
            "source_ref": "indicator--815e3b87-d1e1-52fb-aa44-0dc7a9b55116",
            "target_ref": "vulnerability--a99faefb-377e-585b-9890-70f73d75ffee",
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                    "external_id": "CVE-2024-1234"
                }
            ],
            "object_marking_refs": [
                "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
                "marking-definition--a4d70b75-6f4a-5d19-9137-da863edd33d7"
            ]
        }
    ]
}


