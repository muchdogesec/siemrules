
## Base Rule Create (good): Prompt

### Minimum allowed info

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "testing minimum values",
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

* Default TLP level should be `clear`
* `created` and `modified` should be time run
* check SIEM rules identity used to create objects

### Created time

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "testing created",
  "report_id": "report--005c5f5e-3ef4-4853-a14c-274af0fbd391",
  "created": "2020-01-01T00:00:00",
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

* `created` and `modified` should match `created` value

### tlp level

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "testing tlp green",
  "report_id": "report--f913ff8a-a024-4d97-ac94-ab8721fc10a8",
  "tlp_level": "green",
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "testing tlp amber+strict",
  "report_id": "report--f913ff8a-a024-4d97-ac94-ab8721fc10a8",
  "tlp_level": "amber+strict",
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

* all SDOs and SROs should have this marking
* check no SROs have this marking

### Identity

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "using custom identity",
  "report_id": "report--129017ea-5700-4814-a310-c57d2f1fd23a",
  "identity": {"type":"identity","spec_version":"2.1","id":"identity--068335dc-7ad6-4ed6-a053-cb3f76a1ad1a","name":"Using a custom Identity"},
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

* check assigned to all SDOs, non embedded SROs

### Labels

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "testing labels",
  "report_id": "report--129017ea-5700-4814-a310-c57d2f1fd23a",
  "identity": {"type":"identity","spec_version":"2.1","id":"identity--068335dc-7ad6-4ed6-a053-cb3f76a1ad1a","name":"Using a custom Identity"},
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```



```json
{
  "report_id": "report--7cd0e894-919b-4a3b-b70e-3a9291e7de55",
  "tlp_level": "green",
  "labels": [
    "cve.2025-36546",
    "attack.t1176.002",
    "attack.t1674"
  ],
  "defang": true,
  "ai_provider": "openai:gpt-4o",
  "references": [
    "https://google.com",
    "https://facebook.com"
  ],
  "license": "0BSD",
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true,
  "created": "2025-05-08T15:18:14.359Z",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "Basic IP input"
}
```

## Base Rule Create (bad): Prompt

### Has Attack labels 

```json
{
  "report_id": "report--3d422c9f-c5e9-43d7-b802-090996e2214e",
  "identity": {"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15","name":"Dummy Identity"},
  "tlp_level": "red",
  "labels": [
    "attack.t1176.002",
    "attack.t1674"
  ],
  "defang": true,
  "ai_provider": "openai:gpt-4o",
  "references": [
    "https://google.com",
    "https://facebook.com"
  ],
  "license": "0BSD",
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true,
  "created": "2025-05-08T15:18:14.359Z",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "Basic IP input"
}
```

### Has CVE labels 

```json
{
  "report_id": "report--3d422c9f-c5e9-43d7-b802-090996e2214e",
  "identity": {"type":"identity","spec_version":"2.1","id":"identity--b1ae1a15-6f4b-431e-b990-1b9678f35e15","name":"Dummy Identity"},
  "tlp_level": "red",
  "labels": [
    "attack.t1176.002",
    "attack.t1674"
  ],
  "defang": true,
  "ai_provider": "openai:gpt-4o",
  "references": [
    "https://google.com",
    "https://facebook.com"
  ],
  "license": "0BSD",
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true,
  "created": "2025-05-08T15:18:14.359Z",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "Basic IP input"
}
```

