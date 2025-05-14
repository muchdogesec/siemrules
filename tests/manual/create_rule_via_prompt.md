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
  "report_id": "report--441fd854-fe0b-4b4b-ae0f-26655b8e5c01",
  "labels": [
    "label.one",
    "namespace.tag"
  ],
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

### License

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "testing license",
  "report_id": "report--e185ca7e-0e32-4505-a97f-57143942af47",
  "license": "MIT",
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

### References

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "testing references",
  "report_id": "report--a2efe5a8-4586-4c5f-b87c-702ea822eb27",
  "references": [
    "https://google.com",
    "https://facebook.com"
  ],
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

Check references in external ref and Sigma rule


## Base Rule Create (bad): Prompt

### Has Attack labels 

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "bad has attack tags",
  "report_id": "report--0e428fd7-d65d-4bf6-8764-8a973914f5a5",
  "labels": [
    "attack.t1176.002",
    "attack.t1674"
  ],
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

attack tags not allowed

### Has CVE labels 

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "bad has cve tags",
  "report_id": "report--c6046104-e2ca-4227-bbc0-0f29d8801901",
  "labels": [
    "cve.2021-1675"
  ],
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

cve tags not allowed

### Bad tag type

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "bad has cve tags",
  "report_id": "report--c6046104-e2ca-4227-bbc0-0f29d8801901",
  "labels": [
    "bad_tag"
  ],
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

does not use namespace

### Bad reference

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "bad reference",
  "report_id": "report--bbd9efdc-33e5-4b2c-85f7-c190684bed3b",
  "references": [
    "not a url"
  ],
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

### Bad identity

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "bad identity",
  "report_id": "report--2aad562d-4e26-448a-b5a9-016fb44e9769",
  "identity": "identity--068335dc-7ad6-4ed6-a053-cb3f76a1ad1a",
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```

### Bad tlp

```json
{
  "ai_provider": "openai:gpt-4o",
  "text_input": "Create a detection rule for 1[.]1[.]1[.]1",
  "name": "bad tlp",
  "report_id": "report--dfc76a31-3406-47ad-a9a3-8ab4d840dda2",
  "tlp_level": "black",
  "defang": true,
  "ignore_embedded_relationships": false,
  "ignore_embedded_relationships_sro": true,
  "ignore_embedded_relationships_smo": true
}
```
