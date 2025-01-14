# SIEM Rules

## Before you begin...

We offer a fully hosted web version of SIEM Rules which includes many additional features over those in this codebase. [You can find out more about the web version here](https://www.siemrules.com/).

## Overview

An API that takes a file containing threat intelligence and turns it into a detection rule.

## How it works

1. User uploads files (these are typically threat intel reports)
2. The file is converted to txt (using [file2txt](https://github.com/muchdogesec/file2txt))
3. User inputs processed by [txt2detection](https://github.com/muchdogesec/txt2detection)
4. Objects stored in ArangoDB using [stix2arango](https://github.com/muchdogesec/stix2arango) / Postgres for non STIX objects
5. Objects exposed via API

Step 2 to 4 are tracked in a concept of a Job.

## Storage of STIX objects in ArangoDB

On build of the app, a database should created in arango_db called `stixify` with 2 collections called `siemrules_vertex_collection` / `siemrules_edge_collection`

## API

### Schema

To make it easy for users to get up and running, we should build the API against the OpenAPI v3 spec (https://spec.openapis.org/oas/v3.1.0). We can then use Swagger (https://swagger.io/resources/open-api/) to automatically deliver a lightweight view to allow users to interact with the API in the browser.

### Pagination

We should add an `.env` variable that allows user to set max record returned per page.

All paginated responses should contain the header;

```json
{
    "page_number": "<NUMBER>",
    "page_size": "<SET IN ENV>",
    "page_results_count": "<COUNT OF RESULTS ON PAGE>",
    "total_results_count": "<COUNT OF RESULTS ON ALL PAGES>",
```

### Endpoints

#### Files

Files are uploaded. Uploaded files are turned into markdown files.

##### POST Upload a file

```shell
POST HOST/api/v1/files/
```

The file should be posted as `form-data`.

The file mimetype will be validated before file is processed by the server. If mimetype does not match supported value by file2txt will result in error.

```json
{
  "name": "<USED FOR STIX REPORT>", // txt2detection setting
  "description": "USED FOR STIX REPORT>", // txt2detection setting
  "identity": "{<identity.json>}", // txt2detection setting
  "labels": ["value"], // txt2detection setting
  "tlp_level": "<value>", // txt2detection setting
  "created": "<value>", // txt2detection setting
  "file": "<path to file>", // path to intel file
  "mode": "<value>", // file2txt setting (this is a secondary validation) // REQUIRED
  "defang": "<boolean>", // file2txt setting // OPTIONAL, DEFAULT IS TRUE
  "extract_text_from_image": "<boolean>", // file2txt setting // OPTIONAL, DEFAULT IS FALSE
  "ai_provider": "<value>", // txt2detection setting // OPTIONAL, DEFAULT IS FALSE
  "detection_language": "<value>"
}
```

Will return a 200 response with job info

```json
{
    "jobs": [
        {
            "id": "<value>",
            "report_id": "<value>",
            "mode": "<value>",
            "defang": "<boolean>",
            "extract_text_from_image": "<boolean>",
            "name": "<value>",
            "description": "<value>",
            "tlp_level": "<value>",
            "labels": ["<value1","value2"],
            "identity": "{<identity.json>}",
            "detection_language": "<ID>",
            "state": "<STATE>",
            "run_datetime": "<START TIME>",
            "info": "string"
        }
    ]
}
```

##### GET Files

```shell
GET HOST/api/VERSION/files/
```

Accepts URL parameters

* `report_id` (optional): search by Report ID generated from this file
* `indicator_id` (optional): search using the Indicator ID from this file
* `name` (optional): filter by name, is wildcard
* `page_size` (max is 50, default is 50)
* `page`
    * default is 0
* `sort`:
    * `created_ascending`
    * `created_descending` (default)
    * `name_ascending`
    * `name_descending`

```json
{
  "files": [    
    {
      "id": "<ID>",
      "name": "<NAME>",
      "job_id": "<JOB ID>",
      "mimetype": "string",
      "size_mb": "string",
      "download_url": "string"
    },
    {
      "id": "<ID>",
      "name": "<NAME>",
      "job_id": "<JOB ID>",
      "mimetype": "string",
      "size_mb": "string",
      "download_url": "string"
    }
  ]
}
```

##### GET File by ID

```shell
GET HOST/api/VERSION/files/{id}
```

```json
{
  "files": [    
    {
      "id": "<ID>",
      "name": "<NAME>",
      "job_id": "<JOB ID>",
      "mimetype": "string",
      "size_mb": "string",
      "download_url": "string"
    }
  ]
}
```

##### Get a File Markdown

```shell
GET HOST/api/VERSION/files/markdown
```

Same as Stixify

##### Get a File Images

```shell
GET HOST/api/VERSION/files/images
```

Same as Stixify

##### Get a File Objects (aka detections linked to files)

```shell
GET HOST/api/VERSION/files/objects
```

Only returns indicators.

##### DELETE a File By ID

```shell
DELETE HOST/api/VERSION/files/{id}
```

Will delete the file, and all detection rules / markdown created from it.

#### Detection Rules

Files are processed into detection rules.

##### POST Rules

A user can manually add a Sigma Rule (in yml format), not associate with a threat report (file). This is processed using sigma2stix in `--mode sigmayaml`.

Response will return a job id.

##### GET Rules

```shell
GET <HOST>/api/v1/rules/
```

Returns all Indicator objects that match the criteria.

* `file_id` (optional, list): search by Report ID generated from this file
* `id` (optional): search using the Indicator ID from this file
* `name` (optional): filter by name, is wildcard
* `description` (optional): filter by description, is wildcard
* `tlp_level` (optional)
* `attack_id` (optional)
* `cve_id` (optional)
* `created_by_ref` (optional, list)
* `page_size` (max is 50, default is 50)
* `page`
    * default is 0
* `sort`:
    * `created_ascending`
    * `created_descending` (default)
    * `name_ascending`
    * `name_descending`

```json
{
  "rules": [
    "<MATCHING INDICATOR OBJECTS>"
  ]
}
```

##### GET Rule by ID

Also returns all relationship objects and enriched objects (e.g. cve/attack) over rules search endpoint

```shell
GET <HOST>/api/v1/rules/indicator--ID
```

* `show_attack` (default is true), can be set to false to remove all relationship/objects related to attack
* `show_cve` (default is true), can be set to false to remove all relationship/objects related to cve

```json
{
  "rules": [
    "<INDICATOR OBJECT>"
  ]
}
```

##### GET Rule versions

```shell
GET <HOST>/api/v1/rules/indicator--ID/versions
```

```json
{
  "latest": "string",
  "versions": [
    "string"
  ]
}
```

##### GET Raw Rule by ID

```shell
GET <HOST>/api/v1/rules/indicator--ID/raw
```

Prints the raw text of the rule (what is in the Indicator `pattern` property -- in text format, without JSON escapes)

#### Import existing Sigma rules

##### Import external data

```shell
GET <HOST>/api/v1/import/<MODE>
```

* only mode in v1 is `sigma2stix`

body contains

```json
{
  "version": "string",
  "ignore_embedded_relationships": "boolean"
}
```

Response contains a job.

#### Objects (dogesec commons)

##### `/api/v1/object/{object_id}/`

##### `/api/v1/object/{object_id}/indicators`

##### `/api/v1/objects/scos/`

##### `/api/v1/objects/sdos/`

##### `/api/v1/objects/smos/`

##### `/api/v1/objects/sros/`

#### Jobs

Jobs track the upload and processing of a file into STIX objects

##### GET jobs

```shell
GET HOST/api/VERSION/jobs/
```

Accepts URL parameters:

* `file_id`
* `rule_id`
* `mode`
* `page_size` (max is 50, default is 50)
* `page`
    * default is 0
* `sort`:
    * run_datetime_ascending
    * run_datetime_descending (default)
    * state_ascending
    * state_descending

```json
{
    "jobs": [
        {
            "id": "<value>",
            "report_id": "<value>",
            "mode": "<value>",
            "defang": "<boolean>",
            "extract_text_from_image": "<boolean>",
            "name": "<value>",
            "tlp_level": "<value>",
            "labels": ["<value1","value2"],
            "identity": "{<identity.json>}",
            "detection_language_id": "<ID>",
            "product_ids": [
              "<IDS>"
            ],
            "state": "<STATE>",
            "run_datetime": "<START TIME>",
            "info": "string"
        },
        {
            "id": "<value>",
            "report_id": "<value>",
            "mode": "<value>",
            "defang": "<boolean>",
            "extract_text_from_image": "<boolean>",
            "name": "<value>",
            "tlp_level": "<value>",
            "labels": ["<value1","value2"],
            "identity": "{<identity.json>}",
            "detection_language_id": "<ID>",
            "product_ids": [
              "<IDS>"
            ],
            "state": "<STATE>",
            "run_datetime": "<START TIME>",
            "info": "string"
        }
    ]
}
```

##### GET job by ID

```shell
GET HOST/api/VERSION/jobs/{id}/
```

```json
{
    "jobs": [
        {
            "id": "<value>",
            "report_id": "<value>",
            "mode": "<value>",
            "defang": "<boolean>",
            "extract_text_from_image": "<boolean>",
            "name": "<value>",
            "tlp_level": "<value>",
            "labels": ["<value1","value2"],
            "identity": "{<identity.json>}",
            "detection_language_id": "<ID>",
            "product_ids": [
              "<IDS>"
            ],
            "state": "<STATE>",
            "run_datetime": "<START TIME>",
            "info": "string"
        }
    ]
}
```

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).