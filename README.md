# SIEM Rules

## Before you begin...

We offer a fully hosted web version of SIEM Rules which includes many additional features over those in this codebase. [You can find out more about the web version here](https://www.siemrules.com/).

## Overview

An API that takes a file containing threat intelligence and turns it into a detection rule.

## How it works

1. User uploads files (Selects products in their stack)
2. The file is converted to txt (using [file2txt](https://github.com/muchdogesec/file2txt))
3. User inputs processed by [txt2detection](https://github.com/muchdogesec/txt2detection)
4. Objects stored in ArangoDB using [stix2arango](https://github.com/muchdogesec/stix2arango)
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

Files are uploaded. Uploaded files create Reports (if successfully processed)

##### POST Upload a file

```shell
POST HOST/api/v1/files/
```

The file should be posted as `form-data`.

The file mimetype will be validated before file is processed by the server. If mimetype does not match supported value by file2txt will result in error.

```json
{
  "name": "<USED FOR STIX REPORT>",
  "identity": "{<identity.json>}",
  "file": "<path to file>", // path to intel file
  "mode": "<value>", // file2txt setting (this is a secondary validation) // REQUIRED
  "defang": "<boolean>", // file2txt setting // OPTIONAL, DEFAULT IS TRUE
  "extract_text_from_image": "<boolean>", // file2txt setting // OPTIONAL, DEFAULT IS FALSE
  "detection_language_id": "<DETECTION LANG ID>", // from detections endpoint
  "product_ids": [
    "<VALUES>" // from product endpoint
  ]
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
      "download_url": "string",
    },
    {
      "id": "<ID>",
      "name": "<NAME>",
      "job_id": "<JOB ID>",
      "mimetype": "string",
      "size_mb": "string",
      "download_url": "string",
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
      "download_url": "string",
    }
  ]
}
```

##### DELETE a File By ID

```shell
DELETE HOST/api/VERSION/files/{id}
```

Will delete the file, and all detection rules / reports created from it.

#### Detection Rules

Files are processed into detection rules.

##### GET Rules

```shell
GET <HOST>/api/v1/rules/
```

Returns all Indicator objects that match the criteria.

Returns all Report objects that match the criteria.

* `file_id` (optional): search by Report ID generated from this file
* `report_id` (optional): search using the Indicator ID from this file
* `name` (optional): filter by name, is wildcard
* `tlp_level` (optional)
* `created_by_ref` (optional)
* `pattern_type` (optional): must be a valid detection_rule_id (use the detection rule endpoint to lookup)
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

```shell
GET <HOST>/api/v1/rules/indicator--ID
```

```json
{
  "rules": [
    "<INDICATOR OBJECT>"
  ]
}
```

##### GET Raw Rule by ID

```shell
GET <HOST>/api/v1/rules/indicator--ID/rule
```

Prints the raw text of the rule (what is in the Indicator `description` property)

#### Reports

Files are processed into detection rules.

##### GET Reports

```shell
GET <HOST>/api/v1/reports/
```

Returns all Report objects that match the criteria.

* `file_id` (optional): search by Report ID generated from this file
* `indicator_id` (optional): search using the Indicator ID from this file
* `name` (optional): filter by name, is wildcard
* `tlp_level` (optional)
* `labels` (optional)
* `created_by_ref` (optional)
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
  "objects": [
    "<REPORT OBJECTS>"
  ]
}
```

##### GET Reports by ID

```shell
GET <HOST>/api/v1/reports/report--id
```

Returns all Report objects that match the criteria.

```json
{
  "objects": [
    "<REPORT OBJECT>"
  ]
}
```

##### GET Report Images

```shell
GET <HOST>/api/v1/reports/report--id/images
```

```json
{
  "images": [
    {
      "name": "string",
      "url": "string"
    }
  ]
}
```

##### GET Report Markdown

```shell
GET <HOST>/api/v1/reports/report--id/markdown
```

Response is markdown only.

##### GET Report Bundle

```shell
GET <HOST>/api/v1/reports/report--id/bundle
```

Returns all STIX objects (Report, Indicators, Marking Definitions, Identity)

```json
{
  "objects": [
    "<ALL OBJECTS>"
  ]
}
```

#### Products

Logs are what detection rules search to identify security events. SIEM Rules includes a library of logs which can be used with the AI.

All this data returned by this endpoint is sourced from `config/logs.yaml`. User can add their own entries to this file that will be reflected via the API.

##### GET Products

```shell
GET <HOST>/api/v1/products/
```

* `id` (optional): search is wildcard
* `page_size` (max is 50, default is 50)
* `page`
    * default is 0
* `sort`:
    * `id_ascending`
    * `id_descending` (default)

```json
{
  "products": [
    {
      "id": "<NAME>",
      "logs": [
        "<VALUES>"
      ]
    },
    {
      "id": "<NAME>",
      "logs": [
        "<VALUES>"
      ]
    }
  ]
}
```

##### GET Product

```shell
GET <HOST>/api/v1/products/:PRODUCT_ID
```

```json
{
  "products": [
    {
      "id": "<NAME>",
      "logs": [
        "<VALUES>"
      ]
    }
  ]
}
```

##### GET logs

```shell
GET <HOST>/api/v1/products/:PRODUCT_NAME/logs/
```

* `id` (optional): search is wildcard
* `page_size` (max is 50, default is 50)
* `page`
    * default is 0
* `sort`:
    * `id_ascending`
    * `id_descending` (default)

```json
{
  "logs": [
    {
      "id": "<NAME>",
      "description": "<DESCRIPTION>",
      "samples": [
        "<VALUES>"
      ],
      "tags": [
        "<VALUES>"
      ],
      "created": "<CREATED>",
      "modified": "<MODIFIED>",
      "created_by": "<CREATED_BY>",
      "version": "<VERSION>"
    },
    {
      "id": "<NAME>",
      "description": "<DESCRIPTION>",
      "samples": [
        "<VALUES>"
      ],
      "tags": [
        "<VALUES>"
      ],
      "created": "<CREATED>",
      "modified": "<MODIFIED>",
      "created_by": "<CREATED_BY>",
      "version": "<VERSION>"
    }
  ]
}
```

##### Get log by id

```shell
GET <HOST>/api/v1/products/:PRODUCT_NAME/logs/:LOG_ID
```

```json
{
  "logs": [
    {
      "id": "<NAME>",
      "description": "<DESCRIPTION>",
      "samples": [
        "<VALUES>"
      ],
      "tags": [
        "<VALUES>"
      ],
      "created": "<CREATED>",
      "modified": "<MODIFIED>",
      "created_by": "<CREATED_BY>",
      "version": "<VERSION>"
    }
  ]
}
```

#### Detection languages

Detection languages define the structure of the detection rule.

SIEM Rules ships with a variety of supported detection languages (that the LLMs used understand).

All this data returned by this endpoint is sourced from `config/detection_languages.yaml`. User can add their own entries to this file that will be reflected via the API.

##### GET Detection Languages

```shell
GET <HOST>/api/v1/detection_languages/
```

* `id` (optional): search is wildcard
* `name` (optional): search is wildcard
* `page_size` (max is 50, default is 50)
* `page`
    * default is 0
* `sort`:
    * `id_ascending`
    * `id_descending` (default)

```json
{
  "detection_languages": [
    {
      "id": "<ID>",
      "name": "<NAME>",
      "description": "<DESCRIPTION>",
      "products": [
        "<PRODUCTS>"
      ],
      "created": "<CREATED>",
      "modified": "<MODIFIED>",
      "created_by": "<CREATED_BY>",
      "version": "<VERSION>"
    },
    {
      "id": "<ID>",
      "name": "<NAME>",
      "description": "<DESCRIPTION>",
      "products": [
        "<PRODUCTS>"
      ],
      "created": "<CREATED>",
      "modified": "<MODIFIED>",
      "created_by": "<CREATED_BY>",
      "version": "<VERSION>"
    }
  ]
}
```

##### GET Detection Language

```shell
GET <HOST>/api/v1/detection_languages/:DETECTION_LANG_ID
```

```json
{
  "detection_languages": [
    {
      "id": "<ID>",
      "name": "<NAME>",
      "description": "<DESCRIPTION>",
      "products": [
        "<PRODUCTS>"
      ],
      "created": "<CREATED>",
      "modified": "<MODIFIED>",
      "created_by": "<CREATED_BY>",
      "version": "<VERSION>"
    }
  ]
}
```

#### Jobs

Jobs track the upload and processing of a file into STIX objects

##### GET jobs

```shell
GET HOST/api/VERSION/jobs/
```

Accepts URL parameters:

* `file_id`
* `report_id`
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