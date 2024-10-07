# SIEM Rules

## Before you begin...

We offer a fully hosted web version of SIEM Rules which includes many additional features over those in this codebase. [You can find out more about the web version here](https://www.siemrules.com/).

## Overview

An API that takes a txt file containing threat intelligence and turns it into a detection rule.

## The problem

To illustrate the problem, lets walk through the current status quo process a human goes through when going from idea (threat TTP) to detection rule:

1. read and understand threat, maybe from a blog, report or open-source detection content
  * problem: reports on the same threat can come from multiple sources making it hard to manually collate all relevant intel
2. understand what logs or security data can be used to detect this threat, for example CloudTrail logs in this case, then understand all the field names, field values, how they are structured, how your logging pipeline structures them, etc.
  * problem: TTPs often span many logs making it hard to ensure your detection rule has full coverage
3.  convert the logic in step 1 into a detection rule (SQL/SPL/KQL, whatever) to search logs identified at step 2
  * problem: it can be hard to convert what has been read into a logical detection rule (in a detection language you may not be familiar with)
4. modify the detection rule based on new intelligence as it is discovered
  * problem: this is usually overlooked as people create and forget about rules in their detection tools

## The solution

Use the AI knowledge of threat intelligence, logs, and detection rules to create and keep them updated.

SIEM Rules allows a user to enter some threat intelligence as a file to considered be turned into a detection.

1. User uploads files (Selects products in their stack)
2. File converted to markdown by [file2txt](https://github.com/muchdogesec/file2txt)
3. Based on user inputs, AI prompts structured and sent
4. Rules converted into STIX objects
5. Rules searchable via API

Steps 2-3 are all captured in a concept of Jobs.


## AI Prompts

1. Identify the key indicators or behaviors from the threat intelligence input provided
2. Determine the relevant log sources and fields based on the types of products defined
3. Write the query using the specified detection language
4. Include appropriate filtering to reduce false positives
5. Add comments to explain the logic of the detection

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
            "id": "id",
            "datetime_run": "<TIME STARTED>",
            "file": "string",
            "mode": "<mode>",
            "mimetype": "string",
            "file_size": "string",
            "file_download_url": "string",
            "defang": "<string>",
            "state": "<state>"
        }
    ]
}
```

##### GET Files

```shell
GET HOST/api/VERSION/files/
```

Accepts URL parameters

* `report_id` (optional): search by report IDs
* `page_size` (max is 50, default is 50)
* `page`
    * default is 0
* `sort`:
    * modified_ascending
    * modified_descending (default)
    * created_ascending
    * created_descending
    * name_ascending
    * name_descending

A 200 response returns

```json
{
    "page_size": "<value>",
    "page_number": "<value>",
    "page_results_count": "<value>",
    "total_results_count": "<value>",
    "files": [
        "MATCHING FILE RECORDS"
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
        "FILE RECORD"
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

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).