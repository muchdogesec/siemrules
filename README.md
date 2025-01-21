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

## Install

### Download and configure

```shell
# clone the latest code
git clone https://github.com/muchdogesec/siemrules
```

### Configuration options

SIEM Rules has various settings that are defined in an `.env` file.

To create a template for the file:

```shell
cp .env.example .env
```

To see more information about how to set the variables, and what they do, read the `.env.markdown` file.

### Build the Docker Image

```shell
sudo docker compose build
```

### Start the server

```shell
sudo docker compose up
```

### Access the server

The webserver (Django) should now be running on: http://127.0.0.1:8008/

You can access the Swagger UI for the API in a browser at: http://127.0.0.1:8008/api/schema/swagger-ui/

## Contributing notes

SIEM Rules is made up of different core external components that support most of its functionality.

Generally if you want to improve how SIEM Rules performs functionality, you should address the changes in;

* [file2txt](https://github.com/muchdogesec/file2txt/): converts the file into a markdown file (which is used to extract data from)
* [txt2detection](https://github.com/muchdogesec/txt2detection): turns the markdown file into detection rules / STIX objects
* [stix2arango](https://github.com/muchdogesec/stix2arango): manages the logic to insert the STIX objects into the database

For anything else, then the Obstracts codebase is where you need to be :)

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).