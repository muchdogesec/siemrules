# Tests

## Setup

```shell
python3 -m venv siemrules-venv
source siemrules-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
````

## API schema tests

```shell
st run --checks all http://127.0.0.1:8008/api/schema --generation-allow-x00 true
```