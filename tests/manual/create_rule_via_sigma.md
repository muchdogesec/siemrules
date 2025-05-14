## Test 1

upload /files/sigma_rule.yaml with all settings configured, check creation behaviour is correct.

curl -X 'POST' \
  'http://localhost:8008/api/v1/files/sigma/' \
  -H 'accept: application/json' \
  -H 'Content-Type: multipart/form-data' \
  -H 'X-CSRFTOKEN: N7q1K25452ZnLiw6AWryQwmEnSwZZ4OECAsekeuOuCgKo6lb6cruipNSJR4oMxji' \
  -F 'license=0BSD' \
  -F 'ignore_embedded_relationships_sro=true' \
  -F 'level=critical' \
  -F 'report_id=report--807b7275-a680-4ad7-a9d1-7aa924acab73' \
  -F 'references=https://www.google.com/,https://www.facebook.com/' \
  -F 'created=2020-01-01T00:00:00' \
  -F 'ignore_embedded_relationships_smo=true' \
  -F 'name=testing all settings' \
  -F 'status=deprecated' \
  -F 'ignore_embedded_relationships=false' \
  -F 'sigma_file=@sigma_rule.yaml;type=application/x-yaml' \
  -F 'tlp_level=green' \
  -F 'identity={"type":"identity","spec_version":"2.1","id":"identity--068335dc-7ad6-4ed6-a053-cb3f76a1ad1a","name":"Using a custom Identity"}' \
  -F 'labels=label.1,label.2'