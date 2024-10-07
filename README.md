# txt2detection

A command line script that takes a txt file containing threat intelligence and turns it into a detection rule.

This project is heavily inspired by: https://github.com/dwillowtree/diana

## OSCF

The [Open Cybersecurity Schema Framework](https://github.com/ocsf) is designed to provide a standardardised way of representing key/values for logs considered by cybersecurity tools.

You can see the entire schema here:

https://schema.ocsf.io/1.3.0/classes/file_activity?extensions=

As a simple example, take this log

```txt
2024-10-03T13:05:23Z, auth_fail, user=jdoe, src_ip=192.168.1.101, service=ssh, hostname=server-1, error=invalid password, severity=low
```

Normalised to the OSCF framework this log event would be interpreted as

```json
{
  "event_type": "authentication",
  "outcome": "failure",
  "user": {
    "id": "jdoe",
    "name": "John Doe"
  },
  "source": {
    "ip": "192.168.1.101",
    "hostname": "workstation-101"
  },
  "target": {
    "service": "ssh",
    "account": "jdoe",
    "hostname": "server-1"
  },
  "time": "2024-10-03T13:05:23Z",
  "category": "identity",
  "reason": "invalid credentials",
  "severity": "low"
}

```

Ultimatley the benefit of OSCF is that if you have 100's of log types, all with different field names, OSCF normalisation provides a single structure so that searching across events becomes easy.

txt2detection uses OSCF normalised 



## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).