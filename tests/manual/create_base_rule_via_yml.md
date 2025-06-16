## Test 1

## Identity is string

```yml
title: Okta Policy Modified or Deleted
id: 1667a172-ed4c-463c-9969-efd92195319a
status: test
description: Detects when an Okta policy is modified or deleted.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: Austin Songer @austinsonger
date: 2021-09-12
modified: 2022-10-09
tags:
    - tlp.red
    - attack.t1547
    - attack.command_and_control
    - cve.2024-56520
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventtype:
            - policy.lifecycle.update
            - policy.lifecycle.delete
            - observable@extraction.com
    condition: selection
falsepositives:
    - Okta Policies being modified or deleted may be performed by a system administrator.
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Okta Policies modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: low
license: MIT
```

Check the new sigma rule YML has related property

```
related:
-   id: 1667a172-ed4c-463c-9969-efd92195319a
    type: renamed
```

Check the bundle endpoint to ensure attack tactic, technique, and CVE object exist

## Identity is STIX object

```yml
title: Okta Policy Modified or Deleted
id: 1667a172-ed4c-463c-9969-efd92195319a
status: test
description: Detects when an Okta policy is modified or deleted.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: '{"type":"identity","spec_version":"2.1","id":"identity--068335dc-7ad6-4ed6-a053-cb3f76a1ad1a","name":"Using a custom Identity"}'
date: 2021-09-12
modified: 2022-10-09
tags:
    - tlp.red
    - attack.t1547
    - attack.command_and_control
    - cve.2024-56520
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventtype:
            - policy.lifecycle.update
            - policy.lifecycle.delete
            - observable@extraction.com
    condition: selection
falsepositives:
    - Okta Policies being modified or deleted may be performed by a system administrator.
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Okta Policies modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: low
license: MIT
```

## Identity is STIX ID that exists

```yml
title: Okta Policy Modified or Deleted
id: 1667a172-ed4c-463c-9969-efd92195319a
status: test
description: Detects when an Okta policy is modified or deleted.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: identity--068335dc-7ad6-4ed6-a053-cb3f76a1ad1a
date: 2021-09-12
modified: 2022-10-09
tags:
    - tlp.red
    - attack.t1547
    - attack.command_and_control
    - cve.2024-56520
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventtype:
            - policy.lifecycle.update
            - policy.lifecycle.delete
            - observable@extraction.com
    condition: selection
falsepositives:
    - Okta Policies being modified or deleted may be performed by a system administrator.
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Okta Policies modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: low
license: MIT
```



# Bad tests

## missing title 

```yml
title: Okta Policy Modified or Deleted
id: 1667a172-ed4c-463c-9969-efd92195319a
status: test
description: Detects when an Okta policy is modified or deleted.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: Austin Songer @austinsonger
tags:
    - tlp.red
    - attack.t1547
    - attack.command_and_control
    - cve.2024-56520
license: MIT
```