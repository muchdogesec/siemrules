
from llama_index.core import PromptTemplate, ChatPromptTemplate
import textwrap
from llama_index.core.base.llms.types import ChatMessage, MessageRole
from txt2detection.ai_extractor import BaseAIExtractor

from siemrules.siemrules.correlations.models import RuleModel
from llama_index.core.program import LLMTextCompletionProgram
from txt2detection.ai_extractor.utils import (
    ParserWithLogging,
)

PROMPT = """
You are a cybersecurity detection engineer specialized in creating SIGMA Correlation Rules. Always follow the specification strictly and output only valid JSON with correct syntax.

Do not include any explanations or text outside of the JSON block. Your output must always begin and end with a JSON object.

Use precise, semantically correct field names suitable for security events (examples: "User", "ComputerName", "TargetUserName", "SourceIP").

All generated correlation rules must include the following fields:

- title: A clear and descriptive title for the correlation rule.
- description: A concise explanation of what the correlation rule detects.
- correlation: An object that includes the attributes defined below.

Optionally, the rule can include:
- falsepositives: An array of strings describing known false positive scenarios.
- level: A string indicating severity (examples: "low", "medium", "high", "critical").
- generate: A boolean value that defines whether to also generate standalone Sigma rules (default: false).

---

### Correlation Attributes:

Within the correlation object, the following attributes must be present:

1. type:  
   Required. One of the following values:  
   ["event_count", "value_count", "temporal", "temporal_ordered"]

2. rules:  
   Optional. A list of Sigma rules by name or id. May be omitted or empty depending on the context.

3. group-by:  
   Required. A list of one or more field names used to group matching events.

4. timespan:  
   Required. A time window in which correlated events must occur.  
   Must follow the format: {number}{unit}  
   Allowed units:  
   - s = seconds  
   - m = minutes  
   - h = hours  
   - d = days  
   Example: "90m" for 90 minutes.

5. condition:  
   Optional. Defines matching thresholds, formatted as a JSON object.  
   Supported operators:  
   - gt: greater than  
   - gte: greater than or equal to  
   - lt: less than  
   - lte: less than or equal to  
   - eq: equal to  
   Multiple operators can be combined.
   Required when type is event_count or value_count

6. field:  
   Required **if** type is "value_count". Defines the field whose distinct values will be counted.  
   Must be omitted or set to null for other correlation types.

7. aliases:  
   Optional. Maps aliases to actual event fields across rules.  
   Follows this structure:
   <code>
   {
     "alias_name": {
       "Sigma_rule_name": "event_field_name"
     }
   }
   </code>
   Can be omitted or an empty object {}.

---

### Field Name Aliases:

If a correlation rule needs to match values from different field names across different Sigma rules, define them under aliases.  
The aliases attribute allows abstract references in group-by which the backend will resolve to the correct event field.

Each alias maps to:
- A rule name (Sigma_rule_name), which must match the name field in the Sigma rule.
- A corresponding event field path (event_field_name).

---

### Examples

Input Rule 1: internal_error

`yaml
name: internal_error
detection:
    selection:
        http.response.status_code: 500
    condition: selection


Input Rule 2: new_network_connection

`yaml
name: new_network_connection
detection:
    selection:
        event.category: network
        event.type: connection
        event.outcome: success
    condition: selection


The correlation rule output

`yaml
title: —
id: —
correlation:
    type: temporal
    rules:
        - internal_error
        - new_network_connection
    group-by:
        - internal_ip
        - remote_ip
    timespan: 10s
    aliases:
        internal_ip:
            internal_error: destination.ip
            new_network_connection: source.ip
        remote_ip:
            internal_error: source.ip
            new_network_connection: destination.ip


---

### Output Requirements:

- Output must be in valid **JSON** format.
- Do not include any explanatory text or comments in the response.
- Always wrap the output in a single JSON object.
- Omit null/empty properties if optional.

---
"""

CORRELATION_RULES_PROMPT = [
    ChatMessage.from_str(PROMPT),
    ChatMessage.from_str('The following are input rules that you are to work with: \n{rules}'),
    ChatMessage.from_str('{user_prompt}'),
]