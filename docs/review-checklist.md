# Review Checklist

- Is the change clearly a `provider`, `asn`, `cidr`, or `incident` update?
- Does the record include a valid status?
- Does the summary avoid calling a provider malicious without evidence?
- Is there at least one evidence item or reference?
- Is there a source URL when one is available?
- Is a single IOC being incorrectly generalized into a CIDR?
- If a `/24` or broader CIDR is added, is there independent support beyond one IOC?
- Is the record going into the right output set?
- `provider inventory` for context
- `incident IOC` for exact detection
- `high-risk CIDR` for generalized detection
- Do the generated files change in a way that matches the source edit?
