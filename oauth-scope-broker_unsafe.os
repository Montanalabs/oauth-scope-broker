#! VULNERABLE oauth-scope-broker — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant issueScope

let raw = fetch<web>
using issueScope { privileged { issueScope(raw) } }  # tainted -> tool: REJECTED
