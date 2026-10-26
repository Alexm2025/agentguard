# CLI

```text
agentguard --version
agentguard scan [FILE]                         score text (stdin) with the detectors; exit 1 if flagged

agentguard policy validate FILE...             validate policy files
agentguard policy schema                       print the JSON Schema
agentguard policy init                         print the default policy

agentguard gateway mcp-stdio [--policy P] [--name N] [--pins-file F] [--events-file F] -- CMD...
agentguard gateway mcp-http  [--config C] [--host H] [--port 8100] [--ssl-certfile/--ssl-keyfile]
agentguard gateway llm       [--config C] [--host H] [--port 8200] [--workers N]
agentguard key hash KEY|-                      SHA-256 of a key for static gateway auth

agentguard server run [--migrate] [--host H] [--port 8000] [--ssl-certfile/--ssl-keyfile]
agentguard server migrate [--database-url URL] [--revision head]
agentguard server create-admin EMAIL [--org-slug default]
agentguard server prune [--days N]             delete events past retention
agentguard server verify-audit ORG_ID          exit 1 if the hash chain is broken
agentguard server seed-demo [--org-slug default]   demo sessions for an empty organization
```
