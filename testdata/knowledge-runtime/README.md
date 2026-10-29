# Authored runtime examples

`cases.json` contains 12 risk/benign pairs (24 inputs): seven SQL topics,
Go process invocation, Python deserialization, shell download-to-execution,
agent instruction injection, and rendering-based exfiltration. Never execute
these inputs or run database statements from them. Endpoints and credentials
are synthetic.

`TestKnowledgeRuntimeStaticExamples` really scans each file. Its named static
positive/negative controls cover GO001, SH001, PI001 and, in native builds,
PY-AST10. It also checks that actual matched rule descriptors carry the new
topic guidance. Missing parsers retain their ordinary incomplete coverage.

`TestKnowledgeRuntimeHTTPFixtureExamples` uses real Scan and the built-in HTTP
provider with a loopback fixture server. The server deliberately returns the
case's expected topic for risk inputs and no proposal for benign inputs. It
checks system instructions/schema, evidence validation, full original guidance
in a separate proposal-assessment request, task audit IDs, report formats,
policy and preservation of static findings. This is an integration test, NOT
a classifier or model accuracy test. A benign fixture response does not override
unsupported coverage or authorize installation.

SQL has no static SQL engine in this change. SQL risk responses can now survive
the semantic protocol, but a static-only scan does not detect these SQL defects
merely because a knowledge topic exists. Live inference is not used by these tests.
