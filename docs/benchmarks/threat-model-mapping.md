# Mapping published MCP attack benchmarks to ProvMCP's threat model

ProvMCP detects one thing: a tool call to server B whose arguments carry
content that an earlier response from server A put into the model's context.
This note checks which attacks in the two benchmarks named in the proposal
fall inside that threat model. The classification is our own analysis of each
paper's attack descriptions. The papers do not make these claims.

## Threat model in one line

In scope: **cross-server data flow into a tool call.** Out of scope: the
choice of which tool to call, transport security, host or client bugs, and
attacks with a single server where source and target are the same.

## MCPSecBench (Yang et al., arXiv:2508.13220, MIT license)

MCPSecBench defines 17 attacks over four surfaces (client, protocol, server,
host). Its repository is public under the MIT license
(github.com/AIS2Lab/MCPSecBench). The attacks are implemented as Python MCP
servers plus a driver script, not as a declarative dataset, so there is
nothing to import directly. We recreate the in-scope cases as ProvMCP
scenarios (`benchmarks/msb/`) from the paper's descriptions.

| ID | Attack | Surface | ProvMCP scope | Reason |
|---|---|---|---|---|
| ATT-1 | Prompt injection (direct) | client | out | The user is the attacker; there is no second server. |
| ATT-2 | Tool misuse via "confused AI" | client | out | One server misdescribes its own tool. No cross-server flow. |
| ATT-3 | Schema inconsistencies | client | out | Host and client parsing bug. |
| ATT-4 | Slash command overlap | client | out | Host UI behaviour. |
| ATT-5 | MCP rebinding | protocol | out | Transport and origin security; DNS rebinding. |
| ATT-6 | Man-in-the-middle | protocol | out | Needs TLS and authentication, not provenance. |
| ATT-7 | Tool shadowing | server | partial | The injection arrives in a tool *description*. ProvMCP records tool results, not `tools/list`, so it misses it today. Scenario `msb-att07`, expected miss. |
| ATT-8 | Data exfiltration via a tool parameter | server | partial | Other servers' tool metadata flows into a malicious tool's argument. That is a cross-server flow, but the source is `tools/list`, which is not recorded. Scenario `msb-att08`, expected miss. |
| ATT-9 | Name squatting (tool) | server | out* | Tool selection. *Any data the squatting tool receives from other servers is a flow ProvMCP sees. |
| ATT-10 | Indirect prompt injection | server | **in** | Instructions in one server's output drive a call to another. Scenario `msb-att10`. |
| ATT-11 | Name squatting (server) | server | out* | Same as ATT-9. |
| ATT-12 | Tool poisoning | server | out* | Same as ATT-9. |
| ATT-13 | Rug pull | server | **in** (flow part) | A server that turns malicious and pulls data from other servers into its own calls is a cross-server flow. Scenario `msb-att13`. |
| ATT-14 | Vulnerable client | host | out | Host software bug. |
| ATT-15 | Configuration drift | host | out | Host configuration. |
| ATT-16 | Sandbox escape | host | out | Host isolation. |
| ATT-17 | Vulnerable server | host | out | Server bug (path traversal) inside one server. |

Result: 2 of 17 attacks are fully in scope, 2 are in scope only if tool
metadata is tracked, and 3 are out of scope for detection but in scope for
their consequences. This is expected. MCPSecBench covers the whole MCP attack
surface, and ProvMCP targets one class of it. The finding motivates
recording `tools/list` results as a provenance source, which will be measured
for false positives in Week 9 before it is turned on.

Published baselines used for comparison (ASR with no defense, 15 trials each):

| Attack | Claude Desktop | GPT-4.1 | Cursor |
|---|---|---|---|
| ATT-7 tool shadowing | 20% | 53.3% | 6.7% |
| ATT-8 data exfiltration | 100% | 100% | 100% |
| ATT-10 indirect prompt injection | 33.3% | 0% | 26.7% |
| ATT-13 rug pull | 93.3% | 73.3% | 93.3% |

## ProtoAmp (Maloyan and Namiot, arXiv:2601.17549)

ProtoAmp adapts existing agent-security benchmarks to MCP infrastructure:
312 cases from InjecAgent, 398 from AgentDojo, and 137 new protocol-specific
attacks, 847 in total. It reports cross-server propagation ASR of 61.3% under
MCP against 19.7% for an equivalent non-MCP integration, and an ASR that rises
with the number of connected servers (47.8% with 1 server, 78.3% with 5).

| ProtoAmp attack class | ProvMCP scope | Reason |
|---|---|---|
| Cross-server propagation (server A's response causes a call on server B) | **in** | This is the confused-deputy pattern ProvMCP is built for. |
| Exfiltration of server B's data through server A | **in** | A B → A flow into a tool call. |
| Tool response manipulation | in when it crosses servers | Same as above when the manipulated response drives a call to a different server. |
| Indirect injection through resources | partial | `resources/read` results are recorded, but only `tools/call` is inspected. |
| Sampling-based injection | out | The server asks the client for a completion. Origin authentication is needed, not data-flow tracking. |
| Capability over-claim | out | The server claims permissions; needs attestation. |

**Availability.** The ProtoAmp paper links no code, data or license for
ProtoAmp. It cannot be integrated directly. We follow its *method* instead.
InjecAgent (Zhan et al., ACL Findings 2024, MIT license,
github.com/uiuc-kang-lab/InjecAgent) is public, so `provmcp.importers.injecagent`
converts its test cases into multi-server scenarios: the user tool, the
data-extraction tool and the sending tool are each placed on their own MCP
server. AgentDojo adaptation is left for later.

### Correction to the proposal

Section 7.3 of the proposal says the PROTOAMP benchmark "is open under MIT
license". That is wrong: the paper releases no artifact. The paper also
spells the name ProtoAmp. The final report should say that ProtoAmp's method
was reproduced on InjecAgent, and that ProtoAmp's numbers are quoted from the
paper, not re-run.

## How our numbers will compare

None of the published baselines can be re-run exactly. The models differ
(claude-opus-4.5 and GPT-4.1 in MCPSecBench; Claude-3.5-Sonnet, GPT-4o and
Llama-3.1-70B in ProtoAmp), and neither paper releases per-case traces.
Week 8 therefore measures baselines on our own harness, using the same oracle
for every condition, and quotes the published figures as reference points
only.

## Sources

- Y. Yang et al. MCPSecBench. arXiv:2508.13220 (v3). Attack taxonomy (Table 1), per-platform ASR tables, attack appendix.
- N. Maloyan, D. Namiot. Breaking the Protocol. arXiv:2601.17549. Section III-C, Tables II, IV, VI.
- Q. Zhan et al. InjecAgent. Findings of ACL 2024. arXiv:2403.02691.
