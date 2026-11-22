# OWASP benchmarks: what the tool maps to, and how that is kept current

Every check (rule) in this tool names the OWASP categories it is closest to. The editions it knows are listed in
`src/scopedagent/benchmarks/catalogue.yaml`, which is **data, not code**: updating a benchmark is a reviewed edit of that file.

## What is mapped today (read on 2026-11-22)

| Benchmark | Edition | Source |
|---|---|---|
| OWASP Top 10 | 2025 | <https://owasp.org/Top10/2025/> |
| OWASP API Security Top 10 | 2023 | <https://owasp.org/API-Security/editions/2023/en/0x11-t10/> |
| OWASP Top 10 for LLM Applications | 2026 | <https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/> |

Two of these changed recently, which is why the list is data and why it is dated. The web Top 10 moved from 2021 to 2025 (Security
Misconfiguration is now A02, Injection is A05, and SSRF is folded into A01). The LLM list moved from 2025 to 2026, and *System Prompt
Leakage* became *Hidden Context Exposure* (LLM08), a broader category; the web summaries of the new edition did not list its ten risks,
so they were read from the edition's own PDF.

## What a mapping means, and does not

* A mapping is the **closest category, never a verdict.** A draft is not a finding, and a category is not a diagnosis. Where the fit is
  loose (a `robots.txt` listing, an external redirect) the entry's note says so.
* `scoped-agent benchmarks status` shows, for each edition, every category and the rules that answer it, and says **"no rule yet"** where
  none does. Most categories have none: Injection, Broken Access Control, Authentication Failures, and most of the API and LLM lists are gaps
  today. A category with a rule is not thereby well tested either.
* `scoped-agent benchmarks rules` shows each rule's categories and the reason.
* `findings show` and both report formats print the categories beside the rule. They are **derived from the rule's id when shown**,
  never stored in a finding, so a later edition relabels nothing that was recorded. A report lists the editions and check dates it used.
* A test fails if a rule exists without a mapping, or a mapping names a rule that does not exist.

## Keeping it current (D-E87)

The benchmarks change; this tool cannot download new attack content at run time, and an unattended edit would be unsafe. So:

1. **Look for a newer edition** at the sources above (the owasp.org project pages and genai.owasp.org). `benchmarks status` warns when a
   benchmark has not been checked for 180 days.
2. **Read the actual list from the edition itself** (its page or PDF), not from a summary or from memory.
3. Edit `catalogue.yaml`: the benchmark's `edition`, `source`, categories and `checked_on`. Re-map the rules; where a category was renamed
   or merged, say so in the rule's `note`.
4. Update the tables at the top of `tests/unit/test_benchmarks_catalogue.py` (the editions and every rule's mapping): the data is reviewed
   twice, once as data and once as the test that pins it.
5. Run `benchmarks status` and `benchmarks rules`, open a pull request, and review it.
6. If nothing changed, still bump `checked_on` once you have confirmed it.

A scheduled routine that looks for new OWASP releases and opens a pull request for review is part of the last stage of the plan
(`docs/active-testing-roadmap.md`); it proposes, a person decides.
