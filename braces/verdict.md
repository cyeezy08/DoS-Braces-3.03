# Verdict: CONFIRMED

## Vulnerability
Uncontrolled Resource Consumption (DoS) via comma-separated brace expansion in braces@3.0.3

## Evidence
- PoC demonstrates 110 chars input → 4M items, 18s CPU, 1.2GB memory
- CVE-2024-4068 fix only limited input length (MAX_LENGTH=10000), not combinatorial output
- `rangeLimit` in expand.js only guards numeric ranges, not comma-separated patterns

## CVSS
AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H = 7.5 HIGH

## Reproduction
```
cd targets/braces/repo && npm install
python3 ../poc_braces_dos.py
```

## Recommended Channel
Security email to: github@sellside.com
