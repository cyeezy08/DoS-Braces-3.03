# Security Advisory: Denial of Service in braces via Comma-Separated Brace Expansion

## Summary

The `braces` npm package (versions < 3.0.3, and the 3.0.3 fix is incomplete) is vulnerable to denial of service through uncontrolled resource consumption when processing comma-separated brace expansion patterns.

The existing fix for CVE-2024-4068 only limited the maximum input length to 10,000 characters but did not address the combinatorial explosion of output when processing comma-separated brace patterns like `{a,b}`.

## Affected Versions

- All versions of `braces` prior to the as-yet-unreleased fix
- braces@3.0.3 (latest at time of reporting) - **incomplete fix for CVE-2024-4068**

## Impact

A malicious input as short as **110 characters** can cause:
- **4,194,304 array items** to be materialized in memory
- **~1.2 GB** memory allocation
- **18+ seconds** of CPU blocking
- Complete denial of service in any application that processes untrusted input through `braces.expand()`

Since `braces` is a dependency of `micromatch`, which is used by widely-deployed tools including webpack, vitest, jest, eslint, and many others, the potential impact is significant.

## Technical Details

### Root Cause

In `lib/expand.js`, the `rangeLimit` check (line 60) only applies when `node.ranges > 0`:

```javascript
if (node.ranges > 0) {
  const args = utils.reduce(node.nodes);
  if (utils.exceedsLimit(...args, options.step, rangeLimit)) {
    throw new RangeError('expanded array length exceeds range limit...');
  }
  // ...
}
```

Comma-separated expansions (e.g., `{a,b}{c,d}`) produce AST nodes where `ranges === 0`, so the limit is never checked. The `append()` function recursively materializes all 2^N combinations into an array.

### Proof of Concept

```javascript
const braces = require('braces');
const start = Date.now();
const input = '{a,b}'.repeat(22); // 110 characters
const result = braces.expand(input);
console.log(`${result.length} items in ${Date.now() - start}ms`);
// Output: 4194304 items in 18042ms
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

## Recommended Fix

Add a limit check at each concatenation step in `lib/expand.js` to prevent combinatorial explosion. This can be achieved by wrapping calls to `append` inside the `expand` function with a validation helper:

```javascript
const queueLimit = (queue, stash, enclose) => {
  if (rangeLimit === Infinity) return append(queue, stash, enclose);
  const queueLength = queue ? [].concat(queue).length : 0;
  const stashLength = [].concat(stash).length;
  const nextLength = queueLength === 0 ? stashLength : (stashLength === 0 ? queueLength : queueLength * stashLength);
  if (nextLength > rangeLimit) {
    throw new RangeError('expanded array length exceeds range limit. Use options.rangeLimit to increase or disable the limit.');
  }
  return append(queue, stash, enclose);
};
```

Replacing calls to `append()` inside `walk()` with `queueLimit()` ensures that combinations of consecutive braces and ranges are safely bounded.

## Disclosure Timeline

- 2026-07-17: Vulnerability discovered and reported
- 90-day coordinated disclosure window

## Credit

Discovered during security research using the find-cve-agent methodology.
