# MikroSign

**Lightweight HMAC request signing with zero dependencies**.

[![npm version](https://img.shields.io/npm/v/mikrosign.svg)](https://www.npmjs.com/package/mikrosign)
[![bundle size](https://img.shields.io/bundlephobia/minzip/mikrosign)](https://bundlephobia.com/package/mikrosign)
![Build Status](https://github.com/username/mikrosign/workflows/main/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

MikroSign provides cryptographic verification for API endpoints without external dependencies. It's designed for securing critical operations like software updates, deployment pipelines, and privileged operations.

- **Secure**: Uses [HMAC](https://en.wikipedia.org/wiki/HMAC)-based signatures with timestamp validation
- **Lightweight**: Small footprint with no dependencies
- **Protection against**: Replay attacks, timing attacks, and request tampering
- **Configurable**: Adjustable timestamp validation and signature algorithms
- **TypeScript support**: Full type definitions included
- **Edge case handling**: Robust against various input formats and error conditions

## Installation

```bash
npm install mikrosign -S
```

## Usage

### Basic usage

```typescript
import { MikroSign } from 'mikrosign';

// Client side
const secret = process.env.API_SECRET;
const signer = new MikroSign(secret);

const requestBody = { version: '1.2.3', commitSha: 'abc123' };
const { timestamp, signature } = signer.sign('POST', '/api/update', requestBody);

// Add these to your request headers
const headers = {
  'Content-Type': 'application/json',
  'X-Timestamp': timestamp.toString(),
  'X-Signature': signature
};

// Server side
const verifier = new MikroSign(secret);
const isValid = verifier.verify(
  request.method,
  request.path,
  request.body,
  parseInt(request.headers['x-timestamp'], 10),
  request.headers['x-signature']
);

if (isValid) {
  // Request is authentic, proceed with operation
} else {
  // Invalid signature, reject request
}
```

### Custom configurations

```typescript
import { MikroSign } from 'mikrosign';

// Create with custom options
const verifier = new MikroSign(process.env.API_SECRET, {
  // Use a stronger hashing algorithm
  algorithm: 'sha512',

  // Set a shorter expiry time (30 seconds)
  maxTimestampAgeMs: 30 * 1000
});
```

## How It Works

MikroSign creates a canonical string by combining:

1. The HTTP method (e.g., GET, POST)
2. The request path
3. A hash of the request body
4. The current timestamp

This string is then signed using HMAC with your secret key to create a signature. The server can recreate this signature using the same information and verify that it matches.

### Security features

- **Timestamp validation**: Prevents replay attacks by rejecting expired requests
- **Constant-time comparison**: Prevents timing attacks when verifying signatures
- **Future timestamp protection**: Rejects requests with timestamps from the future
- **Signature format validation**: Guards against malformed signatures
- **Robust body handling**: Consistently processes various body types and formats
- **Error resilience**: Gracefully handles edge cases and malformed inputs

## Integration Examples

### Express.js Middleware

```typescript
import express from 'express';
import { MikroSign } from 'mikrosign';

const app = express();
app.use(express.json());

// Signature verification middleware
const verifySignature = (req, res, next) => {
  const timestamp = parseInt(req.headers['x-timestamp'], 10);
  const signature = req.headers['x-signature'];

  if (!timestamp || !signature) {
    return res.status(401).json({ error: 'Missing authentication headers' });
  }

  const verifier = new MikroSign(process.env.API_SECRET);

  if (!verifier.verify(req.method, req.path, req.body, timestamp, signature)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  next();
};

// Apply to protected routes
app.post('/api/update', verifySignature, (req, res) => {
  // Process the authenticated request
  res.json({ status: 'Update initiated' });
});

app.listen(3000);
```

### GitHub Actions Workflow

```yaml
name: Deploy Update

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'

      - name: Prepare deployment payload
        id: payload
        run: |
          echo "::set-output name=version::$(node -p "require('./package.json').version")"
          echo "::set-output name=commit::$(git rev-parse HEAD)"

      - name: Sign and deploy update
        run: |
          npm install mikrosign
          node -e "
            const { MikroSign } = require('mikrosign');
            const fetch = require('node-fetch');

            // Create payload
            const payload = {
              version: '${{ steps.payload.outputs.version }}',
              commitSha: '${{ steps.payload.outputs.commit }}',
              environment: 'production'
            };

            // Sign the request
            const signer = new MikroSign('${{ secrets.API_SECRET }}');
            const { timestamp, signature } = signer.sign('POST', '/api/update', payload);

            // Send the request to your API
            fetch('https://api.example.com/api/update', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-Timestamp': timestamp.toString(),
                'X-Signature': signature
              },
              body: JSON.stringify(payload)
            })
            .then(res => res.json())
            .then(data => console.log(data))
            .catch(err => {
              console.error(err);
              process.exit(1);
            });
          "
```

## API Reference

### MikroSign Class

#### Constructor

```typescript
constructor(
  secret: string,
  options?: {
    algorithm?: string;
    maxTimestampAgeMs?: number;
  }
)
```

Creates a new MikroSign instance with the provided secret and options.

- `secret`: Secret key used for signing (required)
- `options.algorithm`: Hash algorithm to use (default: 'sha256')
- `options.maxTimestampAgeMs`: Maximum age of timestamps in milliseconds (default: 5 minutes)

#### Methods

##### sign

```typescript
sign(
  method: string,
  path: string,
  body: any
): {
  timestamp: number;
  signature: string;
}
```

Creates a signed request for secure API endpoints.

- `method`: HTTP method (GET, POST, etc.)
- `path`: API endpoint path
- `body`: Request body (will be JSON stringified if not a string)

Returns an object with:

- `timestamp`: Current timestamp in milliseconds
- `signature`: HMAC signature for the request

##### verify

```typescript
verify(
  method: string,
  path: string,
  body: any,
  timestamp: number,
  signature: string
): boolean
```

Verifies the signature of an incoming request.

- `method`: HTTP method from the request
- `path`: API path from the request
- `body`: Parsed request body
- `timestamp`: Timestamp from request headers
- `signature`: Signature from request headers

Returns `true` if the signature is valid, `false` otherwise.

## Comparison with similar libraries

| Feature                        | MikroSign  | @smithy/signature-v4 | crypto-js |
|--------------------------------|------------|----------------------|-----------|
| Size (gzipped)                 | ~900 bytes | 4.8kb                | 2.5kb     |
| Dependencies                   | 0          | Multiple             | 0         |
| Configurability                | ✓          | ✓                    | ✓         |
| Timestamp validation           | ✓          | ✓                    | ✗         |
| Replay attack protection       | ✓          | ✓                    | ✗         |
| Timing attack protection       | ✓          | Partial              | ✗         |
| Body serialization consistency | ✓          | Partial              | ✗         |

## License

MIT. See the `LICENSE` file.
