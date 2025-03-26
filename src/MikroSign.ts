import * as crypto from 'node:crypto';

/**
 * @description MikroSign is a lightweight HMAC request signing library.
 */
export class MikroSign {
  private readonly secret: string;
  private readonly algorithm: string;
  private readonly maxTimestampAgeMs: number;

  /**
   * @description Initialize a new MikroSign instance.
   *
   * @param secret The shared secret key used for signing.
   * @param options Configuration options.
   */
  constructor(
    secret: string,
    options: {
      algorithm?: string;
      maxTimestampAgeMs?: number;
    } = {}
  ) {
    if (!secret || secret.trim() === '') {
      throw new Error('Secret key cannot be empty');
    }
    this.secret = secret;
    this.algorithm = options.algorithm || 'sha256';
    this.maxTimestampAgeMs = options.maxTimestampAgeMs || 5 * 60 * 1000; // Default: 5 minutes
  }

  /**
   * @description Creates a signed request.
   *
   * @param method HTTP method (GET, POST, etc.).
   * @param path API endpoint path.
   * @param body Request body (will be JSON stringified if not a string).
   * @returns Signature data to be sent with the request.
   */
  public sign(
    method: string,
    path: string,
    body: any
  ): {
    timestamp: number;
    signature: string;
  } {
    const timestamp = Date.now();

    const normalizedMethod = typeof method === 'string' ? method : 'GET';
    const normalizedPath = typeof path === 'string' ? path : '/';

    let stringToSign: string;
    try {
      stringToSign = this.generateStringToSign(normalizedMethod, normalizedPath, body, timestamp);
    } catch (err) {
      // If JSON.stringify fails due to circular reference, try with a simplified version
      if (err instanceof TypeError && err.message.includes('circular')) {
        // Create a non-circular copy by manually copying properties
        const simplifiedBody =
          typeof body === 'object' && body !== null
            ? Object.keys(body).reduce((acc: Record<string, any>, key) => {
                if (key !== 'self' && key !== 'circular') {
                  // Skip known circular props
                  acc[key] = body[key];
                }
                return acc;
              }, {})
            : body;

        stringToSign = this.generateStringToSign(
          normalizedMethod,
          normalizedPath,
          simplifiedBody,
          timestamp
        );
      } else {
        throw err;
      }
    }

    const signature = crypto
      .createHmac(this.algorithm, this.secret)
      .update(stringToSign)
      .digest('hex');

    return {
      timestamp,
      signature
    };
  }

  /**
   * @description Verifies the signature of an incoming request.
   *
   * @param method HTTP method from the request.
   * @param path API path from the request.
   * @param body Parsed request body.
   * @param timestamp Timestamp from request headers.
   * @param signature Signature from request headers.
   */
  public verify(
    method: string,
    path: string,
    body: any,
    timestamp: number,
    signature: string
  ): boolean {
    if (Number.isNaN(timestamp) || typeof timestamp !== 'number') return false;

    const now = Date.now();

    const CLOCK_DRIFT_ALLOWANCE = 30 * 1000; // 30 seconds
    if (timestamp > now + CLOCK_DRIFT_ALLOWANCE) return false;

    if (now - timestamp > this.maxTimestampAgeMs) return false;

    if (!signature || typeof signature !== 'string') return false;

    if (!signature || !/^[0-9a-f]+$/i.test(signature)) return false;

    const stringToSign = this.generateStringToSign(method, path, body, timestamp);

    const expectedSignature = crypto
      .createHmac(this.algorithm, this.secret)
      .update(stringToSign)
      .digest('hex');

    try {
      return crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expectedSignature, 'hex')
      );
    } catch (_error) {
      return false;
    }
  }

  /**
   * @description Generates the canonical string to be signed.
   * Format: `METHOD;PATH;TIMESTAMP;BODY_HASH`
   */
  private generateStringToSign(
    method: string,
    path: string,
    body: unknown,
    timestamp: number
  ): string {
    let bodyString = '';

    if (body !== undefined && body !== null) {
      if (typeof body === 'string') {
        bodyString = body;
      } else if (typeof body === 'object') {
        try {
          const sortedObj = this.sortObjectKeys(body);
          bodyString = JSON.stringify(sortedObj);
        } catch (_error) {
          bodyString = JSON.stringify(body);
        }
      } else {
        bodyString = String(body);
      }
    }

    const normalizedPath =
      typeof path === 'string' ? (path.startsWith('/') ? path : `/${path}`) : '/';

    return [
      (typeof method === 'string' ? method : 'GET').toUpperCase(),
      normalizedPath,
      timestamp.toString(),
      crypto.createHash('sha256').update(bodyString).digest('hex')
    ].join(';');
  }

  /**
   * @description Recursively sort object keys for consistent serialization.
   */
  private sortObjectKeys(obj: Record<string, any>): any {
    if (typeof obj !== 'object' || obj === null) return obj;

    if (Array.isArray(obj)) return obj.map((item) => this.sortObjectKeys(item));

    return Object.keys(obj)
      .sort()
      .reduce((result: any, key) => {
        result[key] = this.sortObjectKeys(obj[key]);
        return result;
      }, {});
  }
}
