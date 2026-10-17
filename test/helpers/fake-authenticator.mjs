// 테스트 전용 가짜 WebAuthn 인증기. 서버의 SimpleWebAuthn 검증을 실제 암호 연산으로 통과시키기 위해
// ES256 키쌍으로 서명하고 attestation "none" 객체를 직접 만든다. 실제 기기·브라우저가 아니다.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';

const b64u = buffer => Buffer.from(buffer).toString('base64url');
const sha256 = data => createHash('sha256').update(data).digest();

function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
}

// 이 테스트에 필요한 만큼만 구현한 CBOR 인코더(정수, 문자열, 바이트, Map).
export function cbor(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return Buffer.concat([head(2, value.length), Buffer.from(value)]);
  }
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (value instanceof Map) {
    return Buffer.concat([
      head(5, value.size),
      ...[...value].flatMap(([key, item]) => [cbor(key), cbor(item)]),
    ]);
  }
  throw new TypeError('unsupported cbor value');
}

export class FakeAuthenticator {
  constructor({ rpID, origin }) {
    this.rpID = rpID;
    this.origin = origin;
    this.credentialId = randomBytes(32);
    this.counter = 0;
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = privateKey;
    this.jwk = publicKey.export({ format: 'jwk' });
  }

  get id() {
    return b64u(this.credentialId);
  }

  clientData(type, challenge) {
    return Buffer.from(JSON.stringify({
      type, challenge, origin: this.origin, crossOrigin: false,
    }));
  }

  createResponse(challenge, { userVerified = true } = {}) {
    const cose = cbor(new Map([
      [1, 2], [3, -7], [-1, 1],
      [-2, Buffer.from(this.jwk.x, 'base64url')],
      [-3, Buffer.from(this.jwk.y, 'base64url')],
    ]));
    const length = Buffer.alloc(2);
    length.writeUInt16BE(this.credentialId.length);
    const flags = 0x01 | 0x40 | (userVerified ? 0x04 : 0);
    const counter = Buffer.alloc(4);
    const authData = Buffer.concat([
      sha256(this.rpID), Buffer.from([flags]), counter,
      Buffer.alloc(16), length, this.credentialId, cose,
    ]);
    const attestationObject = cbor(new Map([
      ['fmt', 'none'], ['attStmt', new Map()], ['authData', authData],
    ]));
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      response: {
        clientDataJSON: b64u(this.clientData('webauthn.create', challenge)),
        attestationObject: b64u(attestationObject),
        transports: ['internal'],
      },
      clientExtensionResults: {},
    };
  }

  // signWith를 주면 다른 키로 서명해 "잘못된 서명" 응답을 만든다.
  getResponse(challenge, { signWith = this.privateKey, userVerified = true } = {}) {
    this.counter += 1;
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);
    const authData = Buffer.concat([
      sha256(this.rpID), Buffer.from([0x01 | (userVerified ? 0x04 : 0)]), counter,
    ]);
    const clientDataJSON = this.clientData('webauthn.get', challenge);
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), signWith);
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authData),
        signature: b64u(signature),
        userHandle: null,
      },
      clientExtensionResults: {},
    };
  }
}
