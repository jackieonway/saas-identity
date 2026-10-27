// Explicit disposable RSA fixture; no private key is committed or printed.
import { generateKeyPairSync } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
const destination = process.argv[2];
if (!destination || !path.isAbsolute(destination)) throw new Error('An absolute, task-owned fixture path is required');
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicKey = pair.publicKey.export({ format: 'jwk' });
const privateKeyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
await writeFile(destination, JSON.stringify({ keys: [{ kid: 'context-test', privateKeyPem, n: publicKey.n, e: publicKey.e }] }), { flag: 'wx', mode: 0o600 });
console.log('Disposable context signing fixture created');
