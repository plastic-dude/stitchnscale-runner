// Decrypts the AES-256-GCM job payload (base64 of iv[12] | ciphertext | tag[16]) into /tmp/job.json. Prints nothing secret.
import crypto from 'node:crypto'; import fs from 'node:fs';
const key = Buffer.from(process.env.RUNNER_KEY, 'hex');
const buf = Buffer.from(process.env.PAYLOAD, 'base64');
const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
d.setAuthTag(buf.subarray(buf.length - 16));
const job = JSON.parse(Buffer.concat([d.update(buf.subarray(12, buf.length - 16)), d.final()]).toString());
if (job.gh) console.log(`::add-mask::${job.gh}`);
// Named user secrets for this job only (e.g. GITHUB_PAT). Masked in logs; exported to the script, never to the repo.
const extra = Object.entries(job.env ?? {}).filter(([k]) => /^[A-Z][A-Z0-9_]{1,40}$/.test(k));
for (const [, v] of extra) console.log(`::add-mask::${v}`);
fs.writeFileSync('/tmp/job.json', JSON.stringify(job), { mode: 0o600 });
const sh = (v) => `'${String(v ?? '').replace(/'/g, `'\\''`)}'`;
fs.writeFileSync('/tmp/job.env', [`export GH=${sh(job.gh)}`, `export REPO=${sh(job.repo)}`, `export JOB_ID=${sh(job.job_id)}`, `export CALLBACK_URL=${sh(job.cb)}`, `export STEPS=${sh(JSON.stringify(job.steps ?? []))}`, ...extra.map(([k, v]) => `export ${k}=${sh(v)}`)].join('\n'), { mode: 0o600 });
if (job.script) fs.writeFileSync('/tmp/job.sh', job.script, { mode: 0o600 });
