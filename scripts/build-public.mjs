import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'),);

if (config.step !== 2) {
  throw new Error('2단계 빌드는 aleph.config.json의 step=2 설정이 필요합니다.');
}

await mkdir(resolve(root, 'public'), { recursive: true });
await writeFile(
  output,
  JSON.stringify(
    {
      sampleMarker: config.sampleMarker,
      notes: [],
    },
    null,
    2,
  ) + '\n',
  'utf8',
);

console.log('정적 public/data.json에는 가상 메모를 넣지 않았습니다.');

if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(
    resolve(root, 'public', 'aleph.json'),
    JSON.stringify(identity, null, 2) + '\n',
    'utf8',
  );

  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
