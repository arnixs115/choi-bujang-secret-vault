import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixtureRequests } from './fixture-7.mjs';

const RESPONSE_KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

function validResponse(request, response, ruleIds) {
  return response && typeof response === 'object' && !Array.isArray(response)
    && Object.keys(response).sort().join(',') === RESPONSE_KEYS
    && response.schema === 'aleph.decision.v1'
    && response.requestId === request.requestId
    && ['allow', 'deny', 'step_up'].includes(response.decision)
    && typeof response.reasonCode === 'string'
    && /^[a-z][a-z0-9_]{0,63}$/u.test(response.reasonCode)
    && Array.isArray(response.ruleIds) && response.ruleIds.length > 0
    && response.ruleIds.every(id => ruleIds.includes(id));
}

// Local practice only. The class engine and the server judge validate live requests separately.
export async function checkDecider({ decide, ruleIds }) {
  if (typeof decide !== 'function' || !Array.isArray(ruleIds)
      || !ruleIds.includes('device_registered')) {
    throw new Error('6단계 device_registered 규칙을 먼저 구현하고 RULE_IDS에 적어 주세요.');
  }
  const { normal, suspicious } = fixtureRequests();
  const checks = [
    { name: '등록 기기의 정상 요청', request: normal, decision: 'allow' },
    { name: '미등록 기기의 가상 요청', request: { ...normal, requestId: randomUUID(),
      deviceRegistered: false }, decision: 'deny', reasonCode: 'device_not_registered' },
  ];
  
  const makeZoneRequest = (overrides = {}) => ({
    ...normal,
    requestId: randomUUID(),
    ...overrides,
  });

  checks.push(
    {
      name: '메모 단건 읽기 허용',
      request: makeZoneRequest({
        service: 'notes',
        method: 'GET',
        path: '/notes/demo',
        route: 'GET /notes/:id',
        queryLength: 0,
      }),
      decision: 'allow',
    },
    {
      name: '메모 전체 목록 거부',
      request: makeZoneRequest({
        service: 'notes',
        method: 'GET',
        path: '/notes',
        route: 'GET /notes',
        queryLength: 0,
      }),
      decision: 'deny',
    },
    {
      name: '메모 ID 형식 제한 없음',
      request: makeZoneRequest({
        service: 'notes',
        method: 'GET',
        path: '/notes/judge-virtual-id',
        route: 'GET /notes/:id',
        queryLength: 0,
      }),
      decision: 'allow',
    },
    {
      name: '메모 경로의 하위 기능 거부',
      request: makeZoneRequest({
        service: 'notes',
        method: 'GET',
        path: '/notes/demo/export',
        route: 'GET /notes/:id/export',
        queryLength: 0,
      }),
      decision: 'deny',
    },
    {
      name: '쿼리가 있는 메모 요청 거부',
      request: makeZoneRequest({
        service: 'notes',
        method: 'GET',
        path: '/notes/demo',
        route: 'GET /notes/:id',
        queryLength: 5,
      }),
      decision: 'deny',
    },
    {
      name: '반 공지 읽기 허용',
      request: makeZoneRequest({
        service: 'announcements',
        method: 'GET',
        path: '/announcements',
        route: 'GET /announcements',
        queryLength: 0,
      }),
      decision: 'allow',
    },
    ...['POST', 'PUT', 'PATCH', 'DELETE'].map(method => ({
      name: `반 공지 ${method} 거부`,
      request: makeZoneRequest({
        service: 'announcements',
        method,
        path: '/announcements',
        route: `${method} /announcements`,
        queryLength: 0,
      }),
      decision: 'deny',
    })),
    {
      name: '강사 자료 읽기 거부',
      request: makeZoneRequest({
        service: 'instructor-materials',
        method: 'GET',
        path: '/materials/guide',
        route: 'GET /materials/:id',
        queryLength: 0,
      }),
      decision: 'deny',
    },
    {
      name: '알 수 없는 서비스 거부',
      request: makeZoneRequest({
        service: 'unknown-service',
        method: 'GET',
        path: '/unknown/item',
        route: 'GET /unknown/:id',
        queryLength: 0,
      }),
      decision: 'deny',
    },
  );

  checks.push(
    {
      name: '접속 신호 누락',
      request: { ...normal, requestId: randomUUID(), signals: undefined },
      decision: 'deny',
      reasonCode: 'starter_not_ready',
    },
    {
      name: '허용되지 않은 접속 정보 출처',
      request: {
        ...normal,
        requestId: randomUUID(),
        signals: { ...normal.signals, source: 'client_header' },
      },
      decision: 'deny',
      reasonCode: 'starter_not_ready',
    },
    {
      name: '지역 정보가 공백뿐인 요청',
      request: {
        ...normal,
        requestId: randomUUID(),
        signals: { ...normal.signals, region: '   ' },
      },
      decision: 'deny',
      reasonCode: 'starter_not_ready',
    },
    {
      name: '최근 이벤트 누락',
      request: { ...normal, requestId: randomUUID(), recentEvents: undefined },
      decision: 'deny',
      reasonCode: 'starter_not_ready',
    },
    {
      name: '잘못된 최근 이벤트',
      request: {
        ...normal,
        requestId: randomUUID(),
        recentEvents: [{ kind: 'risk_signal', ageSeconds: -1, count: 1 }],
      },
      decision: 'deny',
      reasonCode: 'starter_not_ready',
    },
    {
      name: '출처 없음인데 지역·네트워크가 채워진 요청',
      request: {
        ...normal,
        requestId: randomUUID(),
        signals: {
          source: 'none',
          region: 'local',
          network: 'usual',
          hour: 14,
        },
      },
      decision: 'deny',
      reasonCode: 'starter_not_ready',
    },
  );

  if (ruleIds.includes('step_up_required')) {
    checks.push(
      { name: '복합 이상 접속', request: suspicious, decision: 'step_up',
        reasonCode: 'step_up_required' },
      { name: '다시 확인한 복합 이상 접속', request: { ...suspicious,
        requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } },
      decision: 'allow' },
    );
  }
  const results = [];
  for (const item of checks) {
    const response = await decide(item.request);
    const valid = validResponse(item.request, response, ruleIds)
      && response.decision === item.decision
      && (!item.reasonCode || response.reasonCode === item.reasonCode);
    results.push({ name: item.name, passed: valid });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { decide, RULE_IDS } = await import('../src/decider.mjs');
    const results = await checkDecider({ decide, ruleIds: RULE_IDS });
    for (const item of results) process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name}\n`);
    process.stdout.write('이 명령은 가상 요청으로 연습하며 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`판정기 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
