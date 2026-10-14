// 9단계에서 학생이 채우는 탐지 함수입니다. 이 기본값은 어떤 접속도 회수하지 않습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.

 // 9단계: 같은 가상 사용자(sub)의 짧은 시간 내 GET 폭주를 탐지합니다.
// 운영 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();

  for (const event of events) {
    if (event?.method !== 'GET') continue;

    const subject = event?.identity?.sub;
    const at = Date.parse(event?.at);

    if (typeof subject !== 'string' || subject.length === 0 || !Number.isFinite(at)) {
      continue;
    }

    if (!readsBySubject.has(subject)) readsBySubject.set(subject, []);
    readsBySubject.get(subject).push(at);
  }

  const windowMs = 10 * 60 * 1000;

  for (const [subject, timestamps] of readsBySubject) {
    timestamps.sort((a, b) => a - b);
    let start = 0;

    for (let end = 0; end < timestamps.length; end += 1) {
      while (timestamps[end] - timestamps[start] > windowMs) {
        start += 1;
      }

      if (end - start + 1 > 120) {
        return {
          action: 'propose_revocation',
          reasonCode: 'burst_read',
          subject,
        };
      }
    }
  }

  return { action: 'observe' };
}
