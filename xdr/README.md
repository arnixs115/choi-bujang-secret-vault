# XDR 보너스 경보

이 폴더는 보너스 여섯 개의 연습 경보입니다. 경보는 수업용으로 만든 Wazuh 모양이며, 실제 로그가 아닙니다. 정답은 이 저장소에 없습니다.

## 경보 묶음

`xdr/fixtures/<moduleKey>.json` 을 읽습니다. `moduleKey` 는 아래 여섯 개입니다.

| moduleKey | 보는 것 |
|---|---|
| `brute-force` | 짧은 시간에 몰린 로그인 실패 |
| `web-injection` | 웹 요청에 섞인 주입 형태 |
| `known-cve` | 이미 공개된 취약점을 노린 요청 형태 |
| `persistence` | 다시 켜도 남도록 심긴 서비스·예약 작업 |
| `privilege` | 평범한 계정의 갑작스러운 권한 상승 |
| `exfiltration` | 처음 보는 곳으로 빠지는 큰 전송 |

한 파일에는 명확한 공격, 애매한 시도, 정상 이벤트가 함께 들어 있습니다. 주소는 문서용 대역만 쓰고, 계정은 `user01` 같은 가상 이름입니다. `known-cve` 의 원격 조회 구문은 문서용 표기입니다. 그 문자열을 다른 시스템에 넣거나 변형하지 않습니다.

## 학생이 만드는 파일

항목마다 `xdr/<moduleKey>/decide.mjs` 를 만듭니다. `decide(alert)` 를 내보냅니다. 비동기 함수여도 됩니다. 반환은 아래 세 값입니다.

- `action`: `block`, `alert`, `record` 중 하나
- `confidence`: 0 이상 1 이하 숫자
- `reason`: 짧은 이유

명확한 공격은 `block`, 애매한 시도는 `alert`, 정상 이벤트는 `record` 입니다. 경보 원본은 고치지 않습니다.

## 실행

저장소 루트에서 항목 키 하나를 넣습니다.

```
node scripts/xdr-run.mjs brute-force
```

`npm run xdr:run -- brute-force` 도 같은 명령입니다. 실행기는 해당 경보마다 `decide` 를 부르고, 결과를 `xdr/<moduleKey>/result.json` 에 씁니다. 형식은 `aleph.xdr.result.v1` 이고, `decisions` 에는 경보 id·행동·확신도·이유가, `counts` 에는 `block`·`alert`·`record` 건수가 있습니다.

반환 형식이 틀린 경보는 `record` 로 남고, 오류 한 줄이 출력됩니다. 실행기 자체는 네트워크를 쓰지 않습니다. 판정자는 격리된 환경에서 같은 명령을 다시 실행해 결과를 봅니다. 이미 커밋된 `result.json` 만으로 판정이 끝나지 않습니다.

## 웹 주입 대응 (`web-injection`)

`xdr/web-injection/respond.mjs` 는 `decide.mjs` 의 결과를 받아 명확한 공격만 15분짜리 임시 거부 규칙으로 등록합니다. `decide.mjs` 는 판정만 하고, 파일 입출력은 이 모듈과 `rule-store.mjs` 가 맡습니다.

- 등록 조건: `action === 'block'`, `confidence >= 0.85`, 경보 `id`, 유효한 `data.srcip`, `data.url` 안의 웹 주입 근거가 모두 있을 때만. 설명문만 있으면 등록하지 않습니다. 같은 IP에 활성 규칙이 있으면 `duplicate` 입니다.
- 규칙 모양: `{ id: 'xdr-wi-…', effect: 'deny', sourceIp, expiresAt, evidenceAlertId, reason, createdAt }` → `xdr/web-injection/deny-rules.json` (Git 제외).
- 결과 구분: `registered` / `duplicate` / `skipped`(+`skipReason`) / `failed`(+`errorKind`: `io_error` 파일 입출력, `registration_failed` 규칙·저장소 내용 문제). 알림 기록 실패는 `log.ok === false` 로 따로 나옵니다.
- 알림: `xdr/alerts.log` 에 경보당 한 줄 JSONL(`ts, moduleKey, alertId, action, confidence, reason, ruleResult, expiresAt`)로 추가합니다. brute-force 줄(`timestamp`, `ruleStatus`)과 같은 파일을 쓰므로 `moduleKey` 로 구분하세요.

### 판정기 앞 연결 계층 `src/xdr-guard.mjs`

`src/decider.mjs` 는 바꾸지 않습니다. `guardedDecide(request, { sourceIp })` 가 활성 XDR 규칙과 출발지 IP를 먼저 비교하고, 걸리지 않으면 기존 `decide(request)` 결과를 그대로 돌려줍니다.

- 응답은 `docs/DECIDER_REQUEST.md` 의 5개 항목(`schema, requestId, decision, reasonCode, ruleIds`)만 씁니다. 거부 시 `decision: 'deny'`, `reasonCode: 'xdr_web_injection_ip_denied'`, `ruleIds: ['xdr-wi-…']`.
- 근거 경보 ID와 만료 시각은 `guardedDecideDetailed()` 의 `xdr` 에 있습니다. (`{ source, ruleId, evidenceAlertId, expiresAt }`, 통과 시 `null`)
- `xdr-wi-` 규칙 ID는 기존 `RULE_IDS` 와 섞이지 않습니다.
- `sourceIp` 는 신뢰할 수 있는 처리 경로에서 얻은 값만 넣습니다. 요청·경보 본문의 IP 필드는 쓰지 않습니다.

### 실행과 시험

```
node scripts/xdr-web-injection-respond.mjs   # fixture → decide → respond, alerts.log 누적
node scripts/xdr-web-injection-test.mjs      # 가상 요청 시험(임시 폴더 사용)
```

### 아직 연결되지 않은 부분

이 저장소에는 `decide()` 를 부르는 실제 요청 진입점이 없고(엔진이 밖에서 호출), 판정 요청 18개 항목에 출발지 IP도 없습니다. 따라서 `guardedDecide` 는 가상 요청 시험까지만 끝났고, 실제 ZTNA 엔진이 이 규칙을 읽어 집행하는 실시간 차단은 아닙니다. 규칙 파일은 로컬 파일이라 서버리스 배포의 여러 인스턴스 사이에서 공유되지 않습니다. `reasonCode`·규칙 ID가 엔진 등록부에 허용돼 있는지도 확인되지 않았습니다.
