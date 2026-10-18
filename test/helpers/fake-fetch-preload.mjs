// `node --import <이 파일>` 로 bundle.mjs를 시험할 때만 쓴다. 전역 fetch를 가상 배포로 바꿔
// 시험 중에 실제 배포로 요청이 나가지 않게 한다.
import { createFakeDeployment } from './fake-deployment.mjs';

globalThis.fetch = createFakeDeployment().fetch;
