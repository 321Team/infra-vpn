## 문제와 변경

- 변경 분류: 코드/실행 설정 포함(혼합 포함) / 사전 검증(Pre-check) 코드 / 문서·증적만
- Pre-check인 경우: 책임 티켓 / 담당 Lead / `REVIEW=NOT PERFORMED (Pre-check)` — 운영 서버 적용 전 해당 SHA 독립 리뷰 필요(순수 검증기 실행은 제외, 판단 근거 기록)
- 책임 티켓/정본 절·AC:
- 해당 Lead:
- 정본 필수 / 기존 승인 구현 / 이번 운영 세칙 중 해당 구분:
- 검토 HEAD / 원본 commit:
- 변경 경로·영향·복구 방법:
- 이번 단계: 소스 이관 / 소비자 전환 / Runtime (해당 단계 명시)

## 검증과 제한

| 단계 | 결과 | 환경·명령·rc·로그·근거 |
|---|---|---|
| STATIC | NOT RUN | |
| MOCK/UNIT | NOT RUN | |
| CI | NOT RUN | 0건을 PASS로 표시하지 않음 |
| RUNTIME | NOT RUN | 대상·계정·KST 시각·source/bundle SHA |

- CI 미실행 사유와 실제 로컬 보상 증적:
- 과거 원본 시험을 인용하는 경우 원본 SHA/Run/Attempt·파일 동일성·적용 한계:
- 이번 단계의 미해결 차단사항 / 후속 Runtime·P1/P2 잔여:

- [ ] 개인키·토큰·실제 Secret 없음, 공개 자료와 테스트 fixture 구분
- [ ] source pin·상대 경로·의존성·만료된 예외·복구 영향 확인
- [ ] 코드 포함 PR: 최신 HEAD의 작성자 외 독립 검토 결과와 승인 근거 연결 (검토 전에는 미체크; 문서 전용은 N/A)
- [ ] 문서 전용 PR: 해당 Lead의 검토·병합 판단 기록 (별도 독립 승인 불필요)
- [ ] CI NOT RUN·과거 이력·미실행 시험의 제한을 기록하고 Lead가 수용 여부를 판단함 (코드 포함 시 독립 검토 범위에도 포함)

REVIEW=PENDING(코드 포함) 또는 NOT_REQUIRED(문서 전용) / LEAD_DECISION=PENDING / MERGE=NOT_DONE / PUBLICATION=NOT_DONE
소스 병합·Runtime·영구 반영·정본 발행·티켓 종결은 결과를 구분한다. 코드 병합 외 절차는 해당 Lead가 결정하며, 여러 단계의 판단은 한 기록에 함께 남길 수 있다.
