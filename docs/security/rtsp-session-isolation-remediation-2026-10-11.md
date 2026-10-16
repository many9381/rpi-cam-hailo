# RTSPS 세션 격리 수정 — 2026-10-11

대상: [실기기 회귀 시험에서 발견한 RTSP-SESSION-ISOLATION-01](rtsp-device-regression-2026-10-11.md).
사용자가 후속 수정을 승인했다. **소스 수정과 Pi의 별도 프로세스 회귀 검증은
완료**했으며, 운영 서비스에 적용한 결과와 구분한다.

후속: 이 문서 작성 후 새 이미지의 SSD 설치와 실제 운영 서비스 검증도 완료했다.
결과 및 원시 빈 헤더 처리의 구분은
[설치·운영 검증 기록](rtsp-deployment-validation-2026-10-11.md)을 참조한다.
아래 설치 대기 상태는 수정 검증을 끝낸 당시의 기록이다.

## 수정 내용

- GStreamer `handle_request()`의 URL 인증 검사를 Session/Pipelined-Requests
  조회보다 앞으로 옮겼다. 인증 실패는 세션의 만료 시각을 갱신하거나 해당 연결의
  관리 목록에 세션을 등록할 수 없다.
- 앱의 공개 OPTIONS는 세션 선택 헤더가 없는 요청에만 허용한다. `Session` 또는
  `Pipelined-Requests` 헤더가 있으면 빈 값도 포함해 Digest 인증을 요구한다.
  인증된 OPTIONS는 기존처럼 처리한다.
- 추가 조사에서 RTSP **응답 메시지**도 전역 세션 풀에서 다른 연결의 세션을
  등록할 수 있음을 재현했다. 응답은 현재 연결에 이미 등록된 세션만 찾도록
  제한했다. 잠금 안에서 참조를 확보한 후 정상 응답의 세션 갱신·콜백은 유지한다.
- 없는 Session의 요청도 인증 전에는 401로 처리한다. 정상 인증 후에는 기존
  프로토콜 응답인 454를 반환한다.

두 변경을 함께 배포해야 한다. 앱만 수정하면 라이브러리의 인증 전 조회·등록이
남고, 라이브러리만 수정하면 앱의 공개 OPTIONS가 세션 등록을 허용한다.
GStreamer 버전 표시는 계속 **1.28.8**이며 아래 로컬 패치로 수정 여부를 식별한다.

| 위치 | 반영 내용 |
| --- | --- |
| `src/rtsp/GstRtspDigestAuth.cpp` | 세션 선택 헤더가 있는 OPTIONS 인증 |
| `tests/unit/rtsp/GstRtspDigestAuthTest.cpp` | 공개/보호 OPTIONS, 비인증 요청·응답의 등록 및 만료 시각 불변, 정상 응답 콜백 검사 |
| `tests/integration/RtspDigestAuthIntegrationTest.cpp` | 실제 TLS 서버·암호화 미디어로 세션 중단 회귀, 인증 후 정상 처리와 새 연결의 재생 검사 |
| 상위 Yocto `meta-rpi5-cam/recipes-multimedia/gstreamer/files/0001-rtsp-client-authenticate-before-session-association.patch` | 인증 전 세션 접근 및 응답을 통한 세션 등록 차단 |
| 상위 Yocto `meta-rpi-cam-hailo/recipes-camera/camera-firmware/files/0006-rtsp-protect-existing-sessions-before-authentication.patch` | 앱 수정 및 테스트를 불변 upstream pin에 적용 |
| `camera-firmware_git.bb`, `rpi-cam-hailo-devrepo_git.bb` | 실행 앱과 선택 설치되는 개발용 소스에 같은 0006 패치 적용 |

## 검증

실제 Pi에서 운영 앱과 별개의 loopback TLS 서버를 실행했다. 고정한 SSH 호스트 키,
빌드·보드·USB 루트 UUID로 장치를 확인하고, 생성한 테스트 영상과 임시 자격증명을
사용했다. 기존 관리자 암호·운영 TLS 비밀키·SRTP 키는 읽거나 복사하지 않았다.
새 라이브러리는 테스트 명령의 `LD_LIBRARY_PATH`에만 지정했고 로더의 실제 경로와
파일 SHA-256을 확인했다. 운영 서비스 파일과 설정은 변경하지 않았다.

| 단계 | 결과 |
| --- | --- |
| 수정 전 단위 시험 | OPTIONS 인증 누락, 비인증 요청의 세션 등록, 응답 메시지의 세션 등록을 실패로 확인. |
| 수정 전 실제 TLS 재생 | PLAY/OPTIONS/GET_PARAMETER/TEARDOWN 및 응답 메시지로 기존 미디어 중단, 후속 PLAY/TEARDOWN 404 재현. 정상 인증 대조군은 통과. |
| 수정 후 RTSP 단위 테스트 | **126개 통과**, 실패·오류·비활성 0. |
| 수정 후 RTSP 통합·설정·자격증명 CLI 테스트 | **44개 통과**, 실패·오류·비활성 0. |
| 비인증 메시지 후 재생 | 테스트의 기존 연결에서 계속 미디어를 받고 인증된 PLAY/TEARDOWN 200 유지. |
| 세션 만료 시각 | 고정한 기준 시각으로 비교해 거부된 요청·응답이 만료 시간을 늘리지 않음을 확인. |
| 정상 응답 처리 | 인증으로 등록한 세션의 응답 콜백 1회, 정확한 세션 객체 전달·등록 수 1개·정상 만료 시간 갱신 확인. |
| 한쪽만 수정한 대조 시험 | 새 앱/기존 라이브러리에서는 등록·만료 시각 검사가 실패. 기존 앱/새 라이브러리에서는 OPTIONS 정책 검사가 실패. |
| 상위 프로젝트 호스트 테스트 | **361개 통과** — 92.946초. |
| 독립 코드 검토 | 차단할 문제 없음. 만료 시각 불변·정상 응답 수신·실제 응답 dispatch 확인을 보완하고 재검토 완료. |

최초 확장 테스트에서 `SecureRtspConfigSmokeTest.AppConfigCanBuildRtspUrl`은
테스트 디렉터리에 저장소의 샘플 설정이 없어 실패했다. 공개
`config/app-rpi5-dev.yaml`을 테스트 디렉터리에 배치하고 해당 디렉터리에서 다시
실행해 전체 통과했다. 이 실행 환경 실패와 수정 전 결함 재현 로그를 구분해 보존한다.

GStreamer 컴포넌트의 Yocto 패치·컴파일은 성공했다. 테스트를 위해 새 QEMU 이미지나
minimal 이미지를 만들지 않았고 카메라 장치를 점유하지 않았다. 테스트 후 운영
앱은 기존 PID **1169**, 재시작 **0회**를 유지했다.

## 이미지 및 설치 상태

두 패치를 포함한 Hailo 이미지 빌드 ID는
`20261011T180648Z-e664cb9647e7`이다. **이미지 생성과 최종 WIC 내부 검사를
완료**했다. BitBake 7,786개 작업이 모두 성공했고, 이 중 7,710개는 재사용했다.

- 이미지 체크섬과 빌드 입력 provenance가 일치한다. 두 보안 패치의 해시가
  빌드 시작 시 기록과 동일하다.
- 컴파일에 사용한 앱 소스·테스트 3개 파일이 현재 저장소 및 WIC 안의
  `/home/rpiadmin/rpi-cam-hailo`와 SHA-256 기준으로 일치한다.
- WIC에서 추출한 앱과 GStreamer 라이브러리가 패키징 rootfs와 일치한다.
  Pi에서 시험한 GStreamer 라이브러리와 이미지 라이브러리의 ELF Build ID는
  `596155e09dca35f41db839406a1b59f8db3061a2`로 같다.
- 카메라 자동 인식, Wi-Fi, 시각 복원 서비스 순서, Hailo 모델, Codex 패키지,
  공개 서명 키 및 개발 저장소 검사가 통과했다. Codex 인증 정보와 기기 TLS
  비밀키는 범용 이미지에 포함하지 않았다.
- Pi의 임시 테스트 디렉터리는 삭제했다. 운영 앱 PID 1169·재시작 0회 및
  HTTPS 화면·정적 파일·초기 설정 완료 상태를 재확인했다. 비로그인 AI API는
  401을 유지했다.

현재 운영 Pi는 검증 당시의 기존 이미지 `20261011T155422Z-e664cb9647e7`이다.
별도 프로세스의 통과 결과를 운영 서비스 교체나 새 이미지 부팅 통과로 보지 않는다.
새 이미지 설치 후 운영 RTSPS 인증·재생·종료를 다시 확인해야 한다.
이번 작업에서는 SSD를 쓰거나 새 이미지의 하드웨어 검증 PASS를 만들지 않았다.
기존 `scripts/install-ssd.sh`의 최신 완료 이미지 선택 대상은 위 새 빌드다.

## 증거와 한계

원본은 상위 저장소의 `.state/rtsp-isolation-fix-2026-10-11/`에 있다.
이 폴더의 테스트 실행 도구, 수정 전/후 및 혼합 버전 결과, XML, 패치와 검토를
Git 제외 증거로 보존한다. 새 이미지의
`artifacts/20261011T180648Z-e664cb9647e7/rpi5-camera-hailo/security/rtsp-isolation/`에
명시적으로 선택한 증거와 SHA-256 목록을 보관한다. 이미지 검증 결과는 같은
`security/host-image-verification.json`에도 기록한다. 이전 이미지의
`rtsp-validation/` FAIL 기록은 그대로 둔다.

이번 통과는 재현된 세션 격리 결함과 관련 RTSP 기능에 대한 결과다. 장시간 부하·
동시성 스트레스·UDP 전송·모든 암호 구현·모든 취약점 검증을 완료했다는 의미는 아니다.
URL 인증 시 이미 해석된 `ctx->session`을 기대하는 외부 인증 subclass의 호환성은
검증하지 않았다. 현재 이미지의 앱은 요청 헤더를 검사하므로 해당 의존성이 없다.
