# 플랫폼 보안 업데이트 이미지 설치·부팅 검증 — 2026-10-12

> Privacy: Device/client addresses in this report are documentation-only
> examples. Original local measurements are retained outside Git.

[커널·curl·FFmpeg 업데이트](platform-security-remediation-2026-10-12.md)를 포함한
이미지 **`20261012T031641Z-e664cb9647e7`**, 프로필 `rpi5-camera-hailo`의 실제
Pi 설치·부팅 검증을 통과했다. **Wi-Fi 재부팅 3회 후에도 카메라·웹·Hailo 추론이
정상 동작했다.** 사용자가 마지막 재부팅 후 영상, `hailo / ready`, 처리 프레임
증가, 객체 이름·신뢰도 표시를 직접 확인했다.

## 설치 이미지와 장치 확인

- SSD 설치 기록의 완료 시각은 **2026-10-12T06:16:37Z**이다.
  GIGABYTE 120 GB USB SSD 설치 기록과 실제 압축 WIC의 SHA-256이 일치했다.
  압축 파일은 345,351,478바이트이며 SHA-256은
  `a0246039daaa88cc80c2f3c671fac01b6c69fda706f3378667a28b031e8732b6`이다.
- 사용자가 새 이미지 Pi의 Wi-Fi 주소 `198.51.100.60`을 확인한 뒤 재설치된 SSH
  키를 별도 검증 파일에 고정했다. 기존 보드 식별자, 빌드 ID, 프로필, USB SSD
  루트 `/dev/sda2`를 확인하고 새 파일시스템 UUID가 재부팅 내내 유지됨을 검사했다.
  이전 이미지의 SSH 키와 검증 기록은 보존했다.
- 설치된 **34개 파일**이 검증된 WIC/개발 소스의 SHA-256과 일치했다.
  커널 이미지·부팅 설정, 커널 모듈 7개, 앱·RTSP 라이브러리, OpenSSH 실행 파일,
  libcamera, libcurl, FFmpeg 도구·라이브러리, 개발용 RTSP 소스·테스트를 포함한다.
- HTTPS·RTSPS 공개 인증서는 인증된 SSH 연결로 수집했다. 접속마다 인증서 체인과
  유효기간을 검사하고 DER 해시를 고정했다. 직접 IP로 접속하므로 `camera.local`
  호스트 이름 검사만 예외로 두었다. SSH/TLS 고정 값은 재부팅 내내 유지됐다.

## 새 커널과 하드웨어

실제로 부팅한 커널은 **`6.18.55-v8-16k`**, 페이지 크기는 **16,384바이트**다.
아래 모듈은 초기 검사와 최종 재부팅 후 모두 로드됐으며 vermagic이 실행 중인
커널과 일치했다.

| 기능 | 모듈 |
| --- | --- |
| Hailo PCIe | `hailo_pci` |
| Camera Module 3 센서·초점 | `imx708`, `dw9807_vcm` |
| Pi 5 카메라 입력·ISP | `rp1_cfe_downstream`, `pisp_be` |
| 팬 | `pwm_fan` |
| Wi-Fi | `brcmfmac` |

초기·최종 커널 로그에서 unknown symbol, vermagic/symbol version 불일치,
kernel panic, Oops, IMX708 probe 실패에 해당하는 검사 패턴은 모두 0건이었다.
이는 지정한 패턴 검사 결과이며 모든 커널 메시지가 없다는 뜻은 아니다.

- Hailo: `/dev/hailo0`와 **HAILO8 / 펌웨어 4.24.0** 확인.
  실제 추론은 별도로 사용자가 웹 대시보드에서 확인했다.
- 팬: 최종 **2/4 단계, 5,026 RPM**. 검증 JSON에 남긴 온도 snapshot 중 최고값은
  **61.70°C**, 최종 상태 검사 시 **59.50°C**였다. 전체 팬 곡선·연속 최고 온도나
  장시간 부하를 측정한 결과는 아니다.
- Codex: **0.162.1**, `Logged in using ChatGPT`가 재부팅 후 유지됐다.
  패키지 의존성 수정 대상인 번들 `rg`도 **15.2.0**으로 실행됐다.
  인증 파일 원문은 수집하지 않았으며 모델 요청은 실행하지 않았다.

## 재부팅 및 자동 실행

최초 관측 부팅의 앱 시작은 커널 기준 **6.386203초**였다.

| 재부팅 | 요청부터 SSH·HTTPS 정상 관측 | 앱 시작(커널 기준) | 앱 재시작 | 20초 안정성 |
| --- | --- | --- | --- | --- |
| 1 | 41.900초 | 6.290245초 | 0 | 통과 |
| 2 | 40.898초 | 6.330304초 | 0 | 통과 |
| 3 | 40.884초 | 6.270393초 | 0 | 통과 |

모든 회차에서 Wi-Fi 자동 연결, systemd running, 카메라 서비스
enabled/active/running, **IMX708 NV12 1920×1080 파이프라인 자동 시작**을 확인했다.
유선 LAN carrier는 0이었다. 각 회차에서 서로 다른 boot ID와 동일한 이미지·보드·
루트 UUID를 확인했으며, 안정성 관찰 중 앱 PID가 유지됐다.

웹·JS·CSS·초기 설정 상태 API는 200, 비로그인 AI API는 401을 반환했다.
초기 설정 완료 상태가 유지됐고 최초 부팅 및 재부팅 로그의
`E_HTTP_TLS_IDENTITY` 오류는 0건이었다. 앱은 `networkd-wait-online`을 기다리지
않고 시작됐다. 초기·최종 상태 검사에서 NTP 동기화를 확인했다. 재부팅 직후에는
동기화가 아직 완료되지 않은 snapshot도 있었지만 HTTPS와 앱 실행은 정상적이었다.

복구 시간은 2초 간격 재시도와 SSH timeout을 포함한 관측값이며 전원 인가부터의
부팅 시간은 아니다. 이번 검사는 소프트웨어 재부팅이며 전원 차단·NTP 차단이나
장기 연속 운전 시험을 포함하지 않는다.

## 설치된 미디어 도구·SSH·RTSPS

- **설치된 FFmpeg 7.1.5**와 시스템 라이브러리로 합성 영상 320×240, H.264 10프레임의
  MP4 생성·디코딩, JPEG 생성·디코딩을 통과했다. 카메라 센서는 점유하지 않았다.
  세 IDX 구간이 두 스트림 ID를 재사용하는 제한된 VobSub fixture도 스트림 2개로
  처리됐다. 시험 전후 운영 카메라 서비스의 boot ID·PID·재시작 횟수는 같았다.
- 업데이트된 libcurl 및 FFmpeg 공유 라이브러리는 앞서 Pi에서 분리 검증한 패키지와
  해시가 일치한다. curl 쿠키/TLS, FFmpeg HLS/DRM 세부 회귀 결과는
  [수정 기록](platform-security-remediation-2026-10-12.md)에 있으며 이번 실행으로
  다시 표시하지 않았다.
- 실제 **OpenSSH 10.6p1**의 socket activation과 공개 키 전용 인증, root 로그인
  금지, `rpiadmin` 허용 정책을 확인했다. root 및 공개 키 없는 접속은 거부됐고,
  사용자 이름 검증과 **131,072바이트 SFTP 왕복 전송·해시 비교**를 통과했다.
- 운영 RTSPS의 TLS·비인증 거부 **16개 검사**와 OPTIONS 세션 선택 헤더 정책
  **5개 검사**를 재부팅 전후 모두 통과했다. 빈 헤더가 파서에서 제거되는 경우와
  실제 선택 값이 있어 인증이 필요한 경우를 구분했다.

인증된 RTSP 미디어 수신·복호화와 세션 격리 전체 시험은
[이전 설치 검증](rtsp-deployment-validation-2026-10-11.md)의 별도 결과다.
이번 검사에서 원문 비밀번호·쿠키·SRTP 키는 수집하지 않았다. 장치의 임시 SFTP·
미디어 시험 파일은 제거했고 운영 계정·패키지·설정은 변경하지 않았다.

## 증거와 남은 범위

원본은 Git 제외 `.state/platform-deployment-2026-10-12/`, 보존본은
`artifacts/20261012T031641Z-e664cb9647e7/rpi5-camera-hailo/security/platform-deployment-2026-10-12/`다.
선정한 결과·공개 인증서·검증 도구·설치 기록·이 문서의 SHA-256을 인덱스에 기록한다.
개인 키·로그인 자격증명·원시 journal 전체는 보존본에서 제외한다.

이번 작업은 설치된 이미지 검증으로, 새 이미지 빌드·SSD 쓰기·QEMU/minimal 빌드나
실행은 하지 않았다. Wi-Fi 개발 이미지의 설치·자동 실행 검증을 완료했으며 별도
유선/minimal 정식 release PASS는 생성하지 않았다.

신규 CVE 스캔은 수행하지 않았다. 앞선 이미지 스캔의 원시 미결 연결 **539건**
(커널 403건 포함), FFmpeg 소스 검토 후 남은 **5개 후보**의 후속 조치와 장기 운전
검증은 별도 미결 작업이다. 이번 부팅 성공은 전체 이미지 보안 PASS를 의미하지 않는다.
