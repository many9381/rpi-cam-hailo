# 초기 설정 후 카메라 런타임 시작 실패 — 2026-10-11

## 실기기 진단

Wi-Fi Pi `198.51.100.60`에 `20261011T073859Z-e664cb9647e7` 이미지가 설치된
것을 SSH로 확인했다. 웹 초기 설정 후 앱 서비스는 active 상태였으며 재시작은
없었다. 로그는 RTSP 준비 완료 → libcamera 시작 → 종료 순서로 반복됐다.
현재 실패는 이전의 Origin/자격 증명 문제와 다른 카메라 장치 초기화 문제다.

- `/dev/video*`, `/dev/media*`가 없었다. `rpicam-hello --list-cameras`는
  `No cameras available!`를 출력했다.
- RP1 CFE, PiSP backend, IMX708, DesignWare I2C 커널 모듈을 찾을 수 없었다.
  실제 CSI·PiSP·I2C 장치의 sysfs `driver` 연결도 없었다.
- `/dev/dma_heap/*`는 `root:root 0600`이었다. 일반 계정의 libcamera 도구는
  `Could not open any dmaHeap device`를 출력했다. 서비스 계정도 동일하게
  접근이 불가능한 권한 상태였다.
- Hailo PCIe 드라이버/펌웨어는 올라왔고 `/dev/hailo0`와 Hailo PCIe 장치를
  확인했다. libcamera의 PiSP IPA 모듈과 IMX708 튜닝 파일도 이미 설치돼 있었다.
  이 확인은 실제 Hailo 추론 성공을 의미하지 않는다.

이미지가 `packagegroup-machine-base`를 사용하지 않아 BSP의 전체 커널 모듈
권장 패키지가 들어오지 않았다. 카메라 overlay와 사용자 공간 라이브러리만
포함하고 카메라 경로의 모듈과 DMA 접근 정책을 명시하지 않은 layer 구성 누락이다.

## 수정과 권한 범위

상위 `meta-rpi5-cam`에 `rpi5-camera-support` 패키지를 추가하고 두 카메라
이미지에서 설치한다. 다음 모듈을 필수 의존성으로 지정했다.

- `kernel-module-i2c-designware-platform`
- `kernel-module-rp1-cfe-downstream`
- `kernel-module-pisp-be`
- `kernel-module-imx708`
- `kernel-module-dw9807-vcm`

나머지 모듈 의존성은 Yocto 커널 패키지 의존성으로 함께 설치된다. 실행 중인
장치의 DT compatible은 `raspberrypi,rp1-cfe`다. 고정한 6.18 커널 소스에서
이 compatible을 처리하는 것은 `rp1-cfe-downstream`이고, 별도의 `rp1-cfe`
드라이버는 `raspberrypi,rp1-cfe-upstream`을 처리하므로 둘을 혼동하지 않는다.

`70-rpi5-camera-dma.rules`는 DMA heap에만 `video` 그룹과 `0660`을 적용한다.
기존 `camera-firmware`와 `rpiadmin`의 video 그룹 소속을 사용한다. 전체 사용자
접근이나 root 실행, sudo 권한 확대, 서비스 격리 해제는 추가하지 않았다.
계정/IP 정책·TLS·무결성 서명 동작은 변경하지 않았다.

## 검증

- 새 `tests/host/verify_camera_rootfs.py`를 이전 이미지 rootfs에 실행해
  RP1 CFE 장치 alias를 처리할 모듈이 없는 실패를 먼저 확인했다.
- 수정 rootfs에서는 실제 DT alias의 `modprobe --show-depends` 결과, 선택된
  모듈과 모든 의존 파일, IMX708·AF 모듈, DMA 그룹 정책 검사가 통과했다.
  이 명령은 모듈을 로드하지 않으며 호스트 장치를 변경하지 않는다.
- 새 udev 규칙의 `udevadm verify` 문법 검증이 통과했다.
- 공식 `uv run --locked` 환경에서 호스트 시험 **287개 통과**. 첫 시스템
  Python 실행에서는 `.venv` 사용을 강제하는 환경 검사 1개만 실패했으며,
  실행 환경을 바로잡아 전체를 다시 확인했다.
- Hailo 이미지 `20261011T085144Z-e664cb9647e7` 빌드가 통과했다. 7,786개 작업
  중 7,731개를 재사용했다. QEMU 이미지는 빌드하지 않았다.
- 수집된 이미지·bmap·공개키의 SHA-256, 최종 패키지 manifest의 필수 모듈,
  이미지 공개키와 로컬 개인 서명 키의 대응 검사가 통과했다.

산출물은 상위 저장소 `artifacts/20261011T085144Z-e664cb9647e7/rpi5-camera-hailo/`,
진단과 검사 로그는 Git 제외 `.state/runtime-start-2026-10-11/`에 보관한다.
로그에 인증 암호나 세션 쿠키를 요청하지 않았다.

위 빌드 완료 시점에는 실행 중인 Pi에 수정본을 설치하지 않았다. 새 이미지 설치 후
일반 서비스 계정의 IMX708 열거·촬영과 웹 런타임 시작을 다시 확인해야 한다. 이미지 검증을
물리적 카메라 연결·촬영·Hailo 추론 시험으로 대신하지 않는다.
`scripts/install-ssd.sh`로 전체 재설치하면 기존 웹 계정/설정도 초기화된다.

## 같은 날 재설치 후 후속 진단

SSD 설치 기록과 Pi의 빌드 ID가 `20261011T085144Z-e664cb9647e7`임을
확인했다. 이전에 확인한 Wi-Fi MAC과 일치하는 장치에서 새 SSH 호스트 키를
고정하고 진단했다. 앞의 패키징 수정은 실기기에 적용돼 있었다.

- `/dev/media0..2`, `/dev/video20..35`가 생성됐고 I2C·CFE·PiSP 드라이버가
  바인딩됐다. DMA heap은 `root:video 0660`이며 도구의 DMA 권한 오류가 사라졌다.
- 그러나 `rpicam-hello --list-cameras`는 여전히 `No cameras available!`였다.
- 커널은 `imx708 11-001a: failed to read chip id 708, with error -5`와
  `dw9807 11-000c`의 I2C 오류 `-121`을 기록했다. 센서와 AF 모터 모두
  현재 선택된 카메라 I2C 버스에서 응답하지 않았다.
- 설치된 `/boot/config.txt`는 `dtoverlay=imx708`만 지정하고 자동 감지는
  설정하지 않았다. BSP의 `RASPBERRYPI_CAMERA_V3 = "1"`이 이 값을 생성한다.
  포트 인수가 없는 IMX708 overlay는 CAM/DISP1에 고정된다. 실제 연결 포트의
  기판 표기는 사용자가 확인하기 어려운 상태여서 포트 불일치를 확정하지 않았다.

[공식 Raspberry Pi 문서](https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/camera/rpicam_configuration.adoc)에
따라 카메라 프로필의 수동 overlay 생성을 끄고 `camera_auto_detect=1`을
추가했다. 공식 Camera Module 3을 Pi 5의 어느 CAM/DISP 포트에 연결하든
펌웨어가 감지하도록 하는 설정이다. 두 카메라 프로필에 상속되며 최소/QEMU
이미지에는 적용되지 않는다. 인증 정보, 서명 정책과 장치 접근 권한은 바꾸지 않는다.

기존 빌드의 실제 `config.txt`를 검사해 자동 감지 누락과 수동 overlay 존재를
실패로 재현했다. `bitbake rpi-config -c deploy`로 부팅 설정만 다시 생성했고
150개 작업 중 142개를 재사용해 모두 통과했다. 생성물에
`camera_auto_detect=1`이 정확히 하나 있고 수동 IMX708 overlay가 없으며,
IMX708 DTBO가 배포 디렉토리에 존재함을 확인했다. 공식 `uv run --locked`
환경에서 호스트 시험 287개가 통과했다. 이 단계에서는 전체 이미지나 QEMU를
빌드하지 않았으며, 기존 COMPLETE 이미지가 갱신됐다는 의미가 아니다.
후속 검사 기록은 Git 제외
`.state/runtime-followup-2026-10-11/`에 보관한다. 현재 연결된 Pi의 부팅 설정은
아직 바꾸지 않았다. 전원을 분리한 상태에서 다른 CAM/DISP 커넥터로 옮긴 뒤
기존 이미지로 센서가 인식되는지 확인하는 최소 시험을 사용자에게 요청했다.
포트 불일치 또는 케이블/센서 문제의 구분과 실제 런타임 성공 판정은 이 실기기
시험 및 촬영 결과를 확인한 뒤 기록한다.

사용자가 같은 커넥터에서 케이블 방향만 바꿔 재연결한 뒤 다시 확인했다.
부팅 ID가 바뀐 것을 확인했지만 카메라 목록은 여전히 비어 있었고 센서 `-5` /
AF `-121` 오류도 동일했다. 다른 CAM/DISP 포트로 옮긴 시험은 아직 아니다.
초기 조회에서 앱 서비스가 inactive였던 것은 `network-online.target` 시작
대기 중이었기 때문이며, 그 상태를 센서 오류로 인한 서비스 종료로 해석하지
않는다. 해당 부팅 로그는 `boot-after-cable-reconnect.log`로 별도 보관한다.

## 기존 OS 동작 확인에 따른 검증 방향 수정

사용자는 같은 카메라와 기존 연결 그대로 다른 OS에서는 정상 작동했다고
알려왔다. 이는 이미지/BSP 설정 차이를 먼저 분리해야 한다는 근거다. 이후에는
케이블 이동을 요구하지 않고, 정상 동작하던 연결을 유지한 채 부팅 설정만
변경하기로 했다. 이전 I2C 오류만으로 케이블/센서 고장을 판정하지 않는다.

등록된 SSD가 빌드 PC의 USB 장치 `/dev/sdb`로 다시 연결됐고 모델·용량·일련번호
일치를 확인했다. 상위 `scripts/install-ssd.sh --repair-camera-boot` 옵션은
같은 등록 장치 검사를 재사용한다. 전체 이미지 설치와 독립적으로 실행되며
부팅 파티션의 원본 `config.txt.before-camera-autodetect` 백업을 보존하고
자동 감지 설정만 원자적으로 교체한다. rootfs는 마운트하지 않아 기존 웹 계정,
TLS 키·서명 파일·Codex 인증 정보가 유지된다. 쓰기 후 읽기 전용 검증과 마운트
해제를 수행한다. `--check`는 마운트 없는 대상 SSD 사전 검사다.

검토 과정에서 발견한 별칭 overlay 지시문, 별도 `dtparam`의 센서 overlay 범위,
부팅 파일 경로 재지정은 자동 수정 대상으로 해석하지 않고 쓰기 전에 거부한다.
원본 보존, 반복 실행, 심볼릭 링크·불일치 백업 거부, 원자적 교체 실패,
장치 변경 및 마운트 해제 실패 시 파일 보존을 시험한다.
추가한 복구 시험 10개와 기존 호스트 시험을 합쳐 297개가 공식
`uv run --locked` 환경에서 통과했다. 별도 코드 재검토에서 중요한 미해결
문제는 없었다. 실제 SSD에 대한 `--repair-camera-boot --check`도 통과했다.
현재 호스트의 sudo는 암호 입력이 필요하므로 실제 SSD 적용은 사용자가 이
명령을 실행한 뒤 확인해야 한다. 소스/부팅 설정 생성물 수정과 SSD 적용,
카메라 촬영 성공은 별개의 검증 단계로 기록한다.

## 자동 감지 적용 후: libcamera와 CFE 인터페이스 불일치

복구 명령 적용 후 Pi의 `config.txt`에 자동 감지가 켜졌고, 커널은 CAM/DISP0의
`imx708 10-001a`에서 모듈 ID `0x0302`를 읽어 `imx708_wide` 센서와 CFE
video0..7 노드를 등록했다. 앞의 CAM/DISP1 고정은 잘못된 이미지 설정이었다.
그런데 사용자 공간의 카메라 목록은 여전히 비어 있었다.

`LIBCAMERA_LOG_LEVELS=*:DEBUG` 로그에서 모든 media 장치와 의존성이 열거된
뒤 `Unable to acquire a CFE instance`가 발생했다. 설치된 upstream libcamera
0.6.0의 PiSP 코드는 `rp1-cfe-fe-image0`, `-fe-stats`, `-fe-config`를 찾고
CSI 출력 pad 1/2 및 routing API를 사용한다. 실제 Raspberry Pi downstream
드라이버는 `rp1-cfe-fe_image0`, `-fe_stats`, `-fe_config`, `-embedded`와
CSI 출력 pad 4/5를 사용한다. 권한이나 웹 초기 설정 문제가 아니라 서로 다른
커널/사용자 공간 인터페이스를 조합한 layer 문제다. 이름만 치환하는 패치로
해결되는 문제가 아니다.

상위 layer의 libcamera 0.6.0 bbappend에서 Raspberry Pi 공식 fork의
`v0.6.0+rpt20251202`, commit `f0e40f1c50bd0afe65727d6e407d0dcb42666ada`를
고정했다. 0.6 클라이언트 ABI를 유지하면서 downstream PiSP/IPA 코드를 함께
선택한다. Raspberry Pi override에만 적용하고 기존 Meson/toolchain 패치는
유지했다. 패키지 버전도 `0.6.0+rpt20251202`로 구분한다.

- 실제 기존 rootfs 검사에서 downstream CFE entity를 지원하지 않는 libcamera
  바이너리 때문에 실패하는 것을 재현했다.
- libcamera 대상 빌드는 2,109개 작업 중 2,090개를 재사용해 통과했다.
- 새 패키지를 Pi의 `rpiadmin` 전용 임시 경로에 배치하고 해당 프로세스에만
  library/IPA 경로를 지정했다. 설치된 시스템 라이브러리는 아직 교체하지 않았다.
- 이 상태에서 IMX708 Wide와 세 센서 모드가 열거됐다. 자동 초점 JPEG 촬영과
  10초 H.264 인코딩이 성공했고 영상은 1920×1080, 291프레임으로 검사됐다.
  raw H.264의 ffprobe 프레임레이트 메타데이터는 `1200000/1`이므로 이 값을
  근거로 30fps 파일이라고 판정하지 않았다.
- 설치된 `camera-firmware` 바이너리도 새 라이브러리로 시험 실행했다. 별도
  개발 설정으로 HTTP/RTSPS를 Pi loopback에만 바인딩했고 실제 서비스의
  계정·TLS·서명·설정을 변경하지 않았다. 1920×1080, 설정 50fps에서
  7,045프레임 촬영/인코딩, 실제 약 50fps, 양쪽 오류 0건을 확인했다.
  스냅샷 API는 유효한 1920×1080 JPEG를 반환했다. Hailo 추론은 이번 시험에서
  활성화하지 않았으므로 이 결과를 Hailo 추론 성공으로 해석하지 않는다.

상세 로그는 Git 제외 `.state/runtime-followup-2026-10-11/`에 보관한다.
관련 upstream/downstream 차이는
[libcamera 개발자 논의](https://lists.libcamera.org/pipermail/libcamera-devel/2026-June/059105.html)와
[Raspberry Pi 고정 소스](https://github.com/raspberrypi/libcamera/tree/f0e40f1c50bd0afe65727d6e407d0dcb42666ada)를
함께 참조한다. 실제 서비스의 영구 라이브러리 교체와 새 이미지 검증은 후속 단계다.

## 검증된 런타임의 이미지 반영 및 기존 SSD 복구 준비

임시 앱 시험의 마지막 조회에서는 1920×1080에서 11,001프레임을 촬영하고
인코딩했으며 약 50fps, 촬영/인코딩 오류 0건이었다. 웹 `live.mp4` 출력도
ffprobe로 H.264 1920×1080임을 확인했다. 시험 프로세스는 SIGTERM으로
종료했고 서비스 설정이나 시스템 라이브러리를 임시 시험으로 덮어쓰지 않았다.

새 Hailo 이미지 `20261011T102426Z-e664cb9647e7`의 전체 빌드가 통과했다.
7,786개 작업 중 7,712개를 재사용했다. 최종 패키지 manifest는 libcamera
`0.6.0+rpt20251202`를 포함한다. rootfs의 실제 DT 드라이버·의존성·DMA
권한·downstream CFE 사용자 공간 검증, 이미지/bmap/공개키 SHA-256 및
이미지 공개키와 로컬 개인 서명 키의 대응 검사가 통과했다. QEMU는 빌드하지
않았다. 이 결과는 새 이미지 전체를 실기기에서 부팅했다는 의미는 아니다.
최종 압축 Wic의 부팅 파티션에서 직접 읽은 `config.txt`에도 자동 감지가
정확히 하나 있고 수동 IMX708 overlay가 없었다. 새 rootfs의 교체 대상 75개
파일은 실기기에서 시험한 복구 payload와 바이트·권한이 모두 일치했다.

기존 계정과 설정을 보존하는 상위 명령은 다음과 같다.

```sh
./scripts/install-ssd.sh --repair-camera-runtime
```

등록된 SSD를 다시 식별하고, 부팅 설정 자동 감지를 확인한 뒤 libcamera의
라이브러리·IPA·proxy·tuning 파일만 교체한다. Git 제외
`.state/camera-runtime-repair/`에 실제 Pi에서 검증한 패키지의 75개 파일과
해시 manifest를 준비했다. 각 파일 해시, 허용 경로, AArch64 ELF 및 0.6
SONAME, 기존 이미지 프로필과 ABI를 확인한다. 원본과 해시는 SSD의
`/var/backups/rpi5-camera-runtime/`에 보존하며 읽기 전용 재검증 후 마운트를
해제한다. 웹 계정·TLS·서명된 앱 설정·앱 바이너리·Codex 인증은 변경 대상에
포함되지 않는다. 설치된 빌드 ID와 RPM DB는 기존 값이며, 이 부분 업데이트는
백업 manifest로 구분한다. 이후 전체 이미지 설치에는 layer의 패키지 버전이
정상 반영된다.

코드 검토에서 지속적인 쓰기 실패 시 일부 파일만 복구되는 문제와 중단 신호
처리 누락을 재현해 수정했다. 성공한 교체만 기록하고, 같은 파일시스템의
원본 백업을 rename하여 추가 데이터 공간 없이 복구한다. SIGINT/SIGTERM은
원자적 교체 경계까지 지연한 뒤 복구하며, 한 복원에 실패해도 나머지 복원을
시도하고 남은 경로와 백업을 보고한다. 전원 차단까지 원자적인 전체 파일시스템
트랜잭션을 보장하는 기능은 아니다. 마운트 해제 실패 시 연결된 파일 트리를
재귀 삭제하지 않는다.

공식 `uv run --locked` 환경에서 호스트 시험 **308개 통과**. 지속 ENOSPC,
실제 SIGINT/SIGTERM, KeyboardInterrupt, 잘못된 CPU/SONAME 및 손상된 ELF,
미완료 복원 보고, rootfs 검사/설치/검증/마운트 해제 실패를 포함한다. 후속 코드
검토에서 중요한 미해결 문제는 없었다. 등록 SSD의 읽기 전용 사전 검사도
통과했다. 호스트 sudo 암호가 필요해 사용자가 복구 명령을 실행하도록 안내한
상태이며, 영구 적용 후 정상 환경의 서비스 시작·웹 영상을 추가 확인해야 한다.

## SSD 적용 후 일반 서비스 및 웹 영상 확인

사용자가 복구한 SSD로 부팅한 Pi의 boot ID는
`ab5d1ab0-ae62-4b20-8069-5379f202f91e`였다. SSH에서 읽은 시스템의 두
libcamera 라이브러리 SHA-256이 실제 시험한 payload와 일치했다. 임시
라이브러리 환경 변수를 지정하지 않은 `rpicam-hello --list-cameras`가
IMX708 Wide의 세 모드를 열거했다. 정상 `camera-firmware.service`는 PID 605,
`active/running`, 재시작 0회였고 다음 시작 로그를 기록했다.

```text
libcamera v0.6.0+rpt20251202+dirty
camera pipeline running: imx708-main NV12 1920x1080
camera firmware running
```

`https://198.51.100.60:8443/` 및 `/app.js`, `/styles.css`가 모두 HTTP 200을
반환했다. 이 진단 요청은 계정이나 쿠키를 보내지 않았고, 설치된 자체 서명
인증서 때문에 curl의 인증서 검증 예외를 사용했다. 이는 브라우저의 인증서
신뢰 설정까지 검증했다는 뜻이 아니다. 사용자가 이어서 **웹 화면과 카메라
영상 모두 정상**임을 확인했다. 따라서 별도 시험 프로세스에 한정됐던 검증이
기존 계정·보안 설정을 유지한 실제 서비스 동작 확인으로 이어졌다.

처음 웹에 접속되지 않은 원인은 별도로 확인됐다. Wi-Fi는 `routable/configured`
상태였지만, `RequiredForOnline=yes`인 eth0가 케이블 없이 `no-carrier/configuring`
상태였다. `systemd-networkd-wait-online`의 120초 시간 초과 뒤 앱이 부팅 후
125.314초에 시작됐다. 카메라 또는 웹 프로세스가 반복 종료된 것이 아니다.

layer 서비스 파일의 `Wants/After=network-online.target`을 제거하고
`After=network.target`으로 바꿨다. HTTPS/RTSPS는 `0.0.0.0`에 바인딩하므로
주소 할당을 기다릴 필요가 없고, 네트워크 스택보다 먼저 종료되는 순서는
유지한다. 이는 [systemd의 서버 네트워크 의존성 안내](https://systemd.io/NETWORK_ONLINE/)에
따른다. 계정·TLS·IP 제한·무결성 검증·서비스 권한은 바꾸지 않는다.

이 마지막 부팅 지연 수정은 **layer 소스에만 적용**한 상태다. 현재 Pi 및 앞서
완료한 `20261011T102426Z-e664cb9647e7` 이미지에는 이전 서비스 파일이
남아 있다. 다음 이미지 빌드/설치 후 부팅 지연 해소를 실기기에서 확인해야
하며, 현재 카메라 영상 정상 확인과 구분한다.
수정 unit은 호스트의 `systemd-analyze verify` 문법 검사를 통과했다. 검사에서만
AArch64 실행 경로를 호스트 `/usr/bin/true`로 치환했으며 실제 서비스를
시작하지 않았다. 관련 firmware 패키징 시험 3개도 통과했다.

## 같은 장비의 Hailo 실제 추론 확인

추가 빌드나 SSD 이동 없이 실행 중인 Pi에서 확인했다. SSH의 읽기 전용
장치 조회 결과 `/dev/hailo0`는 `root:video 0660`, PCIe 장치는
`0001:01:00.0`, 아키텍처는 HAILO8이었다. HailoRT CLI와 장치 펌웨어 모두
4.24.0이었다. 설치된 `yolo_model.hef`의 SHA-256이 layer의 고정 해시와
일치했고 `hailortcli parse-hef`는 다음 모델 형식을 보고했다.

- 네트워크: YOLOv8n, HAILO8, single context.
- 입력: UINT8 NHWC 640×640×3.
- 출력: FLOAT32 HAILO NMS BY CLASS, 80종, 클래스당 최대 100개 박스.

사용자는 로그인한 실제 앱 대시보드에서 `hailo / ready`, 실행기 정상,
프레임 표기 29,081과 지속 증가, 전처리 0.6ms·추론 10.8ms를 확인했다.
프레임 표기는 UI의 마지막 처리 sequence이므로 누적 처리 성공 횟수나
FPS로 해석하지 않는다. 추론 시간의 역수를 실제 처리 FPS로 환산하지도
않는다. 이 관찰은 앞의 AI 비활성 임시 카메라 시험과 달리, 실제 서비스의
모델 로딩과 프레임 추론이 진행된다는 증거다.

SSH 계정에는 로그인된 웹 세션이 없으며 카메라 상태 API는 HTTP 401로
보호돼 있었다. 비밀번호·세션 쿠키를 요청하거나 인증을 우회하지 않고,
인증된 화면의 상태 수치를 사용자에게 확인했다. 별도 경쟁 벤치마크나
두 번째 카메라 프로세스를 띄우지 않았고 앱 설정도 변경하지 않았다.
사용자가 이어서 검출 결과에 **객체 이름과 신뢰도가 표시됨**을 확인했다.
따라서 카메라 입력 → Hailo 실제 추론 → 웹 검출 결과 출력의 기본 동작 검증은
완료했다. 확인 시 서비스는 같은 PID 605로 재시작 0회였고 SoC 온도는
56.75°C였다. 장시간 안정성, 실제 처리 FPS 및 동시 클라이언트 성능은
이 단기 확인에 포함하지 않는다. 상세 장치 로그와
관찰 출처는 Git 제외 `.state/runtime-followup-2026-10-11/hailo-verification.json`
및 같은 디렉토리의 `hailo-*.log`에 보관한다.
