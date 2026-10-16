# Yocto layer 보안 수정 기록 — 2026-10-10

기준일: 2026-10-10 UTC. 대상: 상위 `yocto-rpi5-cam-firmware` 저장소의
`rpi5-camera-hailo` 이미지. 기존 이미지
`20261010T103015Z-e664cb9647e7`의 rootfs manifest와 실제 레시피를 기준으로
수정했다. 2026-09-10 Debian 장비 검사 결과를 Yocto 패키지 버전에 그대로
대입하지 않았다.

## 적용 항목

| 구성 요소 | 기존 → 적용 | 보안 근거 | 레이어 반영 위치 (상위 저장소 기준) |
|---|---|---|---|
| GStreamer 전체 릴리스 계열 | 1.28.2 → **1.28.8** | RTSP 인증 헤더 DoS, KeyMgmt 범위 밖 읽기, RTCP SDES/PRIV 범위 검사, RTP 소스 테이블 메모리 제한 등 | `meta-rpi5-cam/recipes-multimedia/gstreamer/`의 공통 include와 10개 bbappend |
| OpenSSL | 3.5.7 → **3.5.9** | 3.5.8 및 3.5.9 보안 수정 누적 반영 | `meta-rpi5-cam/recipes-connectivity/openssl/openssl_3.5.7.bbappend` |
| PCRE2 | 10.47 → **10.49** | CVE-2026-86145, CVE-2026-103111 | `meta-rpi5-cam/recipes-support/libpcre/libpcre2_10.47.bbappend` |
| SQLite | 3.51.3 → **3.53.4** | 3.53.2에서 수정된 FTS5 문제: CVE-2026-11822 / CVE-2026-11824 (동일 문제) | `meta-rpi5-cam/recipes-support/sqlite/sqlite3_3.51.3.bbappend` |
| zlib | 1.3.2 + **공식 백포트** | CVE-2026-85091, 비차단 gzwrite 후 잘못 남는 입력 포인터 | `meta-rpi5-cam/recipes-core/zlib/`, upstream `df84af25dc1942490e1d1c899a07619152a46148` |
| GLib | 2.88.0 + **공식 백포트** | CVE-2026-58010, GVariant offset 경계 비교 오류 | `meta-rpi5-cam/recipes-core/glib-2.0/`, upstream `be85f9429bb66412a9775440a88cb115803ba897` |
| 웹 개발 의존성 source-map-js | 1.2.1 → **1.2.2** | CVE-2026-93749 / GHSA-68fv-2mgg-jv7q, indexed source-map DoS | `web/package-lock.json` 및 `meta-rpi-cam-hailo`의 웹 소스 패치·npm include |
| 웹 SBOM | SRI base64 → **검증된 hex hash** | CycloneDX 1.5 hash 형식 오류 수정; CVE 수정과 별도의 증거 정확성 개선 | `tools/security/generate_sbom.py`, 회귀 테스트, `docs/security/sbom/web.cdx.json`, 개발용 소스 패치 |

외부 OE-Core/kas 소스 리비전은 변경하지 않았다. 기존 레시피의 패치,
빌드 옵션과 패키징을 재사용하는 버전별 `.bbappend`로 적용했다. 예를 들어
`openssl_3.5.7.bbappend`라는 파일명은 기존 레시피와 매칭하기 위한 것이며,
평가되는 `PV`와 소스 URL은 3.5.9다. 향후 OE-Core 업데이트로 레시피 파일명이
변경되면 이 override들을 검토·제거해야 한다.

GStreamer core/base/good/bad/ugly/RTSP server/libav/Python/devtools/examples를
같은 버전으로 맞췄다. 이미지에 설치하지 않는 계열 패키지는 추가로 설치하지
않는다. `gst-examples`는 공식 1.28.8 태그의 커밋
`1b2a95a1b72787cda146b46df9605b168e5b683b`에 고정했다.

zlib의 수정 릴리스가 아직 없어 1.3.2에 공식 커밋을 백포트했다. GLib은 기존
OE-Core의 CVE-2026-58016 패치 2개를 유지하면서, 실제 소스에 누락된
CVE-2026-58010 수정과 upstream 회귀 테스트를 추가했다. 두 백포트 모두
`CVE:`와 `Upstream-Status: Backport` 메타데이터를 포함한다.

## 웹과 개발용 저장소에 전달되는 경로

애플리케이션 소스 기준 커밋은 `ba503a1fbc4ed68c1fd29aace7214a5c330d7021`로
유지했다. 로컬 checkout만 수정해도 이미지에 자동 반영되는 구조가 아니므로,
`meta-rpi-cam-hailo/recipes-camera/camera-firmware/`에서 다음을 적용했다.

- `camera-firmware-web_git.bb`: `0003-web-update-source-map-js-security-fix.patch`
  적용 후 새 `camera-firmware-npm.inc`의 lockfile SHA-256과 npm archive SRI로
  검증한다. 기존 offline npm 빌드 방식은 유지한다.
- `rpi-cam-hailo-devrepo_git.bb`: 원본 커밋으로 독립 Git checkout을 생성한 후
  `0004-security-fix-web-dependency-and-sbom-hashes.patch`를 적용한다. 따라서
  `/home/rpiadmin/rpi-cam-hailo`에도 새 lockfile, SBOM 수정과 테스트가 들어간다.
  이 변경은 `git diff`와 untracked 회귀 테스트 파일로 확인할 수 있다.
  원본 HEAD/history는 그대로이며 호스트의 인증 파일·설정·임의 변경은 복사하지 않는다.
- 개발용 패키지 제거 옵션 `RPI_CAM_HAILO_DEV_REPO=0`은 그대로 사용한다.

향후 위 소스 수정이 포함된 upstream 커밋으로 `CAMERA_FIRMWARE_SRCREV`를
갱신하면 중복 패치를 제거하고 npm include를 다시 생성한다.

## RTSP/미디어 후속 조치와 기존 기록 정정

1. **CVE-2026-85150 / SA-2026-0082**: 공식 수정 버전은 1.28.7이다.
   이번 1.28.8 업데이트에 포함된다. 현재 앱은 `GstRtspDigestAuth`에서
   인증 vfunc를 재정의하므로, 기본 인증 파서의 취약점이 인증 전 공격으로
   그대로 도달한다고 단정할 수 없다. 과거 문서의 “인증 전 파싱이므로
   비인증 원격 크래시 가능” 주장은 현재 앱 경로에 대한 증거가 부족했다.
2. **SA-2026-0084**: SETUP의 KeyMgmt 파서 수정은 1.28.8에 포함된다.
   현재 앱은 OPTIONS 이외 요청에 Digest 인증을 먼저 검사한다.
   인증된 클라이언트의 입력 경로는 남으므로 라이브러리 수정이 필요했다.
3. **SA-2026-0030, SA-2026-0091**: RTCP SDES/PRIV 범위 검사를 포함한다.
   앱은 RTCP를 사용한다. SRTCP 인증과 키·SSRC 조건이 있으므로 임의 UDP
   패킷만으로 비인증 공격이 성립한다고 단정하지 않는다.
4. **SA-2026-0074**: 소스 테이블 메모리 제한은 1.28.6에서 도입됐으며,
   이번 업데이트에 포함된다. 이를 1.28.7의 수정으로 기록하지 않는다.

5. **CVE-2026-12892 / SA-2026-0047**: H.264 확장 NAL 헤더 뒤의
   1바이트 범위 밖 읽기 수정은 gst-plugins-bad 1.28.5에 포함됐으며, 이번
   1.28.8 업데이트로 함께 반영된다. 공격 조건은 조작된 H.264 입력이다.
   카메라 인코더가 생성한 프레임을 전송하는 현재 경로에서 외부 악성
   비트스트림의 도달이 입증된 것은 아니다.

현재 systemd 서비스의 자동 재시작은 이미 설정되어 있지만, 반복 DoS의
근본 수정으로 보지 않는다. TLS 서버 인증서는 클라이언트 인증을 대신하지
않는다. 실제 인증/SETUP/PLAY/RTCP 회귀 검증은 아래 장비 확인 항목으로 남긴다.

2026-10-11 후속: 설치된 1.28.8 이미지에서 해당 회귀 시험을 실행했다.
인증·암호화 미디어의 범위별 검사는 통과했지만, 유효한 Session 값을 아는
비인증 연결이 기존 재생 세션을 중단시키는 문제를 발견해 전체 판정은 FAIL이다.
이 미수정 항목과 검증 한계는 [실기기 RTSPS 검증 기록](rtsp-device-regression-2026-10-11.md)에 남겼다.

## 검증

- 공식 GStreamer archive 9개의 SHA-256을 공식 sidecar와 대조했다.
  [다운로드 증거](scan-2026-10-10/gstreamer-source-checksums.json)를 보존한다.
  기존 패치 13개는 fuzz 없이 적용되며 license checksum 13개가 유지된다.
- OpenSSL 공식 SHA-256, PCRE2 공식 GitHub release asset digest를 대조했다.
  SQLite archive의 amalgamation SHA3-256을 공식 릴리스 기록과 대조했다.
  모든 기존 license checksum이 유지된다.
- OpenSSL 기존 패치 적용 및 AArch64 Configure 통과. PCRE2 host upstream
  테스트 3/3 통과. SQLite host 빌드·설치 후 버전, FTS5 검색 및 integrity 검사
  통과. zlib host normal/64-bit/shared 테스트 통과.
- 웹 테스트 **739개/55개 파일** 통과, production build 통과.
  [수정 전 검사](scan-2026-10-10/npm-audit-before.json)의 source-map-js
  high 1건을 수정했다. 전체 및 `--omit=dev` npm audit 모두 **0 vulnerabilities**.
  [전체 결과](scan-2026-10-10/npm-audit.json),
  [운영 의존성 결과](scan-2026-10-10/npm-audit-production.json).
  이는 웹 npm 범위의 결과이며 전체 이미지의 취약점 0건을 뜻하지 않는다.
- SBOM Python 회귀 테스트 **4개**, npm metadata 테스트 **8개** 통과.
  재생성한 웹 SBOM의 **174개 구성 요소**와 hash를 공식 CycloneDX 1.5 전체
  JSON schema로 검증했다. Debian 장비의 기존 firmware SBOM은 덮어쓰지 않았다.
- GLib 공식 `/gvariant/normal-checking/tuple-offsets6`를 별도 host ASan
  빌드에서 실행했다. 수정 전 `>` 비교에서는 heap-buffer-overflow / 1-byte
  OOB read로 exit 1, 공식 `>=` 수정 후 동일 테스트는 **1/1 통과**, exit 0.
  누수 검사는 비활성화하고 범위 밖 읽기 회귀만 검증했다.
- 전체 호스트 회귀 테스트 **270개** 통과.
- 개발용 Git 설치 테스트: 보안 패치 누락 및 충돌 시 실패를 먼저 재현한 후
  수정했고, **7개**가 통과했다. 인증·호스트 파일 미복사 검사도 유지된다.
- 최종 Yocto `rpi5-camera-hailo` 이미지 빌드 **통과**. 2026-10-10 17:05 UTC에
  산출물 수집을 완료했다. 총 **7,767개 작업 성공**, 그중 5,401개는 기존 결과를
  재사용했다. 카메라 펌웨어·웹 및 GStreamer core/base/good/bad/RTSP server의
  실제 Pi 대상 빌드와 패키징이 통과했다.
- [최종 이미지 검증 결과](scan-2026-10-10/image-verification.json): **PASS**.
  rootfs의 build ID와 패키지 manifest에서 GStreamer 1.28.8, OpenSSL 3.5.9,
  PCRE2 10.49, SQLite 3.53.4를 확인했다. 설치된 GStreamer 라이브러리·플러그인
  전체가 1.28.8이며 `subparse` 패키지와 공유 라이브러리는 포함되지 않았다.
- 실제 빌드에 사용된 zlib 1.3.2와 GLib 2.88.0 소스에서 공식 백포트 코드를
  확인했다. 두 패키지의 Pi 대상 컴파일도 성공했다.
- rootfs의 `/home/rpiadmin/rpi-cam-hailo`에서 lockfile, SBOM 생성 코드와 회귀
  테스트가 수정된 로컬 소스와 바이트 단위로 일치했다. source-map-js 1.2.2,
  원본 Git HEAD 유지, alternates·호스트 인증 파일·node_modules 미복사도 확인했다.
- 수집된 WIC 압축 이미지와 bmap의 SHA-256 검증 **통과**. 이미지 SPDX를
  산출물의 `security/`에 보존하고, manifest·SPDX 해시를 위 검증 JSON에 기록했다.

완료 build ID는 `20261010T140358Z-e664cb9647e7`이다. 상위 저장소 기준 산출물은
`artifacts/20261010T140358Z-e664cb9647e7/rpi5-camera-hailo/`에 있으며,
`images/rpi5-camera-image-raspberrypi5.rootfs.wic.bz2`가 설치용 이미지다.
`COMPLETE`와 `checksums/SHA256SUMS`가 생성되었으며, 실기기에 설치하지는 않았다.

초기 실행은 메모리 경합을 줄이기 위해 진행 중인 작업을 마친 뒤 정상 중단했다.
이때의 `Stopped build` 기록은 `build-resource-drain.log`에 보존했다. 이후 로컬
설정으로 `BB_NUMBER_THREADS = "4"`, `PARALLEL_MAKE = "-j4"`를 적용하여 같은
build ID로 재개했고, 최종 `build.log`는 전체 성공으로 종료됐다.

검증 원본 로그는 상위 저장소의 `.state/security-2026-10-10/`에 보존하며,
빌드 로그는 해당 build ID의 `artifacts/` 아래에 보존한다. 이 임시 실행
로그들은 Git에서 제외한다.

적용 레시피·패치의 SHA-256은 [레이어 입력 목록](scan-2026-10-10/layer-inputs.json)에
보존한다. 상위 저장소의 기존 미커밋 작업은 유지했으며, 소스 리비전만으로
이 빌드를 재현할 수 있다고 가정하지 않는다.

## 남은 확인과 범위

새 이미지 설치 후 Pi에서 부팅, HTTPS, Digest 인증, RTSPS SETUP/PLAY,
SRTP/SRTCP 및 카메라·Hailo 동작을 재검증해야 한다. 이번 수정 기록만으로
실기기 보안 회귀 테스트나 취약점 재현 테스트가 완료됐다고 주장하지 않는다.

커널·glibc·HailoRT 등 전체 이미지 구성 요소의 최신 CVE 전수 검사는 별도다.
이번 작업은 확인된 수정 가능 항목을 반영한 것이며 미검사 항목을 “안전”으로
종결하지 않는다. OpenSSL/PCRE2/SQLite/zlib/GLib의 CVE마다 실제 기능과 입력
조건이 달라, 해당 라이브러리 사용 자체를 원격 공격 가능성의 증거로 보지 않는다.

독립 검토에서 상속된 OE-Core SSA 자막 패치의 고정 크기 timestamp 버퍼에
길이 제한 없는 복사가 남는 점도 확인했다. 해당 `subparse` 플러그인은 기존
카메라 이미지 설치 목록에 없으며, 이번 완성 이미지에서도 미설치를 확인했다.
향후 `gstreamer1.0-plugins-base-subparse`를 포함할 때는 이 downstream
패치를 먼저 수정하거나 제거해야 한다. 1.28.8 적용을 모든 downstream
코드의 안전성 보장으로 해석하지 않는다.

Yocto image SPDX는 패키지·패치 증거로 보존하되 새로운 취약점 DB를 조회한
검사 결과와 구분한다. 이 OE-Core는 `sbom-cve-check` 방식을 사용한다.
기존 Debian `scan_debian.py` 결과나 빌드 PC의 `ldd`/`dpkg`를 Yocto 이미지의
전수 검사 결과로 사용하지 않는다.

## 공식 출처

- GStreamer: [SA-0082](https://gstreamer.freedesktop.org/security/sa-2026-0082.html),
  [SA-0084](https://gstreamer.freedesktop.org/security/sa-2026-0084.html),
  [SA-0091](https://gstreamer.freedesktop.org/security/sa-2026-0091.html),
  [SA-0074](https://gstreamer.freedesktop.org/security/sa-2026-0074.html),
  [SA-0030](https://gstreamer.freedesktop.org/security/sa-2026-0030.html),
  [SA-0047](https://gstreamer.freedesktop.org/security/sa-2026-0047.html).
- [OpenSSL 3.5 보안 릴리스](https://openssl-library.org/news/openssl-3.5-notes/).
- PCRE2: [CVE-2026-86145](https://github.com/PCRE2Project/pcre2/security/advisories/GHSA-3r4p-g7gg-ppmf),
  [CVE-2026-103111](https://github.com/PCRE2Project/pcre2/security/advisories/GHSA-r9hj-j2rw-4q3m).
- SQLite: [CVE 설명](https://sqlite.org/cves.html),
  [3.53.4 릴리스](https://sqlite.org/releaselog/3_53_4.html).
- [zlib 공식 수정](https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148).
- [GLib 공식 수정 및 회귀 테스트](https://github.com/GNOME/glib/commit/be85f9429bb66412a9775440a88cb115803ba897).
- [source-map-js advisory](https://github.com/advisories/GHSA-68fv-2mgg-jv7q).
- [CycloneDX 1.5 schema](https://github.com/CycloneDX/specification/blob/1.5/schema/bom-1.5.schema.json).
