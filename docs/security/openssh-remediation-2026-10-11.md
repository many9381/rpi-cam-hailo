# OpenSSH 보안 후속 조치 — 2026-10-11

**2026-10-12 후속:** 새 이미지의 실제 설치·SSH·재부팅 3회와 웹 영상·Hailo
추론 확인을 완료했다. [설치·부팅 검증 기록](openssh-deployment-validation-2026-10-12.md)을
참조한다. 아래의 설치 대기 문구는 10월 11일 빌드 완료 당시의 상태다.

전체 이미지 CVE 검사에서 남았던 OpenSSH 후보를 검토하고 Yocto의 OpenSSH를
**10.3p1 → 10.6p1**로 올렸다. 최종 Hailo 이미지
`20261011T190155Z-e664cb9647e7`의 빌드·WIC 검사와 Pi의 별도 시험 프로세스
검증을 완료했다. **새 이미지의 SSD 설치·부팅 검증은 아직 하지 않았다.**

현재 운영 Pi는 RTSP 수정 이미지 `20261011T180648Z-e664cb9647e7`과
OpenSSH 10.3p1을 유지한다. 시험 중 운영 sshd, 계정, SSH 키, 앱 설정은
교체하지 않았다. 이전 RTSP 검증 결과는 해당 이미지의 별도 기록으로 유지한다.

## Layer 및 검증 스크립트 변경

- `meta-rpi5-cam/recipes-connectivity/openssh/openssh_10.3p1.bbappend`에서
  `PV`와 소스 SHA-256을 고정했다. 파일명의 10.3p1은 고정된 OE-Core의 기본
  레시피에 연결하기 위한 이름이며, 실제 빌드·설치 버전은 10.6p1이다.
- 공식 portable tarball을 사용하고 기존 OE-Core 패치·서비스·패키지 구성을
  유지했다. 소스 SHA-256은
  `a9dc9565dffe8640f64d863cd29a32bc4a3dbdec0566a7fc44c5d6ee767d5f39`이며,
  공식 발표의 Base64 체크섬을 디코딩한 값과 일치한다. 라이선스 파일 MD5도
  기존 레시피와 같다.
- Red Hat 전용 변경에 해당하는 CVE 3개에만 `CVE_STATUS`를 추가했다.
  나머지 항목을 포괄적으로 무시하는 설정은 없다.
- 새 `sshd -T`는 지시어를 `PasswordAuthentication` 같은 대소문자로 출력한다.
  `scripts/test-rpi5.sh`, `scripts/test-qemu-guest.sh`의 지시어 비교만
  `tolower($1)`로 바꾸고 값 비교와 중복 `AuthenticationMethods` 거부는
  유지했다. QEMU 스크립트의 호환성 수정이며 QEMU 이미지를 빌드하지 않았다.
- `tests/host/test_sshd_policy.py`는 실제 스크립트의 awk 필터를 실행한다.
  기존 소문자·새 대소문자 출력, 누락·중복 인증 지시어, 추가 인증 방식과
  값의 대소문자 보존을 검사한다. 수정 전 실패, 수정 후 통과를 확인했다.

10.6p1은 2026-10-06 발표된 버전이다. 버전·보안 변경의 1차 근거는
[공식 10.6 발표](https://www.openssh.org/txt/release-10.6),
[10.5 발표](https://www.openssh.org/txt/release-10.5),
[10.4 발표](https://www.openssh.org/txt/release-10.4)다.

## 이전 후보 25개 판정

아래는 기존 10.3p1의 원시 검사 후보를 추적한 결과다. 후보 수는 실제 공격이
성공하는 취약점 수와 다르다. GSSAPI는 이 이미지에서 컴파일되지 않으며,
SSH 압축과 터널은 기존에도 꺼져 있다. 모든 CVE를 개별 exploit으로 재현한
것은 아니다.

| CVE | 관련 경로 | 최종 판정 |
| --- | --- | --- |
| CVE-2026-59995 | SFTP 다운로드 경로 | 10.4 수정 포함 |
| CVE-2026-59996 | SCP 원격 간 복사 경로 | 10.4 수정 포함 |
| CVE-2026-59997 | internal-sftp 인자 수 | 10.4 수정 포함 |
| CVE-2026-59998 | GSSAPI StrictAcceptorCheck | 10.4 수정 포함 |
| CVE-2026-59999 | DisableForwarding/PermitTunnel | 10.4 수정 포함 |
| CVE-2026-60000 | GSSAPI 인증 시도 제한 | 10.4 수정 포함 |
| CVE-2026-60001 | 최소 인증 지연 | 10.4 수정 포함 |
| CVE-2026-60002 | 클라이언트 호스트 키 재협상 UAF | 10.4 수정 포함 |
| CVE-2026-73281 | ssh-agent 잠금·세션 바인딩 | 10.5 수정 포함 |
| CVE-2026-73282 | 원격 포워딩 재할당 UAF | 10.5 수정 포함 |
| CVE-2026-73283 | restrict의 터널 제한 | 10.5 수정 포함 |
| CVE-2026-106552 | SFTP 재귀 복사 경로 | 10.6 수정 포함 |
| CVE-2026-106553 | GSSAPI 실패 후 자격 정보 유지 | 10.6 수정 포함 |
| CVE-2026-106555 | GSSAPI 인증 상태 유지 | 10.6 수정 포함 |
| CVE-2026-106582 | SSH 압축의 채널 간 정보 노출 | 10.6 수정 포함 |
| CVE-2026-106583 | 명령행 사용자 이름의 셸 특수문자 | 10.6 수정 포함, Pi에서 변경 전후 확인 |
| CVE-2026-106584 | 인증서 유효기간의 DST 처리 | 10.6 수정 포함 |
| CVE-2026-106585 | 압축 해제 후 패킷 길이 | 10.6 수정 포함 |
| CVE-2026-106586 | restrict의 추가 터널 제한 문제 | 10.6 수정 포함 |
| CVE-2026-106587 | Match 구문의 `none` 처리 | 10.6 수정 포함 |
| CVE-2026-55653 | Red Hat FIPS DH-GEX 패치 | 해당 없음: 그 배포판 패치 미포함 |
| CVE-2026-55654 | Red Hat GSSAPI auth-indicators 패치 | 해당 없음: 그 배포판 패치 미포함 |
| CVE-2026-55655 | Red Hat abstract X11 소켓 패치 | 해당 없음: 그 배포판 패치 미포함 |
| CVE-2026-106588 | macOS 27 SDK sandbox 제거 | 해당 없음: Linux seccomp 빌드 |
| CVE-2026-106589 | FD 전달을 지원하지 않는 플랫폼의 권한 | 해당 없음: Linux FD 전달 지원 빌드 |

Red Hat CNA는 [55653](https://access.redhat.com/security/cve/CVE-2026-55653),
[55654](https://access.redhat.com/security/cve/CVE-2026-55654),
[55655](https://access.redhat.com/security/cve/CVE-2026-55655)를 downstream
전용으로 명시한다. 공식 portable 소스와 적용 패치 목록에도 해당 변경이 없다.

플랫폼 2건은 단순 버전 비교로 종결하지 않았다. 실제 `config.h`에서
`SANDBOX_SECCOMP_FILTER=1`, `HAVE_SENDMSG=1`, `HAVE_RECVMSG=1`이며,
`SANDBOX_DARWIN`, `DISABLE_FD_PASSING`, `USE_PIPES`는 정의되지 않았다.
커널도 `CONFIG_SECCOMP=y`, `CONFIG_SECCOMP_FILTER=y`다. macOS SDK나
QNX/SCO의 해당 실행 경로가 이 Linux 이미지에 포함되지 않는 근거다.

## 최종 이미지 재검사와 한계

최종 이미지의 SPDX와 설치 manifest를 대상으로 `sbom-cve-check 1.3.5`를
다시 실행했다. 당일 고정 NVD/FKIE·CVEList 스냅샷, 검증된 SQLite 어댑터,
원시 보고서, 도구·DB·입력 해시를 보존했다. 스냅샷 이후 공개된 모든 정보를
포함하는 실시간 검사라는 뜻은 아니다. 공식 릴리스와 CNA 근거는 당일 별도로
확인하고 원본을 보존했다.

- OpenSSH 원시 미해결 후보: **25 → 0**.
- 이전 25건에 대한 검토 판정: **버전 수정 20건, 해당 없음 5건**.
- 원시 스캐너는 플랫폼 2건도 `fixed`로 출력한다. `10.6p1`과 `10.6`의 버전
  비교만으로 수정됐다고 단정하지 않고 별도 overlay에 위 플랫폼 근거를 남겼다.
  원시 CSV·JSON은 수정하지 않았다.
- 이미지 전체에는 원시 미해결 연결 **4,825건**이 남는다. 이 중 커널 외
  연결은 **190건**이다. 이는 설치 레시피와 CVE의 버전 기반 연결 수이며,
  실제 취약점 수·공격 가능성 판정 또는 전체 보안 승인 결과가 아니다.
  커널·FFmpeg·curl 등의 후속 검토는 계속 필요하다.

## 실행한 검증

| 검증 | 결과 및 범위 |
| --- | --- |
| OpenSSH Yocto 컴포넌트 | 컴파일·패키징·QA 통과, 1,618 tasks |
| 최종 Hailo 이미지 | 7,786 tasks 성공, 이 중 7,750 cached |
| 호스트 테스트 | **365개 통과** |
| 명령행 사용자 이름 | 기존 10.3p1은 `audit$probe` 허용, 새 10.6p1은 거부. `ssh -G`만 실행하여 네트워크 연결·명령 실행 없음 |
| Pi upstream 단위 시험 | **13개 suite 통과**, `-f` fast 모드. 전체 slow/fuzz 시험은 미실행 |
| Pi upstream 기능 시험 | **7개 suite 통과**: connect, proxy-connect, rekey, key-options, servcfginclude, cfgmatch, sftp |
| 유효 보안 설정 | 새 바이너리의 `sshd -T`로 이미지 설정을 읽어 키 인증 전용, 비밀번호·키보드 인증·root 로그인 금지, rpiadmin 한정 확인 |
| WIC 내용 | 설치 OpenSSH 패키지 10.6p1, SSH·SCP·sshd·인증/세션 helper·keygen·SFTP server의 해시가 시험한 패키지와 일치 |
| 기존 이미지 기능 구성 | 카메라·Wi-Fi·팬 모듈·Hailo 모델·Codex 구성, 초기 시각 서비스 순서, RTSP 수정 라이브러리·앱·개발용 소스 확인 |
| 무결성 | 산출물 체크섬, 빌드 입력 provenance, 실제 WIC의 이미지 ID·서비스·SSH 설정 검사 통과 |
| 검토 | 독립 검토에서 발견한 설정 출력 호환성 문제 수정 후 재검토 완료 |
| 운영 Pi 보존 | 시험 후 같은 부팅·앱 프로세스, 앱 재시작 0회, HTTPS 정상, 기존 SSH 10.3p1 유지 |

시험용 새 서버는 rpiadmin의 별도 디렉터리에서 실행했으며, TCP 시험 리스너는
loopback 전용이었다. `sshd -i` 프록시 실행도 함께 검사했다. 운영 서비스의
root 권한 시작·socket activation·새 이미지 재부팅까지 검증한 것은 아니다.
설정 검사에서는 읽을 수 없는 운영 호스트 키 대신 시험 키를 사용하고 이미지의
drop-in을 펼쳤다. 인증 정책 값은 기존 운영 `sshd -T` 결과와 일치했다.

UTF-8 suite는 처음에 `en_US.UTF-8` 부재로 실패했다. 같은 Yocto glibc의 로케일을
시험 디렉터리에만 복사하고 `LOCPATH`로 지정한 뒤 34개 내부 검사를 통과했다.
기능 시험 첫 connect 실패는 시험용 `obj/netcat`, `obj/timestamp` 링크 누락이었다.
이미 cross-build된 upstream helper에 연결한 뒤 7개 suite를 다시 실행했다.
초기 실패 로그도 보존하며 제품 코드나 운영 이미지에 로케일·시험 도구를 추가하지
않았다. 시험 디렉터리·시험 키를 삭제하고 리스너와 시험 프로세스 부재를 확인했다.

## 증거 및 다음 단계

작업 원본은 Git 제외 `.state/openssh-remediation-2026-10-11/`에 있다.
최종 이미지 아래 `security/`에 다음을 보존한다.

- `host-image-verification.json`, `host-image-checksums.log`: 실제 WIC 검사.
- `cve-scan/`: 원시 검사, 입력 SPDX·manifest, 메타데이터,
  `openssh-triage-overlay.json`.
- `scanner-evidence/`, `configuration-evidence/`: 재현용 검사 도구와 설정 근거.
- `openssh-remediation/`: 선정한 시험·빌드·소스·검토 기록과 SHA-256 목록.

새 이미지 배포는 등록 SSD를 빌드 PC에 연결한 뒤 기존
`./scripts/install-ssd.sh`로 진행한다. 설치는 SSD 내용을 다시 기록한다.
그 후 새 이미지의 SSH 접속·부팅 자동 실행·웹 영상·Hailo 추론을 확인해야 한다.
현재 설치된 RTSP 이미지의 로그인된 Hailo 화면 확인도 아직 미확인으로 유지한다.
이번 작업에서 QEMU/minimal 이미지를 생성하거나 새 이미지의 hardware/release
PASS를 발급하지 않았다.
