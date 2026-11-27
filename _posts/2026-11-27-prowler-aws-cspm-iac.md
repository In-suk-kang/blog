---
title: "Prowler로 AWS CSPM 점검하고 Terraform으로 조치하기 (Before/After)"
date: 2026-11-27 16:00:00 +0900
categories: [Cloud Security, AWS]
tags: [aws, prowler, cspm, terraform, iac, isms-p, cis]
description: Terraform으로 만든 취약 AWS 환경을 Prowler로 점검하고 코드로 조치했다. Critical 5→3, High 18→9, CIS 준수율 36.9%→54.2%. 탐지 누락, 새 FAIL, 위험 수용까지 정리.
---

> **한 줄 요약**: Terraform으로 일부러 취약하게 만든 AWS 환경을 Prowler로 점검하고, 같은 코드로 고친 뒤 다시 점검했다. Critical FAIL은 5건에서 3건으로, High는 18건에서 9건으로 줄었고, CIS AWS 7.0 준수율은 36.9%에서 54.2%로 올랐다.

CSPM 도구를 한 번 돌려 보는 데서 그치지 않고, **취약 환경 구성 → 점검 → 코드로 조치 → 재점검**의 한 사이클을 직접 돌려 봤다. 정리해 보니 숫자보다 "결과를 어떻게 읽어야 하는가"에서 배운 게 더 많았다.

## 실습 개요

| 항목 | 내용 |
| --- | --- |
| 목적 | 클라우드 보안 형상 관리(CSPM) 점검과 IaC 기반 조치 사이클을 직접 수행 |
| 기간 | 2026년 11월 25일 ~ 27일 |
| 환경 | AWS 무료 플랜 계정 1개, 서울 리전(ap-northeast-2) |
| 도구 | Terraform 1.x, AWS CLI v2, Prowler CLI 5.52.0 |
| 점검 기준 | CIS AWS Foundations Benchmark 7.0, KISA ISMS-P 2023 |
| 비용 | 약 $0 (EBS 1GiB 월 약 $0.08 외 무료 범위) |

> 계정 번호 등 식별 정보는 마스킹했다.

## 실습 환경과 아키텍처

환경을 바꾸는 계정과 점검하는 계정을 분리했다. Terraform은 관리자 프로필로 리소스를 만들고, Prowler는 AWS 관리형 정책 `SecurityAudit`와 `ViewOnlyAccess`만 가진 전용 사용자로 설정을 **읽기만** 한다.

<!-- 이미지 필요: 실습 아키텍처 — 도구 2개, AWS 리소스 5영역 -->

각 리소스 상자의 두 번째 줄은 Before → After 상태다. 두 상태는 같은 Terraform 코드에서 `secure` 변수 하나로 전환한다.

## 취약 환경 설계

실무에서 자주 생기는 설정 오류 6개 영역을 골라 모두 Terraform 코드 하나로 만들었다. `terraform apply -var="secure=false"`면 취약한 상태가, `secure=true`면 조치된 상태가 배포된다. 콘솔에서 손으로 고치지 않고 코드로만 조치해서, 변경 내역이 코드 diff로 남도록 했다.

| 영역 | Before (secure=false) | After (secure=true) |
| --- | --- | --- |
| S3 계정 설정 | 계정 수준 퍼블릭 액세스 차단 4개 항목 모두 해제 | 모두 차단 |
| S3 버킷 | `Principal: "*"` 읽기 정책, 버전 관리 꺼짐 | 퍼블릭 차단, HTTPS 강제 정책, 버전 관리 |
| 보안 그룹 | 22·3389 포트 0.0.0.0/0 개방 | 22 포트를 관리자 IP/32에만 허용, default SG 규칙 제거 |
| EBS | 기본 암호화 꺼짐, 암호화 없는 1GiB 볼륨 | 기본 암호화 켜짐, 암호화 볼륨으로 교체 |
| IAM 사용자·정책 | AdministratorAccess와 `Action "*" / Resource "*"` 고객 관리형 정책을 사용자에게 직접 연결 | 정책 삭제, ReadOnly 그룹으로 권한 부여 |
| 비밀번호 정책 | 최소 6자, 복잡도·재사용 제한 없음 | 14자 이상, 대소문자·숫자·특수문자, 재사용 24회 금지, 90일 만료 |
| 로깅·분석 | CloudTrail, VPC Flow Logs, Access Analyzer 없음 | 멀티 리전 트레일(로그 무결성 검증), Flow Logs→S3, Access Analyzer |

일부러 취약하게 만드는 만큼 안전장치도 뒀다.

- 실습용 IAM 사용자에는 콘솔 비밀번호와 액세스 키를 만들지 않았다. 관리자 권한이 붙어 있어도 실제로는 쓸 수 없다.
- 퍼블릭 버킷에는 더미 파일만 넣었다.
- 비용이 드는 리소스(NAT Gateway, KMS 키 등)는 쓰지 않았다.

## Before 점검 결과

취약 환경을 점검하니 556개 점검 항목에서 **FAIL 83건, PASS 45건**이 나왔다. FAIL 중 Critical은 5건, High는 18건이고, 서비스별로는 IAM(31건), CloudWatch(15건), S3(13건) 순이었다.

그런데 FAIL이 모두 내가 의도한 취약점은 아니었다. Critical·High 23건을 원인별로 나눠 보면 다음과 같다.

| 분류 | 건수 | 대표 점검 항목 | 처리 방향 |
| --- | --- | --- | --- |
| 의도한 취약점 | 11 | `s3_bucket_public_access`, `iam_policy_allows_privilege_escalation`, `ec2_ebs_volume_encryption`, `cloudtrail_multi_region_enabled` | `secure=true`로 조치 |
| 실습 운영 계정 문제 | 7 | `iam_user_administrator_access_policy`(lab-admin), `iam_user_with_temporary_credentials`, `iam_avoid_root_usage` | 개선 방향만 정리 |
| 위험 수용 | 5 | `iam_root_hardware_mfa_enabled`, `ec2_networkacl_allow_ingress_any_port`, `organizations_scp_check_deny_regions` | 근거를 문서화 |

### 탐지되지 않은 취약점

가장 의외였던 건 **22·3389 포트를 0.0.0.0/0에 연 보안 그룹이 인터넷 개방 점검에 걸리지 않았다**는 점이다. `ec2_securitygroup_not_used`(Low)로만 잡혔다.

원인은 Prowler 기본 설정이었다. 기본값(`Scanning unused services and resources: False`)에서는 어떤 리소스에도 연결되지 않은 보안 그룹을 건너뛴다. 반면 같은 포트가 열린 기본 NACL은 `ec2_networkacl_allow_ingress_tcp_port_22`·`_3389`(Medium)로 탐지됐다.

지금 연결된 인스턴스가 없더라도, 나중에 누군가 이 보안 그룹을 붙이면 곧바로 노출되는 잠재 위험이다. **도구의 기본 점검 범위를 확인하지 않으면 이런 항목을 놓칠 수 있다.**

## 대표 취약점 분석

의도한 취약점 11건 중 위험도가 높고 성격이 다른 4개를 골랐다. 4개 모두 조치 후 재점검에서 PASS로 바뀌었다.

### 1. S3 버킷 퍼블릭 노출 (Critical)

| 항목 | 내용 |
| --- | --- |
| 점검 항목 | `s3_bucket_public_access` 외 연관 4건(계정·버킷 퍼블릭 차단, 교차 계정 접근, 버전 관리) |
| 관련 기준 | ISMS-P 2.6.1 네트워크 접근, 2.6.2 정보시스템 접근, 2.10.2 클라우드 보안 |
| 위험 시나리오 | 버킷 URL만 알면 인증 없이 객체를 내려받을 수 있다. 고객 데이터나 백업 파일이 있었다면 그대로 유출된다. |
| 직접 검증 | Before: `curl`로 객체 내용이 그대로 출력됨 / After: `AccessDenied` |
| 조치 | 계정·버킷 퍼블릭 차단 켜기, `Principal: "*"` 읽기 정책을 HTTPS 강제(Deny) 정책으로 교체 |

Before에서는 인증 없이 객체 내용이 그대로 출력됐다.

<!-- 이미지 필요: S3 Before — curl로 객체 내용이 출력됨 -->

After에서는 같은 요청이 `AccessDenied`로 차단됐다.

<!-- 이미지 필요: S3 After — AccessDenied -->

계정 수준 퍼블릭 차단은 `secure` 변수 하나로 켜고 끈다.

```hcl
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = var.secure
  ignore_public_acls      = var.secure
  block_public_policy     = var.secure
  restrict_public_buckets = var.secure
}
```

### 2. IAM 과도한 권한과 권한 상승 (Critical·High)

| 항목 | 내용 |
| --- | --- |
| 점검 항목 | `iam_user_administrator_access_policy`, `iam_policy_allows_privilege_escalation`, `iam_customer_attached_policy_no_administrative_privileges`, `iam_no_custom_policy_permissive_role_assumption` |
| 관련 기준 | ISMS-P 2.5.1 사용자 계정 관리, 2.5.5 특수 계정 및 권한 관리, 2.5.6 접근권한 검토 |
| 위험 시나리오 | 이 사용자의 자격 증명이 유출되면 계정 전체를 장악할 수 있다. Prowler는 `*:*` 정책에 대해 권한 상승에 쓸 수 있는 구체적인 API 목록까지 제시했다. |
| 조치 | 고객 관리형 정책 삭제, 관리자 정책 분리, ReadOnlyAccess 그룹을 통해 권한 부여 |

눈에 띈 건 **정책 1개가 FAIL 6건(High 3, Medium 3)을 동시에 만들었다**는 점이다. 과도한 정책 하나가 여러 위험으로 번진다.

### 3. EBS 미암호화 (High)

| 항목 | 내용 |
| --- | --- |
| 점검 항목 | `ec2_ebs_volume_encryption`, `ec2_ebs_default_encryption` |
| 관련 기준 | ISMS-P 2.7.1 암호정책 적용 |
| 위험 시나리오 | 볼륨이나 스냅샷이 잘못 공유되면 데이터가 평문으로 노출된다. |
| 조치 | 계정 단위 EBS 기본 암호화를 켜고 암호화 볼륨으로 교체 |
| 결과 | ISMS-P 2.7.1이 FAIL에서 PASS(6건)로 전환 |

기존 볼륨은 암호화 설정을 바꿀 수 없어서 Terraform이 삭제 후 재생성(`-/+`)했다. 운영 환경이라면 데이터 이전 계획이 먼저 필요한 부분이다.

### 4. CloudTrail 미설정 (High)

| 항목 | 내용 |
| --- | --- |
| 점검 항목 | `cloudtrail_multi_region_enabled` |
| 관련 기준 | CIS AWS 7.0 4.1, ISMS-P 2.9.4 로그 및 접속기록 관리, 2.10.1 보안시스템 운영 |
| 위험 시나리오 | 침해가 발생해도 누가 언제 어떤 API를 호출했는지 추적할 수 없다. 침해 대응의 출발점이 없는 상태다. |
| 조치 | 멀티 리전 트레일 생성, 로그 파일 무결성 검증 켜기, 전용 로그 버킷에 저장 |
| 결과 | 멀티 리전·무결성 검증 모두 PASS |

단, 트레일이 생기면서 KMS 암호화 같은 새 점검 항목이 생겼다. 이건 바로 다음에서 다룬다.

## After 결과와 비교

조치 후 Critical·High FAIL은 **23건에서 12건**으로 줄었고, 의도한 취약점 11건은 모두 해소됐다. 조치 전에 예상한 값(Critical 3, High 9)과 실제 결과도 일치했다.

<!-- 이미지 필요: Before/After 스캔 결과 비교 — prowler-before.csv, prowler-after.csv -->

| 지표 | Before | After | 변화 |
| --- | --- | --- | --- |
| 전체 PASS 비율 | 34.4% (PASS 45 / FAIL 83) | 52.7% (PASS 79 / FAIL 68) | +18.3%p |
| CIS AWS 7.0 준수율 | 36.9% (PASS 24 / FAIL 41) | 54.2% (PASS 39 / FAIL 33) | +17.3%p |
| ISMS-P 2023 준수율 | 35.2% | 53.7% | +18.5%p |

ISMS-P 항목 중 **2.5.4 비밀번호 관리**, **2.6.2 정보시스템 접근**, **2.7.1 암호정책 적용**은 FAIL이 모두 사라졌다.

### 조치했는데 FAIL이 새로 생긴 이유

Before FAIL 중 28건이 해소됐지만(PASS 전환 15건, 리소스 삭제·교체 13건), After에서는 FAIL 14건이 새로 생겼다. 전부 조치하면서 새로 만든 리소스에서 나왔고, High 1건을 빼면 Medium·Low다.

| 새로 만든 리소스 | 새 FAIL | 내용 |
| --- | --- | --- |
| 로그 저장 S3 버킷 | 7 | KMS 암호화, MFA Delete, 서버 접근 로깅, Object Lock, 수명주기, 이벤트 알림, 교차 리전 복제 |
| CloudTrail 트레일 | 5 | KMS 암호화, CloudWatch Logs 연동, Insights, 로그 버킷 접근 로깅, MFA Delete |
| 교체된 EBS 볼륨 | 2 | 스냅샷 없음(High), 백업 플랜 없음 |

**보안 기능을 추가하면 그 기능 자체도 점검 대상이 된다.** 그래서 FAIL 건수만으로는 개선 정도를 판단할 수 없고, 심각도별 변화와 준수율을 함께 봐야 한다. ISMS-P 2.7.2 암호키 관리가 1건에서 3건으로 늘어난 것도 KMS를 쓰지 않기로 한 결정이 새 리소스에서 드러난 결과다.

## 남은 항목과 위험 수용

After에 남은 Critical·High 12건은 실습 운영 계정 문제 7건과, 의도적으로 조치하지 않은 항목 5건이다. 가장 큰 발견은 **점검을 위해 만든 관리자 계정 lab-admin이 스스로 Critical 위험이 됐다**는 점이다.

### 실습 운영 계정 문제 (7건)

| 심각도 | 점검 항목 | 대상 | 개선 방향 |
| --- | --- | --- | --- |
| Critical | `iam_user_administrator_access_policy` | lab-admin | 관리자 그룹으로 이동, 사용자에게 직접 연결 제거 |
| Critical | `iam_aws_attached_policy_no_administrative_privileges` | AdministratorAccess | 관리자 역할을 MFA 조건부 AssumeRole로만 사용 |
| High | `iam_user_with_temporary_credentials` | lab-admin, prowler-scanner | 장기 액세스 키 대신 IAM Identity Center나 역할 기반 임시 자격 증명 |
| High | `iam_user_hardware_mfa_enabled` | lab-admin, prowler-scanner | 최소한 가상 MFA 적용 |
| High | `iam_avoid_root_usage` | root | 초기 설정 이후 루트 로그인 중단 |

실무에서도 자동화·운영 계정이 가장 큰 권한을 가진 채 장기 키로 방치되는 경우가 많다. 점검 도구가 점검 대상이 아니라 **점검을 위해 만든 계정**을 위험으로 잡아낸 셈이다.

### 위험 수용 (5건)

| 심각도 | 점검 항목 | 수용 근거 |
| --- | --- | --- |
| Critical | `iam_root_hardware_mfa_enabled` | 루트에는 가상 MFA가 적용돼 있다. 하드웨어 키는 구매 비용이 든다. |
| High | `iam_user_hardware_mfa_enabled` (실습용 사용자) | 콘솔 비밀번호·액세스 키가 없어 로그인할 수 없는 계정이다. |
| High | `ec2_networkacl_allow_ingress_any_port` | 기본 VPC의 기본 NACL이다. 트래픽은 보안 그룹으로 통제한다. |
| High | `ec2_ebs_volume_snapshots_exists` | 데이터가 없는 실습용 빈 볼륨이다. |
| High | `organizations_scp_check_deny_regions` | Organizations에 가입하면 무료 플랜이 유료로 전환된다. |

Medium·Low에도 비용 때문에 남긴 항목이 있다. CloudWatch 경보 15건은 CloudTrail을 CloudWatch Logs로 보내야 하고, KMS 암호화는 키당 월 약 $1, AWS Config·Backup은 사용량 과금이 있어서 실습 범위에서 뺐다. 운영 환경이라면 가장 먼저 적용할 항목들이다.

## 트러블슈팅

실습 중 막혔던 문제 4건이다. 그중 시간 오차 문제는 ISMS-P 2.9.6 시간 동기화 통제가 왜 필요한지 몸으로 겪은 사례였다.

| 증상 | 원인 | 해결 |
| --- | --- | --- |
| `apt install terraform`이 `Unable to locate package`로 실패 | Ubuntu 기본 저장소에는 Terraform이 없고, HashiCorp 저장소를 등록하지 않았다 | `snap install terraform --classic`으로 설치 |
| `terraform plan`에서 `Inconsistent conditional result types` | 조건식의 두 결과(버킷 정책 객체)의 구조가 달랐다. 한쪽에만 `Condition`이 있었다 | 각 정책을 먼저 `jsonencode()`로 문자열로 바꾼 뒤 조건식에서 선택 |
| `SignatureDoesNotMatch: Signature expired` (STS 403) | VMware VM의 시계가 AWS 서버보다 약 25분 늦었다. AWS는 서명 시각이 15분 넘게 차이 나면 요청을 거부한다 | 재부팅과 NTP 동기화(`timedatectl set-ntp true`), VMware 호스트 시간 동기화 설정 |
| `prowler -v`에서 pydantic `ConfigError` | 시스템 Python이 3.14라 호환되는 최신 Prowler가 설치되지 않고, 오래된 버전이 설치됐다 | uv로 Python 3.12 환경을 따로 만들어 설치(`uv tool install --python 3.12 prowler`) |

## 배운 점

CSPM 도구는 설정 오류를 빠르게 찾아 주지만, 결과를 제대로 읽으려면 점검 범위와 맥락을 사람이 해석해야 한다.

- **FAIL 건수보다 심각도와 준수율을 봐야 한다.** 보안 기능을 추가하면 그 기능도 점검 대상이 돼서 FAIL이 새로 생긴다.
- **도구의 기본 점검 범위를 알아야 한다.** 연결되지 않은 보안 그룹의 전체 개방은 기본 설정에서 건너뛰어졌다.
- **운영 계정도 점검 대상이다.** 점검을 위해 만든 관리자 계정이 Critical로 잡혔다.
- **조치는 코드로 해야 재현할 수 있다.** 변수 하나로 Before/After를 몇 번이든 되돌리고 다시 검증할 수 있었다.
- **조치하지 않는 것도 결정이다.** 비용과 범위를 근거로 위험 수용 항목을 문서화했다.

## 다음에 해 볼 것

- `prowler aws --scan-unused-services`로 재점검해서 보안 그룹 개방이 탐지되는지 확인
- lab-admin을 IAM Identity Center 기반 임시 자격 증명으로 전환하고 운영 계정 FAIL 재점검
- CloudTrail 로그에서 `PutBucketPolicy`, `AuthorizeSecurityGroupIngress` 등을 추적해 설정 변경 주체 식별
- Cartography로 AWS 자산과 권한 관계를 Neo4j 그래프로 적재해 위험 경로 분석
- GitHub Actions에서 `terraform plan` 후 Prowler를 자동 실행하는 파이프라인 구성

다음 글에서는 `--scan-unused-services` 재점검 결과부터 정리해 볼 예정이다.
