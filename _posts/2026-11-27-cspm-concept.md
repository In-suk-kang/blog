---
title: "CSPM이란? 클라우드 설정 오류를 잡는 도구와 CWPP·CIEM·CNAPP와의 차이"
date: 2026-11-27 17:40:00 +0900
categories: [개념, Cloud Security]
tags: [cspm, cnapp, cwpp, ciem, cloud-security, shared-responsibility, aws]
description: CSPM(클라우드 보안 형상 관리)이 무엇이고 왜 필요한지, 어떻게 동작하는지, CWPP·CIEM·CNAPP와는 무엇이 다른지 정리했다.
---

> **한 줄 정의**: CSPM(Cloud Security Posture Management, 클라우드 보안 형상 관리)은 클라우드 계정의 **설정 오류와 규정 위반을 지속적으로 찾아내고 고치는** 도구이자 과정이다.

지난 글 [Prowler로 AWS CSPM 점검하고 Terraform으로 조치하기]({{ '/posts/prowler-aws-cspm-iac/' | relative_url }})에서 CSPM 도구를 직접 돌려 봤다. 이번에는 한 발 물러서서, CSPM이 정확히 무엇을 하는 도구인지, 비슷한 약어들(CWPP, CIEM, CNAPP)과는 어떻게 다른지 정리해 본다.

## CSPM이란

CSPM은 Gartner가 이름 붙인 클라우드 보안 도구 분류 중 하나다. Gartner는 CSPM을 IaaS와 PaaS의 보안 형상을 **예방·탐지·대응을 통해 지속적으로 관리하는** 솔루션으로 정의한다. 여기서 "형상(posture)"은 클라우드 리소스가 지금 어떻게 설정되어 있는지를 말한다.

쉽게 말하면 이런 질문에 자동으로 답해 주는 도구다.

- 인터넷에 공개된 S3 버킷이 있는가?
- 0.0.0.0/0에 SSH(22) 포트를 연 보안 그룹이 있는가?
- 암호화되지 않은 디스크나 데이터베이스가 있는가?
- CloudTrail 같은 감사 로그가 꺼져 있지 않은가?
- 루트 계정에 MFA가 걸려 있는가?
- 이 설정들이 CIS Benchmark, ISMS-P 같은 기준에 맞는가?

## 왜 필요한가: 클라우드 사고의 대부분은 "설정 실수"

### 공동 책임 모델

클라우드 보안은 **공동 책임 모델(Shared Responsibility Model)** 위에서 돌아간다. AWS, Azure, GCP 모두 비슷한 모델을 공개하고 있는데, 핵심은 한 문장이다.

| 책임 주체 | 범위 | 예시 |
| --- | --- | --- |
| 클라우드 사업자 | 클라우드 **자체**의 보안 (Security **of** the Cloud) | 데이터센터, 물리 서버, 하이퍼바이저, 글로벌 네트워크 |
| 고객 | 클라우드 **안**의 보안 (Security **in** the Cloud) | IAM 권한, 보안 그룹, 버킷 정책, 암호화 설정, 데이터 |

즉 AWS가 아무리 튼튼한 인프라를 제공해도, **버킷을 퍼블릭으로 여는 설정은 고객이 한 것**이고 그 책임도 고객에게 있다. 그런데 이 경계를 정확히 이해하지 못해서 "클라우드니까 알아서 안전하겠지"라고 생각하는 경우가 많고, 이것이 설정 오류의 주요 원인으로 꼽힌다.

### 설정 오류가 사고로 이어진다

Gartner는 클라우드 서비스에 대한 공격 성공 사례의 거의 전부가 **고객 측의 설정 오류, 관리 부실, 실수**에서 비롯된다고 봤다. Verizon DBIR 2021에서도 설정 오류는 해킹 다음으로 많은 데이터 유출 원인이었다.

대표적인 사례가 2019년 Capital One 유출 사고다. 미국 법원 기소장에 따르면 사고는 WAF의 설정 오류에서 시작됐다. 공격자는 SSRF로 WAF에 붙은 IAM 역할의 자격 증명을 얻었고, 그 역할이 700개가 넘는 S3 버킷에 접근할 수 있었기 때문에 1억 명 이상의 고객 정보가 유출됐다. WAF에 필요 이상의 S3 권한이 붙어 있었다는 점, 즉 **설정과 권한의 문제**가 피해를 키웠다.

### 사람이 다 볼 수 없다

클라우드 환경은 계정, 리전, 서비스가 많고 변화가 빠르다. 개발자가 콘솔이나 코드로 리소스를 수시로 만들고 바꾸기 때문에, 보안 담당자가 설정을 하나하나 눈으로 검토하는 방식은 금방 한계에 부딪힌다. 그래서 **설정을 API로 읽어 와 기준과 자동으로 비교하는** 도구가 필요해졌다.

## CSPM은 어떻게 동작하는가

대부분의 CSPM은 에이전트를 설치하지 않고, **클라우드 API로 설정 정보를 읽는** 방식으로 동작한다.

| 단계 | 하는 일 | Prowler 실습에서의 예 |
| --- | --- | --- |
| 1. 연결 | 읽기 전용 권한으로 클라우드 계정에 접근 | `SecurityAudit` + `ViewOnlyAccess`만 가진 전용 사용자 |
| 2. 자산 수집 | 계정 안의 리소스와 설정을 API로 수집 | S3, EC2, IAM, CloudTrail 등 설정 조회 |
| 3. 정책 평가 | 수집한 설정을 점검 규칙과 비교 | 556개 점검 항목을 PASS/FAIL로 판정 |
| 4. 기준 매핑 | 결과를 컴플라이언스 기준에 연결 | CIS AWS 7.0, ISMS-P 2023 준수율 산출 |
| 5. 우선순위화 | 심각도와 노출 여부로 정렬 | Critical·High부터 분석 |
| 6. 조치 | 수동·자동으로 수정하고 재점검 | Terraform 코드로 조치 후 재스캔 |

핵심은 **한 번 점검하고 끝나는 게 아니라 계속 돌린다**는 점이다. 오늘 깨끗했던 계정도 내일 누군가 보안 그룹 하나를 열면 바로 위험해진다. Gartner가 CSPM을 "지속적인 개선과 적응의 과정"이라고 표현한 이유도 여기에 있다.

### CSPM이 주로 찾는 것

| 영역 | 대표 점검 항목 |
| --- | --- |
| 스토리지 | 퍼블릭 버킷, 버킷 정책의 `Principal: "*"`, 버전 관리·암호화 미설정 |
| 네트워크 | 0.0.0.0/0에 열린 관리 포트(22, 3389), 기본 보안 그룹 사용 |
| 계정·권한 | 루트 계정 사용, MFA 미설정, 과도한 권한(`*:*`), 오래된 액세스 키 |
| 암호화 | 디스크·DB·스냅샷 암호화 미설정, 키 관리 |
| 로깅·모니터링 | CloudTrail·VPC Flow Logs 미설정, 로그 무결성 검증 꺼짐 |
| 컴플라이언스 | CIS, NIST, PCI DSS, ISMS-P 등 기준별 준수율 |

## CSPM이 못 하는 것

CSPM은 **"설정"을 보는 도구**다. 그래서 다음은 CSPM만으로는 잡기 어렵다.

- **워크로드 내부 위협**: EC2 안에서 돌고 있는 악성코드, 컨테이너 이미지의 취약한 패키지, 런타임 공격
- **실제 공격 행위**: 설정은 정상인데 유출된 키로 들어온 공격자의 행동 (이건 CloudTrail·GuardDuty 같은 탐지 영역)
- **권한의 실제 사용 여부**: 정책 문서상 권한은 보지만, 그 권한이 실제로 쓰이는지, 누가 어떤 경로로 어디까지 갈 수 있는지는 깊게 보지 못한다
- **점검 범위 밖의 리소스**: 도구 설정에 따라 일부 리소스를 아예 건너뛰기도 한다. Prowler 실습에서 연결되지 않은 보안 그룹의 전체 개방이 기본 설정에서 탐지되지 않았던 것이 그 예다

이 빈틈을 메우기 위해 다른 분류의 도구들이 생겼다.

## CWPP, CIEM, CNAPP와의 차이

이 약어들도 모두 Gartner가 시장을 분류하면서 붙인 이름이다. 무엇을 보느냐로 구분하면 이해하기 쉽다.

| 분류 | 풀네임 | 무엇을 보는가 | 대표 질문 |
| --- | --- | --- | --- |
| **CSPM** | Cloud Security Posture Management | 클라우드 **설정** (컨트롤 플레인) | "이 버킷이 공개돼 있나?" |
| **CWPP** | Cloud Workload Protection Platform | **워크로드** 내부 (VM, 컨테이너, 서버리스) | "이 컨테이너에 취약한 패키지나 악성 프로세스가 있나?" |
| **CIEM** | Cloud Infrastructure Entitlement Management | **권한(Identity)** | "이 역할이 실제로 쓰지 않는 과도한 권한을 갖고 있나?" |
| **CNAPP** | Cloud-Native Application Protection Platform | 위 전부를 **하나로 통합** | "이 설정 오류 + 취약점 + 과도한 권한이 이어지면 공격 경로가 되나?" |

조금 더 풀어 보면 이렇다.

- **CSPM vs CWPP**: CSPM이 "집의 문과 창문이 잠겨 있는지"를 본다면, CWPP는 "집 안에 누가 들어와 무엇을 하고 있는지"를 본다. 둘은 경쟁 관계가 아니라 보완 관계다.
- **CIEM**: 클라우드 사고의 상당수가 권한 문제라서 따로 떨어져 나왔다. CSPM도 `*:*` 같은 명백한 과도 권한은 잡지만, CIEM은 실제 사용 기록과 비교해 **최소 권한**에 맞게 줄이는 데 집중한다. Capital One 사례처럼 "WAF 역할에 S3 권한이 왜 필요한가"를 묻는 영역이다.
- **CNAPP**: CSPM, CWPP, CIEM에 IaC 스캔 등 배포 전 점검까지 묶은 통합 플랫폼이다. 각각의 결과를 **연결해서** 보여 준다는 점이 핵심이다. 예를 들어 "인터넷에 열린 EC2(설정) + 그 위의 치명적 취약점(워크로드) + 그 EC2에 붙은 관리자 역할(권한)"을 하나의 공격 경로로 묶어 우선순위를 매긴다.

요즘 상용 제품은 대부분 CNAPP를 표방하고, CSPM은 그 안의 기본 구성 요소로 들어가 있다.

## 실무에서 쓰는 CSPM 도구

| 종류 | 도구 | 특징 |
| --- | --- | --- |
| 클라우드 기본 제공 | AWS Security Hub CSPM | AWS 기본 CSPM. 2025년 6월 기존 Security Hub가 이 이름으로 바뀌었고, "Security Hub"라는 이름은 탐지 결과를 통합·연관 분석하는 새 서비스가 가져갔다 |
| 클라우드 기본 제공 | Microsoft Defender for Cloud, Google Security Command Center | 각 클라우드의 기본 형상 관리 기능 |
| 오픈소스 | Prowler | AWS·Azure·GCP·Kubernetes 지원, CIS·ISMS-P 등 다양한 기준 매핑 |
| 오픈소스 | ScoutSuite, Steampipe | 멀티 클라우드 설정 점검과 SQL 기반 조회 |
| 상용 CNAPP | Wiz, Prisma Cloud, CrowdStrike Falcon Cloud Security 등 | CSPM을 포함한 통합 플랫폼 |

AWS에서 "Security Hub"를 검색하면 두 서비스가 나와서 헷갈릴 수 있다. CSPM 기능을 찾는다면 **Security Hub CSPM** 쪽을 보면 된다.

## 자주 헷갈리는 점

- **"CSPM 점수가 높으면 안전하다?"** 아니다. CSPM은 설정만 본다. 설정이 완벽해도 키가 유출되면 뚫린다. 또 Prowler 실습에서 봤듯이 보안 기능을 추가하면 그 기능 자체가 새 점검 대상이 되어 FAIL이 늘기도 한다. 건수보다 **심각도별 변화와 준수율**을 함께 봐야 한다.
- **"FAIL은 전부 고쳐야 한다?"** 아니다. 비용이나 운영상 이유로 **위험을 수용**하는 것도 정당한 결정이다. 다만 그 근거를 문서로 남겨야 한다.
- **"CSPM = 취약점 스캐너?"** 다르다. 취약점 스캐너(Nessus, Inspector 등)는 OS·패키지의 CVE를 찾고, CSPM은 클라우드 서비스의 설정을 본다. 굳이 나누면 취약점 스캔은 CWPP 쪽 영역에 가깝다.
- **"한 번 점검하면 끝?"** CSPM의 핵심은 **지속성**이다. 이상적으로는 CI/CD에 넣어 배포 전에 IaC를 점검하고(Shift Left), 배포 후에도 주기적으로 재점검한다.

## 정리

- CSPM은 클라우드 **설정 오류와 규정 위반을 지속적으로 찾아 고치는** 도구다.
- 필요한 이유: 공동 책임 모델에서 설정은 고객 책임이고, 클라우드 사고의 대부분이 설정 실수에서 나온다.
- 동작 방식: 읽기 전용 API로 설정을 수집 → 규칙·기준과 비교 → 우선순위화 → 조치 → 재점검.
- 한계: 워크로드 내부, 실제 공격 행위, 권한의 실제 사용은 깊게 보지 못한다. 그래서 CWPP·CIEM이 있고, 이를 묶은 것이 CNAPP다.

다음에는 CSPM의 빈틈을 메우는 쪽, 특히 **CIEM과 IAM 권한 상승 경로**를 정리해 볼 생각이다.

## 참고 자료

- [AWS 공동 책임 모델](https://aws.amazon.com/compliance/shared-responsibility-model/)
- [TechTarget — What is cloud security posture management (CSPM)?](https://www.techtarget.com/searchsecurity/definition/Cloud-Security-Posture-Management-CSPM)
- [Chef — Gartner의 CSPM 정의 인용](https://www.chef.io/glossary/what-is-cloud-security-posture-management-cspm)
- [Zscaler — 클라우드 설정 오류와 Gartner 분석](https://zscaler.com/blogs/product-insights/prevent-cloud-security-breaches-attributable-cloud-misconfigurations-cspm)
- [The Register — Verizon DBIR 2021: 설정 오류는 해킹 다음 원인](https://www.theregister.com/2021/12/20/cloud_security_common_misconfigurations/)
- [Rackspace — Capital One 유출 사고 분석](https://www.rackspace.com/blog/capital-one-data-breach-two-security-controls-you-should-review)
- [eSecurity Planet — CSPM vs CWPP vs CIEM vs CNAPP](https://esecurityplanet.com/cloud/cspm-cwpp-ciem-cnapp)
- [Coralogix — CNAPP vs CSPM](https://coralogix.com/guides/cnapp-vs-cspm/)
- [AWS Security Blog — Security Hub CSPM과 새 Security Hub](https://aws.amazon.com/blogs/security/security-hub-cspm-automation-rule-migration-to-security-hub)
