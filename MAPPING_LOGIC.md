# CPE 매핑 로직 (Deterministic Ranking)

EMBA가 생성한 CycloneDX SBOM의 각 컴포넌트에 대해, NVD CPE Dictionary에서
**가장 가능성 높은 CPE 10개를 순위 매겨 병기**하는 파이프라인.

전체 흐름:
```
 SBOM 컴포넌트  ──▶ pre_filter (후보 50개 추출 + 점수)
                     │
                     ├─ Pass 1   (vendor, product) 정확 매칭
                     ├─ Pass 2   product LIKE 매칭
                     └─ Pass 3   rapidfuzz 퍼지 매칭
                     │
                     ▼
                 점수 가산
                     ├─ version 일치 (정확 / semver 인접 / wildcard)
                     ├─ deprecated 감점
                     └─ CVE attribution 가산  (← 핵심 신호)
                     │
                     ▼
                 Top-10 결정
                     │
                     ▼
            SBOM properties에 병기
```

---

## 1. 입력: CycloneDX SBOM 컴포넌트

EMBA가 펌웨어를 분석해 만든 SBOM의 각 컴포넌트는 다음 필드를 가집니다.

```json
{
  "name": "libopenssl",
  "version": "1.1.1g-1",
  "group": "OpenWRT",
  "cpe": "cpe:2.3:a:libopenssl:libopenssl:1.1.1g:*:*:*:*:*:*:*",
  "purl": "pkg:opkg/openwrt/libopenssl@1.1.1g-1",
  "supplier": { "name": "OpenSSL Software Foundation" },
  "description": "..."
}
```

**중요**: EMBA가 채운 `cpe` 필드는 그대로 못 씁니다. 대표적 오류 패턴:

- `vendor == product` (예: `libopenssl:libopenssl`) — NVD에는 거의 없음
- 비표준 버전 문자열 (`g5da56622b3-dirty-1`)
- OpenWRT 패키지명이 NVD product와 다름 (`kmod-fs-msdos` ≠ `linux_kernel`)
- distro packaging revision 포함 (`1.1.1g-1`의 `-1`)

→ 우리는 `cpe` 필드 자체보다 **name + group + supplier + purl + description**을
추출 가능한 모든 신호로 보고, 그것들로 NVD를 검색합니다.

---

## 2. Pre-filter — 후보 50개 추출

`pre_filter.py`의 `find_candidates(conn, comp, top_n=50)`. 3개 pass를 union해서
candidate pool을 만든 뒤 점수로 정렬해 상위 50개를 반환합니다.

### 2.1 토큰 정규화

쿼리 토큰을 만들기 전에 컴포넌트의 이름/버전을 정규화합니다.

| 입력 | 정규화 결과 | 처리 |
|------|-----------|------|
| `kmod-fs-msdos` | `fs-msdos` | `kmod-` 접두 제거 |
| `libopenssl` | `openssl` | `lib` 접두 제거 (alias 적용) |
| `1.1.1g-1` | `1.1.1g` | distro packaging revision `-N` strip |
| `2019.78-2` | `2019.78` | 동일 |
| group `linux_kernel+module` | force product `linux_kernel` | GROUP_PRODUCT_HINTS |

`PRODUCT_ALIASES`에 hand-curated 매핑 사전이 있어 잘 알려진 변환을 보강합니다
(예: `dropbear` → `dropbear_ssh_server`/`dropbear_ssh`).

### 2.2 Pass 1 — (vendor, product) 정확 매칭

NVD CPE Dictionary에서:
```sql
SELECT * FROM cpe WHERE vendor IN (...) AND product IN (...)
```
- 기본 점수 **+3.0**
- 가장 신뢰할 수 있는 신호. 보통 같은 제품의 모든 버전 row가 한꺼번에 잡힘.

예시 (busybox):
```
cpe:2.3:a:busybox:busybox:1.30.1   ← Pass 1, score 3.0
cpe:2.3:a:busybox:busybox:1.30.0   ← Pass 1, score 3.0
cpe:2.3:a:busybox:busybox:-        ← Pass 1, score 3.0 (wildcard version)
... (수십~수백개)
```

### 2.3 Pass 2 — product LIKE 매칭

product 토큰의 substring 매칭:
```sql
SELECT * FROM cpe WHERE product LIKE '%token%' OR product LIKE 'token%'
```
- 기본 점수 **+2.0**
- vendor가 SBOM에 잘못 적혀있어도 product 변종(`dropbear_ssh`, `dropbear_project`
  등)을 포착.

### 2.4 Pass 3 — rapidfuzz 퍼지 매칭

Pass 1·2 결과에 추가로, NVD title + (vendor, product) 합성 문자열에 대해
`token_set_ratio` 유사도 80+ 인 항목 추출.
- 기본 점수 **+1.0**
- 오타/약자/언어 변종 등을 보강하는 안전망.

---

## 3. 점수 가산 (보너스/페널티)

3개 pass를 통과한 후보 풀에 추가 신호를 더합니다.

### 3.1 Version 보너스

`apply_version_bonus()` — 컴포넌트 버전과 후보 CPE 버전의 관계:

| 관계 | 가산 |
|------|------|
| 정확 일치 (`1.1.1g` == `1.1.1g`) | **+5.0** |
| Wildcard 버전 (`-` / `*` — 모든 버전 적용) | **+0.6** |
| Semver prefix 근접 (`1.30.1` vs `1.30.0` → 0.7) | +1.5 × proximity |
| 무관 (`1.1.1g` vs `0.9.8x`) | 0 |

### 3.2 Deprecated 페널티

```python
if candidate.deprecated:
    candidate.score *= 0.85
```
deprecated CPE는 새 CVE attribution을 못 받지만, 과거 CVE는 여전히 매칭되므로
완전 제거는 안 합니다.

### 3.3 CVE Attribution 보너스 — 핵심 신호

`apply_cve_attribution_bonus()` — 각 후보의 (vendor, product) 페어가 NVD CVE에서
실제로 얼마나 인용됐는지를 점수에 반영. 이 값은 **정답성의 가장 강한 신호**입니다.

#### 왜 이게 결정적인가

같은 product 이름에 NVD CPE Dictionary에는 vendor 변종이 여럿 있을 수 있습니다.

| Dictionary 항목 | 실제 CVE 회수 |
|----------------|--------------|
| `cpe:2.3:a:dropbear_ssh_project:dropbear_ssh` | **20** |
| `cpe:2.3:a:dropbear_project:dropbear` | 0 |
| `cpe:2.3:a:matt_johnston:dropbear` | 0 |
| `cpe:2.3:a:openssl:openssl` | **275** |
| `cpe:2.3:a:openbsd:openssl` | 0 |
| `cpe:2.3:a:gnu:gnutls` | **71** |

→ Dictionary에 등재됐어도 NVD가 CVE 인덱싱에 안 쓰는 페어는
`cve_count == 0`. CVE 매칭의 실제 유용성은 0이므로 점수에서 강하게 감점.

#### 측정 방법

`download_nvd_cves.py`가 NVD CVE 2.0 API에서 모든 CVE(~350K)를 가져와,
각 CVE의 `configurations.nodes[].cpeMatch[].criteria`를 파싱하고 등장한
(vendor, product) 페어를 `Counter`로 누적합니다. 결과를
`data/nvd_cve_attribution.sqlite`에 저장:

```sql
CREATE TABLE cve_attribution (
    vendor    TEXT,
    product   TEXT,
    cve_count INTEGER,
    PRIMARY KEY (vendor, product)
);
```

같은 CVE가 같은 페어의 여러 버전 row를 인용해도 한 번만 카운트(unique 페어)
— 안 그러면 row 많은 product가 인위적으로 canonical로 보입니다.

#### 가산 공식

```python
def _cve_bonus(count):
    if count == 0:    return -2.0           # NVD가 한 번도 인용 안 함 → 강한 감점
    if count <= 2:    return  0.0           # 표본 부족 → 중립
    return min(3.0, max(1.0, log10(count))) # 살아있는 CPE → +1.0 ~ +3.0
```

| count | bonus | 의미 |
|-------|-------|------|
| 0 | **-2.0** | 사실상 dead CPE, 매칭해도 CVE 회수 0 |
| 1~2 | 0 | 신생/희귀 — 신호 부족 |
| 3~9 | +1.0 | 살아있는 CPE, 보수적 가산 |
| 10~99 | +1.0~+2.0 | 활발하게 인덱싱 |
| 100+ | +3.0 (cap) | 핵심 OSS (예: openssl 275, linux_kernel 5000+) |

로그 스케일이라 큰 product가 작은 product를 묻지 않습니다.

---

## 4. Top-10 선정

`select_topn(pool, n=10)`:

1. 같은 cpe_name이 여러 pass에 잡혔으면 **최고 점수만 보존** (dedupe)
2. `(-score, deprecated, cpe_name)` 순으로 정렬 → 점수 내림차순, 동점 시 non-deprecated 우선
3. 상위 10개 반환

각 후보는 다음 필드를 가짐:
```python
Candidate(
    cpe_name="cpe:2.3:a:openssl:openssl:1.1.1g:...",
    vendor="openssl", product="openssl", version="1.1.1g",
    deprecated=0,
    score=11.5,           # 3.0 (Pass 1) + 5.0 (version exact) + 3.0 (CVE 275)
    pass_id=1,
    rationale="pass 1 vendor/product exact; version 1.1.1g exact; 275 CVE attributions"
)
```

---

## 5. 출력 — SBOM properties에 병기

`enrich_sbom.py`가 각 컴포넌트의 `properties` 배열에 다음을 추가합니다.
원본 `cpe` 필드는 **건드리지 않음** (CycloneDX 1.5 호환).

```json
"properties": [
  { "name": "EMBA:cpe_candidates:source",      "value": "deterministic@2026-05-07" },
  { "name": "EMBA:cpe_candidates:status",      "value": "deterministic" },
  { "name": "EMBA:cpe_candidates:1:cpe",       "value": "cpe:2.3:a:openssl:openssl:1.1.1g:*:*:*:*:*:*:*" },
  { "name": "EMBA:cpe_candidates:1:score",     "value": "0.958" },
  { "name": "EMBA:cpe_candidates:1:rationale", "value": "pass 1 vendor/product exact; version 1.1.1g exact; 275 CVE attributions" },
  { "name": "EMBA:cpe_candidates:2:cpe",       "value": "cpe:2.3:a:openssl:openssl:1.1.1g:-:..." },
  ...
  { "name": "EMBA:cpe_candidates:10:cpe",      "value": "..." }
]
```

`status` 필드 값:
- `deterministic` — pre_filter + CVE attribution으로 결정 (LLM 미사용)
- `no_candidates` — NVD에 매칭 후보 자체 없음 (firmware blob 등)

`score` 정규화: 원시 점수(0~12 범위)를 12로 나누어 [0, 1]에 매핑. 0.85 이상이
"canonical (vendor, product) + 정확 버전 + 활발한 CVE attribution" 영역.

---

## 6. 실제 예시: `libopenssl 1.1.1g-1` 매핑

| 단계 | 결과 |
|------|------|
| **입력** | name=`libopenssl`, version=`1.1.1g-1`, EMBA cpe=`a:libopenssl:libopenssl:1.1.1g` |
| **정규화** | name 토큰 = `openssl` (lib 접두 제거 + alias), version = `1.1.1g` (-1 strip) |
| **Pass 1** | `vendor=openssl, product=openssl` 200+ row 회수, base 3.0 |
| **Pass 1** | `vendor=openbsd, product=openssl` 1 row 회수, base 3.0 |
| **Pass 2** | `product LIKE %openssl%` — Pass 1 결과와 거의 동일 |
| **Version bonus** | `1.1.1g` 정확 일치 row → +5.0 |
| **CVE bonus** | `(openssl, openssl)` count=275 → +3.0; `(openbsd, openssl)` count=0 → -2.0 |
| **Top-1** | `cpe:2.3:a:openssl:openssl:1.1.1g:...` 최종 점수 11.0 / 12 = **0.917** |
| **Top-2** | `cpe:2.3:a:openssl:openssl:-` (wildcard) 점수 6.6 / 12 = **0.55** |
| **버려짐** | `cpe:2.3:a:openbsd:openssl:1.1.1g` 점수 0.85 → Top-10 끝자리 |

**핵심**: SBOM에 적힌 `libopenssl:libopenssl` vendor를 **무시**하고, NVD가 실제로
인덱싱에 쓰는 `openssl:openssl`을 데이터로 골라냈습니다. CVE attribution 신호
없이는 이 변별이 불가능했을 부분.

---

## 7. 후속 사용

이 enriched SBOM은 vulnerability scanner의 입력으로 사용:

- **Top-1만 사용**: 가장 가능성 높은 단일 CPE를 NVD에 조회
- **Top-10 OR-union**: 모든 후보를 OR로 묶어 회수율 극대화. fallback / 동등 점수
  변종까지 포괄.
- **score ≥ 0.85 컷오프**: 신뢰도 임계로 자동화. 미달 컴포넌트는 사람이 검토.

`status="no_candidates"` 71개는 펌웨어 blob, 비표준 toolchain 산출물 등
NVD CPE가 존재하지 않는 항목이므로 별도 처리 (취약점 매핑 불가, 수동 분석 대상).

---

## 8. 파일/모듈 매핑

| 파일 | 역할 |
|------|------|
| `download_nvd_cpe.py` | NVD CPE Dictionary 전체를 SQLite로 받음 (1회) |
| `download_nvd_cves.py` | NVD CVE 2.0 API에서 (vendor, product) 인용 횟수 인덱스 구축 (1회) |
| `pre_filter.py` | 3-pass 후보 추출 + 점수 부여 (`find_candidates`) |
| `enrich_sbom.py` | 메인 오케스트레이터, properties 주입 |
| `data/nvd_cpe.sqlite` | NVD CPE Dictionary (~550 MB, 1.7M row) |
| `data/nvd_cve_attribution.sqlite` | (vendor, product) → cve_count 인덱스 (~수 MB) |
| `data/run_cache.sqlite` | 컴포넌트별 결과 캐시 (재실행 시 건너뛰기) |

LLM 백엔드(`gemini_rank.py`, `codex_rank.py`)는 `--backend gemini|codex`로
선택 가능하지만 기본은 `deterministic`이며, 이 문서가 설명하는 것이 기본 경로.
