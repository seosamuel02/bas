# BASTION - Caldera-Wazuh Integration Plugin

Caldera BAS(Breach and Attack Simulation)와 Wazuh SIEM을 통합하여 공격 시뮬레이션과 탐지 검증을 자동화하는 플러그인입니다.

## 주요 기능

- ✅ Wazuh API 통합 (Manager + Indexer)
- ✅ 실시간 알림 조회
- ⏳ Caldera 작전과 Wazuh 알림 상관관계 분석 (구현 예정)
- ⏳ 탐지 커버리지 리포트 생성 (구현 예정)
- ⏳ 적응형 작전 생성 (구현 예정)

## 설치 방법

### 1. 플러그인 복사
```bash
# Caldera 디렉토리로 이동
cd /path/to/caldera

# 플러그인 복사 또는 심볼릭 링크
cp -r /path/to/BASTION/plugins/bastion plugins/
```

### 2. Caldera 설정
`conf/local.yml` 파일에 플러그인 추가:
```yaml
plugins:
  - bastion
```

### 3. Wazuh 환경 설정
로컬 Docker로 Wazuh 실행:
```bash
# Wazuh Docker 저장소 클론
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node

# Wazuh 시작
docker-compose up -d

# 상태 확인
docker-compose ps
```

기본 접속 정보:
- Wazuh Dashboard: https://localhost:443 (admin / SecretPassword)
- Wazuh Manager API: https://localhost:55000 (wazuh / wazuh)
- Wazuh Indexer: https://localhost:9200 (admin / admin)

### 4. Caldera 시작
```bash
python3 server.py --insecure --build
```

브라우저에서 접속: http://localhost:8888

## API 엔드포인트

### 헬스체크
```bash
curl http://localhost:8888/plugin/bastion/health
```

### 최근 알림 조회
```bash
# 최근 1시간, 레벨 7 이상
curl "http://localhost:8888/plugin/bastion/alerts?hours=1&min_level=7"

# 최근 24시간, 레벨 5 이상
curl "http://localhost:8888/plugin/bastion/alerts?hours=24&min_level=5"
```

### 작전-알림 상관관계 분석 (구현 예정)
```bash
curl -X POST http://localhost:8888/plugin/bastion/correlate \
  -H "Content-Type: application/json" \
  -d '{"operation_id": "작전ID"}'
```

## 개발 현황

### ✅ Phase 1: 기본 통합 (완료)
- [x] 플러그인 구조 생성
- [x] hook.py 진입점
- [x] Wazuh API 클라이언트
- [x] 알림 조회 엔드포인트
- [x] 헬스체크 엔드포인트

### 🚧 Phase 2: 대시보드 (진행 예정)
- [ ] Vue.js 컴포넌트
- [ ] 실시간 알림 뷰어
- [ ] 탐지 커버리지 매트릭스
- [ ] 상관관계 타임라인

### 📋 Phase 3: 고급 기능 (계획)
- [ ] 상관관계 엔진 구현
- [ ] 적응형 adversary 생성
- [ ] 탐지 갭 분석
- [ ] PDF/JSON 리포트

## 트러블슈팅

### Wazuh API 연결 실패
```
[BASTION] Wazuh Manager 연결 실패: Cannot connect to host localhost:55000
```
해결: Wazuh Docker 컨테이너가 실행 중인지 확인
```bash
docker-compose -f wazuh-docker/single-node/docker-compose.yml ps
```

### 플러그인 로딩 실패
```
[BASTION] 모듈 임포트 실패: No module named 'app.bastion_service'
```
해결: 플러그인 디렉토리 구조 확인
```bash
ls -la plugins/bastion/app/
```

### SSL 인증서 오류
```
ssl.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
```
해결: `conf/default.yml`에서 `verify_ssl: false` 설정

## 라이센스

MIT License

## 기여

버그 리포트 및 기능 제안 환영합니다!
