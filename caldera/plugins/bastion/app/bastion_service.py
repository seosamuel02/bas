"""
BASTION 서비스 - Caldera와 Wazuh 통합 핵심 로직
"""

import aiohttp
import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from aiohttp import web


class BASTIONService:
    """Caldera-Wazuh 통합 서비스"""

    # Wazuh Rule ID → MITRE ATT&CK Technique 매핑
    # Wazuh 기본 규칙에 MITRE 태그가 없으므로 수동 매핑
    RULE_MITRE_MAPPING = {
        # 인증 및 계정
        '5715': 'T1078',      # SSH authentication success → Valid Accounts
        '5501': 'T1078',      # PAM: Login session opened → Valid Accounts
        '5402': 'T1078.003',  # Successful sudo to ROOT → Valid Accounts: Local Accounts

        # 네트워크 탐지
        '533': 'T1049',       # netstat ports changed → System Network Connections Discovery

        # 시스템 탐지
        '510': 'T1082',       # rootcheck anomaly → System Information Discovery
        '502': 'T1082',       # Wazuh server started → System Information Discovery
        '503': 'T1082',       # Wazuh agent started → System Information Discovery

        # SCA (Security Configuration Assessment)
        '19005': 'T1082',     # SCA summary → System Information Discovery
        '19007': 'T1082',     # SCA high severity → System Information Discovery
        '19008': 'T1082',     # SCA medium severity → System Information Discovery
        '19009': 'T1082',     # SCA low severity → System Information Discovery

        # 파일 접근
        '550': 'T1083',       # Integrity checksum changed → File and Directory Discovery
        '554': 'T1083',       # File added to the system → File and Directory Discovery

        # 프로세스
        '592': 'T1059',       # Process creation → Command and Scripting Interpreter
        '594': 'T1059',       # Process execution → Command and Scripting Interpreter
    }

    def __init__(self, services: Dict[str, Any], config: Dict[str, Any]):
        """
        Args:
            services: Caldera 서비스 딕셔너리
            config: BASTION 설정
        """
        self.services = services
        self.data_svc = services.get('data_svc')
        self.rest_svc = services.get('rest_svc')
        self.app_svc = services.get('app_svc')
        self.knowledge_svc = services.get('knowledge_svc')
        self.log = self.app_svc.log if self.app_svc else logging.getLogger('bastion')

        # Wazuh 설정
        self.manager_url = config.get('wazuh_manager_url', 'https://localhost:55000')
        self.indexer_url = config.get('wazuh_indexer_url', 'https://localhost:9200')
        self.username = config.get('wazuh_username', 'wazuh')
        self.password = config.get('wazuh_password', 'wazuh')
        self.indexer_username = config.get('indexer_username', 'admin')
        self.indexer_password = config.get('indexer_password', 'SecretPassword')
        self.verify_ssl = config.get('verify_ssl', False)
        self.monitor_interval = config.get('alert_query_interval', 300)

        # 상태 관리
        self.token = None
        self.token_expiry = None
        self.last_alert_time = datetime.utcnow()
        self.is_authenticated = False

    async def authenticate(self):
        """Wazuh Manager API 인증"""
        try:
            auth = aiohttp.BasicAuth(self.username, self.password)
            url = f'{self.manager_url}/security/user/authenticate?raw=true'

            timeout = aiohttp.ClientTimeout(total=10)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.post(url, auth=auth) as resp:
                    if resp.status == 200:
                        self.token = await resp.text()
                        self.token_expiry = datetime.utcnow() + timedelta(minutes=15)
                        self.is_authenticated = True
                        self.log.info('[BASTION] Wazuh API 인증 성공')
                        return True
                    else:
                        error_text = await resp.text()
                        raise Exception(f'인증 실패 (HTTP {resp.status}): {error_text}')

        except aiohttp.ClientConnectorError as e:
            self.log.error(f'[BASTION] Wazuh Manager 연결 실패: {e}')
            self.log.error(f'[BASTION] {self.manager_url} 주소가 올바른지 확인하세요')
            raise
        except asyncio.TimeoutError:
            self.log.error('[BASTION] Wazuh API 연결 타임아웃 (10초)')
            raise
        except Exception as e:
            self.log.error(f'[BASTION] Wazuh 인증 오류: {e}')
            raise

    async def _ensure_authenticated(self):
        """토큰 유효성 확인 및 재인증"""
        if not self.token or not self.token_expiry:
            await self.authenticate()
        elif datetime.utcnow() >= self.token_expiry:
            self.log.info('[BASTION] 토큰 만료, 재인증 중...')
            await self.authenticate()

    async def get_recent_alerts(self, request: web.Request) -> web.Response:
        """
        최근 Wazuh 알림 조회

        Query Parameters:
            hours: 조회 시간 범위 (기본: 1시간)
            min_level: 최소 심각도 레벨 (기본: 7)
        """
        try:
            hours = int(request.query.get('hours', 1))
            min_level = int(request.query.get('min_level', 7))

            self.log.info(f'[BASTION] 알림 조회 요청: 최근 {hours}시간, 레벨 >= {min_level}')

            # OpenSearch 쿼리
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": min_level}}},
                            {"range": {"timestamp": {"gte": f"now-{hours}h"}}}
                        ]
                    }
                },
                "size": 100,
                "sort": [{"timestamp": {"order": "desc"}}],
                "_source": [
                    "timestamp", "rule.id", "rule.level", "rule.description",
                    "agent.id", "agent.name", "data.mitre.technique", "data.mitre.id"
                ]
            }

            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                # Wazuh Indexer 인증
                auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                async with session.post(
                    f'{self.indexer_url}/wazuh-alerts-*/_search',
                    json=query,
                    auth=auth
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        alerts = data.get('hits', {}).get('hits', [])

                        # MITRE 기법 추출 및 각 alert에 technique_id 추가
                        techniques = set()
                        processed_alerts = []

                        for alert in alerts:
                            source = alert.get('_source', {})

                            # 1. 먼저 알림에서 직접 MITRE 데이터 확인
                            mitre_data = source.get('data', {}).get('mitre', {})
                            technique_id = None
                            if isinstance(mitre_data, dict) and 'id' in mitre_data:
                                technique_id = mitre_data['id']

                            # 2. MITRE 데이터가 없으면 규칙 ID 매핑 테이블 사용
                            if not technique_id:
                                rule_id = str(source.get('rule', {}).get('id', ''))
                                technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                            if technique_id:
                                techniques.add(technique_id)

                            # 각 alert에 매핑된 technique_id 추가 (프론트엔드 표시용)
                            alert_data = source.copy()
                            alert_data['technique_id'] = technique_id
                            processed_alerts.append(alert_data)

                        result = {
                            'success': True,
                            'total': len(alerts),
                            'alerts': processed_alerts,
                            'detected_techniques': list(techniques),
                            'query_time': datetime.utcnow().isoformat()
                        }

                        self.log.info(f'[BASTION] 알림 {len(alerts)}건 조회 완료')
                        return web.json_response(result)
                    else:
                        error_text = await resp.text()
                        self.log.error(f'[BASTION] Indexer 쿼리 실패: {error_text}')
                        return web.json_response({
                            'success': False,
                            'error': f'Indexer query failed: HTTP {resp.status}'
                        }, status=500)

        except Exception as e:
            self.log.error(f'[BASTION] 알림 조회 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def correlate_operation(self, request: web.Request) -> web.Response:
        """
        Caldera 작전과 Wazuh 알림 상관관계 분석

        Body:
            operation_id: Caldera 작전 ID
        """
        try:
            data = await request.json()
            operation_id = data.get('operation_id')

            if not operation_id:
                return web.json_response({
                    'success': False,
                    'error': 'operation_id required'
                }, status=400)

            # Caldera 작전 조회
            operations = await self.data_svc.locate('operations', match={'id': operation_id})
            if not operations:
                return web.json_response({
                    'success': False,
                    'error': f'Operation {operation_id} not found'
                }, status=404)

            operation = operations[0]

            # 작전 실행 시간 범위 계산 (timezone 안전)
            start_time = operation.start
            if start_time and start_time.tzinfo:
                # timezone-aware인 경우 UTC로 변환 후 naive로
                start_time = start_time.replace(tzinfo=None)

            end_time = operation.finish if operation.finish else datetime.utcnow()
            if end_time and end_time.tzinfo:
                # timezone-aware인 경우 UTC로 변환 후 naive로
                end_time = end_time.replace(tzinfo=None)

            # 1. 작전에서 실행된 MITRE 기법 추출
            operation_techniques = set()
            executed_abilities = []

            for link in operation.chain:
                # 각 링크는 실행된 ability를 나타냄
                ability = link.ability
                executed_abilities.append({
                    'ability_id': ability.ability_id,
                    'name': ability.name,
                    'tactic': ability.tactic,
                    'technique_id': ability.technique_id,
                    'technique_name': ability.technique_name
                })

                # MITRE 기법 ID 추출 (예: T1059)
                if ability.technique_id:
                    operation_techniques.add(ability.technique_id)

            self.log.info(f'[BASTION] 작전 실행 기법: {operation_techniques}')

            # 2. Wazuh 알림 조회 (작전 시간 범위)
            duration_seconds = int((end_time - start_time).total_seconds())
            duration_minutes = max(1, duration_seconds // 60)  # 최소 1분

            # OpenSearch 쿼리
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": 3}}},  # 낮은 레벨부터 조회
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": start_time.isoformat(),
                                        "lte": end_time.isoformat()
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": 500,
                "sort": [{"timestamp": {"order": "asc"}}],
                "_source": [
                    "timestamp", "rule.id", "rule.level", "rule.description",
                    "agent.id", "agent.name", "data.mitre.technique", "data.mitre.id",
                    "data.mitre.tactic"
                ]
            }

            # 3. Wazuh Indexer에서 알림 조회
            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

            detected_techniques = set()
            alerts_matched = []

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                async with session.post(
                    f'{self.indexer_url}/wazuh-alerts-*/_search',
                    json=query,
                    auth=auth
                ) as resp:
                    if resp.status == 200:
                        result_data = await resp.json()
                        alerts = result_data.get('hits', {}).get('hits', [])

                        # 알림에서 MITRE 기법 추출
                        for alert in alerts:
                            source = alert.get('_source', {})
                            mitre_data = source.get('data', {}).get('mitre', {})

                            # MITRE ID 추출 (다양한 형식 지원)
                            technique_id = None
                            if isinstance(mitre_data, dict):
                                technique_id = mitre_data.get('id')
                            elif isinstance(mitre_data, list):
                                for item in mitre_data:
                                    if isinstance(item, dict) and 'id' in item:
                                        technique_id = item.get('id')
                                        break

                            # MITRE 데이터가 없으면 규칙 ID 매핑 테이블 사용
                            if not technique_id:
                                rule_id = str(source.get('rule', {}).get('id', ''))
                                technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                            if technique_id:
                                detected_techniques.add(technique_id)
                                alerts_matched.append({
                                    'timestamp': source.get('timestamp'),
                                    'rule_id': source.get('rule', {}).get('id'),
                                    'rule_level': source.get('rule', {}).get('level'),
                                    'description': source.get('rule', {}).get('description'),
                                    'agent_name': source.get('agent', {}).get('name'),
                                    'technique_id': technique_id
                                })

                    else:
                        error_text = await resp.text()
                        self.log.error(f'[BASTION] Indexer 쿼리 실패: {error_text}')

            # 4. 매칭 및 탐지율 계산
            matched_techniques = operation_techniques.intersection(detected_techniques)
            undetected_techniques = operation_techniques - detected_techniques

            detection_rate = 0.0
            if len(operation_techniques) > 0:
                detection_rate = len(matched_techniques) / len(operation_techniques)

            # 5. 상관관계 결과 생성
            correlation_result = {
                'success': True,
                'operation_id': operation_id,
                'operation_name': operation.name,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration_seconds,
                'correlation': {
                    'detection_rate': round(detection_rate, 2),
                    'total_techniques': len(operation_techniques),
                    'detected_techniques': len(matched_techniques),
                    'undetected_techniques': len(undetected_techniques),
                    'matched_techniques': list(matched_techniques),
                    'undetected_techniques_list': list(undetected_techniques),
                    'all_operation_techniques': list(operation_techniques),
                    'all_detected_techniques': list(detected_techniques)
                },
                'executed_abilities': executed_abilities,
                'alerts_matched': alerts_matched,
                'total_alerts': len(alerts_matched)
            }

            self.log.info(f'[BASTION] 상관관계 분석 완료: 탐지율 {detection_rate:.1%}')

            return web.json_response(correlation_result)

        except Exception as e:
            self.log.error(f'[BASTION] 상관관계 분석 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def generate_detection_report(self, request: web.Request) -> web.Response:
        """탐지 커버리지 리포트 생성"""
        try:
            # TODO: 구현 필요
            report = {
                'success': True,
                'message': 'Detection report generation not implemented yet',
                'total_operations': 0,
                'detection_rate': 0.0
            }

            return web.json_response(report)

        except Exception as e:
            self.log.error(f'[BASTION] 리포트 생성 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def create_adaptive_operation(self, request: web.Request) -> web.Response:
        """Wazuh 데이터 기반 적응형 작전 생성"""
        try:
            # TODO: 구현 필요
            return web.json_response({
                'success': True,
                'message': 'Adaptive operation not implemented yet'
            })

        except Exception as e:
            self.log.error(f'[BASTION] 적응형 작전 생성 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def get_agents_with_detections(self, request: web.Request) -> web.Response:
        """
        Caldera Agents 목록 + Wazuh Agent 매칭 + 최근 탐지 정보

        Query Parameters:
            hours: 조회 시간 범위 (기본: 1시간)
            operation_id: 특정 작전 ID 필터 (선택사항)
            os_filter: OS 플랫폼 필터 (선택사항: Windows, Linux, macOS)
            search: 검색어 (선택사항)
        """
        try:
            hours = int(request.query.get('hours', 1))
            operation_id_filter = request.query.get('operation_id', '').strip()
            os_filter = request.query.get('os_filter', '').strip().lower()
            search_query = request.query.get('search', '').strip().lower()

            self.log.info(f'[BASTION] Agents 조회 요청 (최근 {hours}시간 탐지, op_filter={operation_id_filter}, os={os_filter}, search={search_query})')

            # 1. Wazuh Agents 조회 (ID로 인덱싱)
            wazuh_agents_by_id = {}
            try:
                await self._ensure_authenticated()
                timeout = aiohttp.ClientTimeout(total=10)
                connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    headers = {'Authorization': f'Bearer {self.token}'}
                    async with session.get(f'{self.manager_url}/agents', headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for wazuh_agent in data.get('data', {}).get('affected_items', []):
                                agent_id = wazuh_agent.get('id')
                                wazuh_agents_by_id[agent_id] = {
                                    'id': agent_id,
                                    'name': wazuh_agent.get('name', ''),
                                    'ip': wazuh_agent.get('ip'),
                                    'status': wazuh_agent.get('status'),
                                    'version': wazuh_agent.get('version')
                                }
                            self.log.info(f'[BASTION] Wazuh Agents {len(wazuh_agents_by_id)}개 조회')
            except Exception as e:
                self.log.warning(f'[BASTION] Wazuh Agents 조회 실패: {e}')

            # 2. Caldera Agents 조회
            agents = await self.data_svc.locate('agents')

            agents_data = []
            for agent in agents:
                # Agent alive 상태 판단 (timezone 안전)
                alive = False
                if agent.last_seen:
                    try:
                        # timezone-aware datetime 처리
                        last_seen = agent.last_seen.replace(tzinfo=None) if agent.last_seen.tzinfo else agent.last_seen
                        alive = (datetime.utcnow() - last_seen).total_seconds() < 300  # 5분 이내
                    except Exception:
                        alive = False

                # last_seen 처리 (datetime 또는 str)
                last_seen = None
                if agent.last_seen:
                    last_seen = agent.last_seen.isoformat() if isinstance(agent.last_seen, datetime) else agent.last_seen

                agent_info = {
                    'paw': agent.paw,
                    'host': agent.host,
                    'username': agent.username,
                    'platform': agent.platform,
                    'executors': agent.executors,
                    'privilege': agent.privilege,
                    'last_seen': last_seen,
                    'sleep_min': agent.sleep_min,
                    'sleep_max': agent.sleep_max,
                    'group': agent.group,
                    'contact': agent.contact,
                    'alive': alive,
                    'recent_detections': [],
                    'attack_steps_count': 0,  # Week 11: Agent별 attack steps 수
                    'detections_count': 0     # Week 11: Agent별 detections 수
                }

                # Wazuh Agent 매칭 (Facts 기반: wazuh.agent.id trait 사용)
                wazuh_agent = None
                wazuh_agent_id = None

                # Agent의 links에서 facts 추출
                try:
                    if hasattr(agent, 'links') and agent.links:
                        for link in agent.links:
                            if hasattr(link, 'facts') and link.facts:
                                for fact in link.facts:
                                    if fact.trait == 'wazuh.agent.id':
                                        wazuh_agent_id = fact.value
                                        self.log.info(f'[BASTION] Agent {agent.paw}: Wazuh ID {wazuh_agent_id} (Links에서 발견)')
                                        break
                            if wazuh_agent_id:
                                break

                    if not wazuh_agent_id:
                        self.log.warning(f'[BASTION DEBUG] Agent {agent.paw}: No wazuh.agent.id fact found in links')
                except Exception as e:
                    self.log.error(f'[BASTION] Error getting facts for agent {agent.paw}: {e}')

                # Wazuh agent 정보 조회
                if wazuh_agent_id:
                    wazuh_agent = wazuh_agents_by_id.get(wazuh_agent_id)
                    if not wazuh_agent:
                        self.log.warning(f'[BASTION] Agent {agent.paw}: Wazuh ID {wazuh_agent_id} 존재하지 않음')

                agent_info['wazuh_matched'] = wazuh_agent is not None
                agent_info['wazuh_agent'] = wazuh_agent if wazuh_agent else None

                # 2. 각 Agent의 최근 Wazuh 탐지 조회 (매칭된 경우만)
                if wazuh_agent:
                    query = {
                        "query": {
                            "bool": {
                                "must": [
                                    {"range": {"rule.level": {"gte": 5}}},
                                    {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
                                    {"term": {"agent.id": wazuh_agent['id']}}
                                ]
                            }
                        },
                        "size": 10,
                        "sort": [{"timestamp": {"order": "desc"}}],
                        "_source": [
                            "timestamp", "rule.id", "rule.level", "rule.description",
                            "data.mitre.id", "data.mitre.tactic", "agent.name", "agent.ip"
                        ]
                    }

                    try:
                        timeout = aiohttp.ClientTimeout(total=10)
                        connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

                        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                            auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                            async with session.post(
                                f'{self.indexer_url}/wazuh-alerts-*/_search',
                                json=query,
                                auth=auth
                            ) as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    alerts = data.get('hits', {}).get('hits', [])

                                    for alert in alerts:
                                        source = alert.get('_source', {})

                                        # 1. 먼저 알림에서 직접 MITRE 데이터 확인
                                        mitre_data = source.get('data', {}).get('mitre', {})
                                        technique_id = mitre_data.get('id') if isinstance(mitre_data, dict) else None

                                        # 2. MITRE 데이터가 없으면 규칙 ID 매핑 테이블 사용
                                        if not technique_id:
                                            rule_id = str(source.get('rule', {}).get('id', ''))
                                            technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                                        agent_info['recent_detections'].append({
                                            'timestamp': source.get('timestamp'),
                                            'rule_id': source.get('rule', {}).get('id'),
                                            'rule_level': source.get('rule', {}).get('level'),
                                            'description': source.get('rule', {}).get('description'),
                                            'technique_id': technique_id
                                        })

                    except Exception as e:
                        self.log.warning(f'[BASTION] Agent {agent.paw} 탐지 조회 실패: {e}')
                        # 에러가 나도 agent 정보는 반환

                # Week 11: Agent 통계 계산
                # 1. Detections count (recent_detections 길이)
                agent_info['detections_count'] = len(agent_info['recent_detections'])

                # 2. Attack steps count (agent의 links 수)
                try:
                    if hasattr(agent, 'links') and agent.links:
                        # Operation filter가 있는 경우, 해당 operation의 links만 카운트
                        if operation_id_filter:
                            all_operations = await self.data_svc.locate('operations')
                            for op in all_operations:
                                if op.id == operation_id_filter:
                                    # 이 작전의 chains에서 현재 agent의 links 카운트
                                    for chain in op.chain:
                                        if hasattr(chain, 'paw') and chain.paw == agent.paw:
                                            agent_info['attack_steps_count'] += 1
                                    break
                        else:
                            # 전체 links 카운트
                            agent_info['attack_steps_count'] = len([link for link in agent.links if link.finish])
                except Exception as e:
                    self.log.warning(f'[BASTION] Agent {agent.paw} attack steps 계산 실패: {e}')

                # OS Filter 적용
                if os_filter:
                    if os_filter not in agent.platform.lower():
                        continue

                # Search Filter 적용
                if search_query:
                    search_match = False
                    if search_query in agent.paw.lower():
                        search_match = True
                    elif search_query in (agent.host or '').lower():
                        search_match = True
                    elif search_query in (agent.username or '').lower():
                        search_match = True
                    if not search_match:
                        continue

                # Operation Filter 적용 (해당 작전에 참여한 agent만 포함)
                if operation_id_filter:
                    all_operations = await self.data_svc.locate('operations')
                    operation_match = False
                    for op in all_operations:
                        if op.id == operation_id_filter:
                            # 이 작전의 agent 중에 현재 agent가 있는지 확인
                            for op_agent in op.agents:
                                if op_agent.paw == agent.paw:
                                    operation_match = True
                                    break
                            break
                    if not operation_match:
                        continue

                agents_data.append(agent_info)

            result = {
                'success': True,
                'total_agents': len(agents_data),
                'agents': agents_data,
                'query_time': datetime.utcnow().isoformat()
            }

            self.log.info(f'[BASTION] Agents {len(agents_data)}개 조회 완료')
            return web.json_response(result)

        except Exception as e:
            self.log.error(f'[BASTION] Agents 조회 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def health_check(self, request: web.Request) -> web.Response:
        """플러그인 및 Wazuh 연결 상태 확인"""
        try:
            health = {
                'plugin': 'healthy',
                'wazuh_manager': 'unknown',
                'wazuh_indexer': 'unknown',
                'authenticated': self.is_authenticated,
                'timestamp': datetime.utcnow().isoformat()
            }

            # Wazuh Manager 상태 확인
            try:
                await self._ensure_authenticated()
                health['wazuh_manager'] = 'healthy'
            except Exception as e:
                health['wazuh_manager'] = f'unhealthy: {str(e)}'

            # Wazuh Indexer 상태 확인
            try:
                timeout = aiohttp.ClientTimeout(total=5)
                connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                    async with session.get(f'{self.indexer_url}/_cluster/health', auth=auth) as resp:
                        if resp.status == 200:
                            cluster_health = await resp.json()
                            health['wazuh_indexer'] = cluster_health.get('status', 'unknown')
            except Exception as e:
                health['wazuh_indexer'] = f'unhealthy: {str(e)}'

            return web.json_response(health)

        except Exception as e:
            self.log.error(f'[BASTION] 헬스체크 실패: {e}', exc_info=True)
            return web.json_response({
                'plugin': 'unhealthy',
                'error': str(e)
            }, status=500)

    async def get_dashboard_summary(self, request: web.Request) -> web.Response:
        """
        대시보드 통합 데이터 조회 (KPI, Operations, Tactic Coverage, Timeline)

        Query Parameters:
            hours: 조회 시간 범위 (기본: 24시간)
            min_level: 최소 심각도 레벨 (기본: 5)
            operation_id: 특정 작전 ID 필터 (선택사항)
            os_filter: OS 플랫폼 필터 (선택사항: Windows, Linux, macOS)
            search: 검색어 (선택사항)
        """
        try:
            hours = int(request.query.get('hours', 24))
            min_level = int(request.query.get('min_level', 5))
            operation_id_filter = request.query.get('operation_id', '').strip()
            os_filter = request.query.get('os_filter', '').strip().lower()
            search_query = request.query.get('search', '').strip().lower()

            self.log.info(f'[BASTION] 대시보드 요약 조회: 최근 {hours}시간 (op_filter={operation_id_filter}, os_filter={os_filter}, search={search_query})')

            # 1. Operations 목록 조회 (Caldera)
            all_operations = await self.data_svc.locate('operations')
            all_agents = await self.data_svc.locate('agents')  # 모든 agents 조회

            # 최근 N시간 내 작전 필터링
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            operations_data = []
            total_attack_steps = 0
            operation_techniques = set()  # 전체 작전에서 실행된 기법

            self.log.error(f'[BASTION DEBUG] Total operations: {len(all_operations)}, cutoff_time: {cutoff_time}')
            for op in all_operations:
                # Operation ID 필터 적용
                if operation_id_filter and op.id != operation_id_filter:
                    continue

                # 최근 N시간 내 시작된 작전만 포함 (timezone 안전 비교)
                if op.start:
                    op_start = op.start.replace(tzinfo=None) if op.start.tzinfo else op.start
                    self.log.warning(f'[BASTION DEBUG] Operation {op.name}: op_start={op_start}, passes filter: {op_start >= cutoff_time}')
                    if op_start >= cutoff_time:
                        # 작전 실행 단계 추출
                        attack_steps = []
                        op_techniques = set()

                        for link in op.chain:
                            ability = link.ability
                            # link.finish가 datetime 객체인 경우 isoformat 변환, 문자열인 경우 그대로 사용
                            finish_time = None
                            if link.finish:
                                if isinstance(link.finish, str):
                                    finish_time = link.finish
                                else:
                                    finish_time = link.finish.isoformat()

                            attack_steps.append({
                                'ability_id': ability.ability_id,
                                'name': ability.name,
                                'tactic': ability.tactic,
                                'technique_id': ability.technique_id,
                                'technique_name': ability.technique_name,
                                'timestamp': finish_time,
                                'paw': link.paw  # Agent ID 추가 (OS filter용)
                            })

                            if ability.technique_id:
                                op_techniques.add(ability.technique_id)
                                operation_techniques.add(ability.technique_id)

                        total_attack_steps += len(attack_steps)

                        # Agent PAWs와 platforms 매핑
                        # attack_steps에 사용된 모든 PAW의 platform을 매핑
                        agent_paws = []
                        agent_platforms = {}

                        # attack_steps의 모든 PAW를 먼저 수집
                        attack_step_paws = set(step['paw'] for step in attack_steps)
                        self.log.warning(f'[BASTION DEBUG] Operation {op.name}: attack_step_paws = {attack_step_paws}')

                        # 각 PAW의 platform을 all_agents 또는 op.chain의 link에서 찾기
                        for paw in attack_step_paws:
                            # 1. all_agents에서 찾기
                            found = False
                            for agent in all_agents:
                                if agent.paw == paw:
                                    agent_platforms[paw] = agent.platform
                                    agent_paws.append(paw)
                                    found = True
                                    break

                            # 2. op.agents에서 찾기 (all_agents에 없는 경우)
                            if not found:
                                for agent in op.agents:
                                    if agent.paw == paw:
                                        agent_platforms[paw] = agent.platform
                                        agent_paws.append(paw)
                                        found = True
                                        break

                            # 3. executor로 platform 유추
                            if not found:
                                for link in op.chain:
                                    if link.paw == paw and link.executor:
                                        executor_name = link.executor.name
                                        if executor_name in ['sh', 'bash']:
                                            agent_platforms[paw] = 'linux'
                                        elif executor_name in ['cmd', 'psh', 'powershell']:
                                            agent_platforms[paw] = 'windows'
                                        elif executor_name == 'osascript':
                                            agent_platforms[paw] = 'darwin'
                                        else:
                                            agent_platforms[paw] = 'linux'
                                        agent_paws.append(paw)
                                        self.log.warning(f'[BASTION DEBUG] Inferred {paw} from executor {executor_name}: {agent_platforms[paw]}')
                                        break

                            if not found and paw not in agent_platforms:
                                self.log.warning(f'[BASTION DEBUG] FAILED to find platform for PAW {paw}')

                        # OS Filter 적용 (agent_platforms 중 하나라도 매칭되면 포함)
                        if os_filter:
                            platform_match = False
                            for platform in agent_platforms.values():
                                if os_filter in platform.lower():
                                    platform_match = True
                                    break
                            if not platform_match:
                                self.log.info(f'[BASTION] Operation {op.name} 스킵: OS filter 미매칭 ({os_filter})')
                                continue

                        # Search Filter 적용 (작전명, agent PAW, technique 검색)
                        if search_query:
                            search_match = False
                            # 작전명 검색
                            if search_query in op.name.lower():
                                search_match = True
                            # Agent PAW 검색
                            for paw in agent_paws:
                                if search_query in paw.lower():
                                    search_match = True
                                    break
                            # Technique ID/Name 검색
                            for tech_id in op_techniques:
                                if search_query in tech_id.lower():
                                    search_match = True
                                    break
                            if not search_match:
                                self.log.info(f'[BASTION] Operation {op.name} 스킵: search 미매칭 ({search_query})')
                                continue

                        # started/finished 처리 (datetime 또는 str)
                        started = None
                        if op.start:
                            started = op.start.isoformat() if isinstance(op.start, datetime) else op.start

                        finished = None
                        if op.finish:
                            finished = op.finish.isoformat() if isinstance(op.finish, datetime) else op.finish

                        operations_data.append({
                            'id': op.id,
                            'name': op.name,
                            'state': op.state,
                            'started': started,
                            'finished': finished,
                            'attack_steps': attack_steps,
                            'techniques': list(op_techniques),
                            'agent_count': len(op.agents),
                            'agent_paws': agent_paws,  # Agent PAW 목록 (OS filter용)
                            'agent_platforms': agent_platforms  # PAW -> Platform 매핑
                        })

            # 2. Wazuh Agent 정보 조회 (agent_id -> OS 매핑)
            wazuh_agent_os_map = {}
            timeout = aiohttp.ClientTimeout(total=30)

            async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=self.verify_ssl)) as session:
                # Wazuh Manager API에서 JWT 토큰 획득
                auth = aiohttp.BasicAuth(self.username, self.password)
                async with session.post(
                    f'{self.manager_url}/security/user/authenticate?raw=true',
                    auth=auth
                ) as resp:
                    if resp.status == 200:
                        token = await resp.text()
                        headers = {'Authorization': f'Bearer {token}'}

                        # 모든 Wazuh agent 조회
                        async with session.get(
                            f'{self.manager_url}/agents',
                            headers=headers,
                            params={'limit': 500}
                        ) as agents_resp:
                            if agents_resp.status == 200:
                                agents_data = await agents_resp.json()
                                for agent in agents_data.get('data', {}).get('affected_items', []):
                                    agent_id = agent.get('id')
                                    agent_os = agent.get('os', {}).get('platform', '').lower()
                                    if agent_id and agent_os:
                                        wazuh_agent_os_map[agent_id] = agent_os

            # 3. Wazuh 탐지 이벤트 조회
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": min_level}}},
                            {"range": {"timestamp": {"gte": f"now-{hours}h"}}}
                        ]
                    }
                },
                "size": 1000,
                "sort": [{"timestamp": {"order": "asc"}}],
                "_source": [
                    "timestamp", "rule.id", "rule.level", "rule.description",
                    "agent.id", "agent.name", "data.mitre.id", "data.mitre.tactic"
                ]
            }

            detected_techniques = set()
            detection_events = []

            async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=self.verify_ssl)) as session:
                auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                async with session.post(
                    f'{self.indexer_url}/wazuh-alerts-*/_search',
                    json=query,
                    auth=auth
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        alerts = data.get('hits', {}).get('hits', [])

                        for alert in alerts:
                            source = alert.get('_source', {})

                            # MITRE 기법 추출
                            mitre_data = source.get('data', {}).get('mitre', {})
                            technique_id = None
                            tactic = None

                            if isinstance(mitre_data, dict):
                                technique_id = mitre_data.get('id')
                                tactic = mitre_data.get('tactic', [])
                                if isinstance(tactic, list) and tactic:
                                    tactic = tactic[0]

                            # 규칙 ID 매핑 테이블 사용
                            if not technique_id:
                                rule_id = str(source.get('rule', {}).get('id', ''))
                                technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                            if technique_id:
                                detected_techniques.add(technique_id)

                            # Detection events에 agent.id 및 agent_os 추가
                            timestamp = source.get('timestamp')
                            agent_id = source.get('agent', {}).get('id')
                            agent_os = wazuh_agent_os_map.get(agent_id, 'unknown')

                            detection_events.append({
                                'timestamp': timestamp,
                                'rule_id': source.get('rule', {}).get('id'),
                                'rule_level': source.get('rule', {}).get('level'),
                                'description': source.get('rule', {}).get('description'),
                                'agent_name': source.get('agent', {}).get('name'),
                                'agent_id': agent_id,
                                'agent_os': agent_os,
                                'technique_id': technique_id,
                                'tactic': tactic
                            })

            # 3. Security Posture Score 계산 (Cymulate/AttackIQ 스타일)
            agents = await self.data_svc.locate('agents')
            total_agents = len(agents)

            matched_techniques = operation_techniques.intersection(detected_techniques)
            coverage = len(matched_techniques) / len(operation_techniques) if operation_techniques else 0.0

            # Detection Rate (0-100%)
            detection_rate = round(coverage * 100, 1)

            # Security Score 계산 (Detection Rate 기반)
            security_score = int(detection_rate)

            # Grade 계산 (A-F)
            if security_score >= 90:
                security_grade = 'A'
            elif security_score >= 80:
                security_grade = 'B'
            elif security_score >= 70:
                security_grade = 'C'
            elif security_score >= 60:
                security_grade = 'D'
            else:
                security_grade = 'F'

            # MTTD 계산 (Mean Time To Detection) - 공격과 탐지 시간 차이
            mttd_seconds = 0
            mttd_count = 0
            for op in operations_data:
                if op.get('attack_steps'):
                    for step in op['attack_steps']:
                        step_time = step.get('timestamp')
                        if step_time:
                            # 해당 technique의 탐지 이벤트 찾기
                            step_technique = step.get('technique_id')
                            for event in detection_events:
                                if event.get('technique_id') == step_technique:
                                    try:
                                        from dateutil import parser as date_parser
                                        attack_time = date_parser.parse(step_time).replace(tzinfo=None)
                                        detection_time = date_parser.parse(event['timestamp']).replace(tzinfo=None)
                                        time_diff = (detection_time - attack_time).total_seconds()
                                        if time_diff >= 0:  # 탐지가 공격 이후인 경우만
                                            mttd_seconds += time_diff
                                            mttd_count += 1
                                    except:
                                        pass

            mttd_minutes = round(mttd_seconds / 60 / mttd_count, 1) if mttd_count > 0 else 0

            # Critical Gaps (시뮬레이션했지만 탐지 안된 technique 수)
            critical_gaps = len(operation_techniques - detected_techniques)

            # Tactic Coverage (14개 tactic 중 몇 개 커버하는지)
            all_tactics = set()
            for op in operations_data:
                for step in op.get('attack_steps', []):
                    if step.get('tactic'):
                        all_tactics.add(step['tactic'])
            tactic_coverage = len(all_tactics)

            result = {
                'success': True,
                'kpi': {
                    'total_operations': len(operations_data),
                    'total_agents': total_agents,
                    'total_attack_steps': total_attack_steps,
                    'total_detections': len(detection_events),
                    'coverage': round(coverage, 2),
                    'last_seen': detection_events[0]['timestamp'] if detection_events else None,
                    # Week 11: Security Posture Metrics
                    'security_score': security_score,
                    'security_grade': security_grade,
                    'detection_rate': detection_rate,
                    'mttd_minutes': mttd_minutes,
                    'critical_gaps': critical_gaps,
                    'tactic_coverage': tactic_coverage
                },
                'operations': operations_data,
                'detection_events': detection_events[:400],  # 최근 400건만
                'query_time': datetime.utcnow().isoformat()
            }

            self.log.info(f'[BASTION] 대시보드 요약 생성 완료 (작전: {len(operations_data)}, 탐지: {len(detection_events)}, Score: {security_score}/{security_grade})')
            return web.json_response(result)

        except Exception as e:
            self.log.error(f'[BASTION] 대시보드 요약 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def get_technique_coverage(self, request: web.Request) -> web.Response:
        """
        MITRE ATT&CK Technique 커버리지 분석 (Tier 2 Heat Map용)

        각 technique별로 시뮬레이션 횟수와 탐지 횟수를 집계하여
        Detection Rate를 계산합니다.

        Query Parameters:
            hours: 조회 시간 범위 (기본: 24시간)
        """
        try:
            hours = int(request.query.get('hours', 24))
            self.log.info(f'[BASTION] Technique 커버리지 분석: 최근 {hours}시간')

            # 1. 모든 agents의 links에서 technique 추출
            all_agents = await self.data_svc.locate('agents')
            technique_stats = {}  # {technique_id: {simulated: N, detected: N, name: str, tactic: str}}

            cutoff_time = datetime.utcnow() - timedelta(hours=hours)

            for agent in all_agents:
                if not hasattr(agent, 'links') or not agent.links:
                    continue

                for link in agent.links:
                    # 시간 필터링
                    if link.finish:
                        if isinstance(link.finish, datetime):
                            finish_time = link.finish.replace(tzinfo=None) if link.finish.tzinfo else link.finish
                            if finish_time < cutoff_time:
                                continue
                        elif isinstance(link.finish, str):
                            # 문자열인 경우 datetime으로 파싱 시도
                            try:
                                from dateutil import parser as date_parser
                                finish_time = date_parser.parse(link.finish).replace(tzinfo=None)
                                if finish_time < cutoff_time:
                                    continue
                            except:
                                pass  # 파싱 실패 시 시간 필터링 스킵

                    # Technique 정보 추출
                    ability = link.ability
                    if not ability or not ability.technique_id:
                        continue

                    tech_id = ability.technique_id
                    if tech_id not in technique_stats:
                        technique_stats[tech_id] = {
                            'id': tech_id,
                            'name': ability.technique_name or tech_id,
                            'tactic': ability.tactic or 'unknown',
                            'simulated': 0,
                            'detected': 0
                        }

                    technique_stats[tech_id]['simulated'] += 1

            # 2. Wazuh alerts 조회하여 탐지 통계 추가
            try:
                await self.ensure_authenticated()
                alerts = await self.query_indexer_alerts(hours=hours, min_level=1)

                for alert in alerts:
                    rule = alert.get('rule', {})
                    mitre = rule.get('mitre', {})
                    technique_list = mitre.get('technique', [])

                    # Wazuh rule → technique 매핑도 활용
                    rule_id = str(rule.get('id', ''))
                    if rule_id in self.RULE_MITRE_MAPPING:
                        mapped_tech = self.RULE_MITRE_MAPPING[rule_id]
                        if mapped_tech not in technique_list:
                            technique_list.append(mapped_tech)

                    # 탐지된 technique 카운트
                    for tech_id in technique_list:
                        if tech_id in technique_stats:
                            technique_stats[tech_id]['detected'] += 1

            except Exception as e:
                self.log.warning(f'[BASTION] Wazuh alerts 조회 실패 (탐지 통계 없이 진행): {e}')

            # 3. Detection Rate 계산
            techniques = []
            for tech_id, stats in technique_stats.items():
                simulated = stats['simulated']
                detected = stats['detected']
                detection_rate = (detected / simulated * 100) if simulated > 0 else 0

                # 상태 결정: 회색(미시뮬), 빨강(갭), 노랑(부분), 초록(완전)
                if simulated == 0:
                    status = 'not_simulated'  # 회색
                elif detected == 0:
                    status = 'gap'  # 빨강
                elif detection_rate < 80:
                    status = 'partial'  # 노랑
                else:
                    status = 'complete'  # 초록

                techniques.append({
                    'id': tech_id,
                    'name': stats['name'],
                    'tactic': stats['tactic'],
                    'simulated': simulated,
                    'detected': detected,
                    'detection_rate': round(detection_rate, 1),
                    'status': status
                })

            # Tactic별 그룹화
            tactics = {}
            for tech in techniques:
                tactic = tech['tactic']
                if tactic not in tactics:
                    tactics[tactic] = {
                        'name': tactic,
                        'techniques': [],
                        'total_simulated': 0,
                        'total_detected': 0
                    }
                tactics[tactic]['techniques'].append(tech)
                tactics[tactic]['total_simulated'] += tech['simulated']
                tactics[tactic]['total_detected'] += tech['detected']

            # Tactic 커버리지 계산
            for tactic_data in tactics.values():
                total = tactic_data['total_simulated']
                detected = tactic_data['total_detected']
                tactic_data['coverage'] = round((detected / total * 100) if total > 0 else 0, 1)

            return web.json_response({
                'techniques': techniques,
                'tactics': list(tactics.values()),
                'summary': {
                    'total_techniques': len(techniques),
                    'total_simulated': sum(t['simulated'] for t in techniques),
                    'total_detected': sum(t['detected'] for t in techniques),
                    'overall_detection_rate': round(
                        sum(t['detected'] for t in techniques) / sum(t['simulated'] for t in techniques) * 100
                        if sum(t['simulated'] for t in techniques) > 0 else 0,
                        1
                    )
                },
                'time_range': {
                    'hours': hours,
                    'from': (datetime.utcnow() - timedelta(hours=hours)).isoformat(),
                    'to': datetime.utcnow().isoformat()
                }
            })

        except Exception as e:
            self.log.error(f'[BASTION] Technique 커버리지 조회 실패: {e}', exc_info=True)
            return web.json_response({
                'error': str(e),
                'techniques': [],
                'tactics': [],
                'summary': {
                    'total_techniques': 0,
                    'total_simulated': 0,
                    'total_detected': 0,
                    'overall_detection_rate': 0
                }
            }, status=500)

    async def continuous_monitoring(self):
        """지속적인 Wazuh 알림 모니터링 (백그라운드 태스크)"""
        self.log.info(f'[BASTION] 지속 모니터링 시작 (간격: {self.monitor_interval}초)')

        while True:
            try:
                await asyncio.sleep(self.monitor_interval)

                # TODO: 알림 모니터링 및 자동 대응 로직
                self.log.debug('[BASTION] 모니터링 주기 실행')

            except asyncio.CancelledError:
                self.log.info('[BASTION] 지속 모니터링 중지됨')
                break
            except Exception as e:
                self.log.error(f'[BASTION] 모니터링 오류: {e}')
                await asyncio.sleep(60)
