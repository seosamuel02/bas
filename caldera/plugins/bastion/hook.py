"""
BASTION (Bridging Attack Simulations To Integrated Observability Network)
Caldera와 Wazuh SIEM을 통합하여 공격 시뮬레이션과 탐지 검증을 자동화
"""

from aiohttp import web
import logging

name = 'bastion'
description = 'BASTION - Bridging Attack Simulations To Integrated Observability Network'
address = None  # Vue 자동 라우팅 사용 (/plugins/bastion)

async def enable(services):
    """
    플러그인 초기화 함수

    Args:
        services: Caldera 코어 서비스 딕셔너리
    """
    app_svc = services.get('app_svc')
    log = app_svc.log if app_svc else logging.getLogger('bastion')

    log.info('[BASTION] BASTION Plugin 초기화 시작')

    try:
        # 설정 로드 - 환경 변수 우선, 그 다음 local.yml
        import os

        bastion_config = app_svc.get_config().get('bastion', {}) if app_svc else {}
        wazuh_config = bastion_config.get('wazuh', {})

        config = {
            'wazuh_manager_url': os.getenv('WAZUH_MANAGER_URL') or wazuh_config.get('manager_url', 'https://wazuh.manager:55000'),
            'wazuh_indexer_url': os.getenv('WAZUH_INDEXER_URL') or wazuh_config.get('indexer_url', 'https://wazuh.indexer:9200'),
            'wazuh_username': os.getenv('WAZUH_USERNAME') or wazuh_config.get('manager_username', 'wazuh'),
            'wazuh_password': os.getenv('WAZUH_PASSWORD') or wazuh_config.get('manager_password', 'wazuh'),
            'indexer_username': os.getenv('WAZUH_INDEXER_USERNAME') or wazuh_config.get('indexer_username', 'admin'),
            'indexer_password': os.getenv('WAZUH_INDEXER_PASSWORD') or wazuh_config.get('indexer_password', 'SecretPassword'),
            'verify_ssl': wazuh_config.get('verify_ssl', False),
            'alert_query_interval': bastion_config.get('refresh_interval', 300)
        }

        log.info(f'[BASTION] Wazuh Manager URL: {config["wazuh_manager_url"]}')

        # BASTION 서비스 초기화
        from plugins.bastion.app.bastion_service import BASTIONService
        bastion_svc = BASTIONService(services, config)

        # REST API 엔드포인트 등록
        app = app_svc.application

        # 알림 조회 엔드포인트
        app.router.add_route('GET', '/plugin/bastion/alerts',
                            bastion_svc.get_recent_alerts)

        # 상관관계 분석 엔드포인트
        app.router.add_route('POST', '/plugin/bastion/correlate',
                            bastion_svc.correlate_operation)

        # 탐지 리포트 생성
        app.router.add_route('GET', '/plugin/bastion/detection_report',
                            bastion_svc.generate_detection_report)

        # 적응형 작전 생성
        app.router.add_route('POST', '/plugin/bastion/adaptive_operation',
                            bastion_svc.create_adaptive_operation)

        # 헬스체크 엔드포인트
        app.router.add_route('GET', '/plugin/bastion/health',
                            bastion_svc.health_check)

        # Agent 조회 엔드포인트
        app.router.add_route('GET', '/plugin/bastion/agents',
                            bastion_svc.get_agents_with_detections)

        # 대시보드 통합 데이터 엔드포인트
        app.router.add_route('GET', '/plugin/bastion/dashboard',
                            bastion_svc.get_dashboard_summary)

        # Tier 2: MITRE ATT&CK Technique 커버리지 분석
        app.router.add_route('GET', '/plugin/bastion/dashboard/techniques',
                            bastion_svc.get_technique_coverage)

        # 정적 파일 제공 (CSS, JS, 이미지)
        app.router.add_static('/bastion/static',
                             'plugins/bastion/static/',
                             append_version=True)

        log.info('[BASTION] REST API 엔드포인트 등록 완료')
        log.info('[BASTION] 사용 가능한 엔드포인트:')
        log.info('  - GET  /plugin/bastion/alerts')
        log.info('  - POST /plugin/bastion/correlate')
        log.info('  - GET  /plugin/bastion/detection_report')
        log.info('  - POST /plugin/bastion/adaptive_operation')
        log.info('  - GET  /plugin/bastion/health')
        log.info('  - GET  /plugin/bastion/agents')
        log.info('  - GET  /plugin/bastion/dashboard')
        log.info('  - GET  /plugin/bastion/dashboard/techniques (NEW - Week 11)')
        log.info(f'  - GUI: http://localhost:8888{address}')

        # Wazuh 인증을 백그라운드 태스크로 시작
        import asyncio

        async def authenticate_wazuh():
            try:
                await bastion_svc.authenticate()
                log.info('[BASTION] Wazuh API 인증 성공')
            except Exception as auth_error:
                log.warning(f'[BASTION] Wazuh API 인증 실패: {auth_error}')
                log.warning('[BASTION] Wazuh 서버가 실행 중인지 확인하세요')

        asyncio.create_task(authenticate_wazuh())
        log.info('[BASTION] Wazuh 인증을 백그라운드에서 시작합니다')

        # 백그라운드 모니터링 시작 (선택사항)
        if config.get('enable_continuous_monitoring', False):
            asyncio.create_task(bastion_svc.continuous_monitoring())
            log.info('[BASTION] 지속적 모니터링 시작됨')

        log.info('[BASTION] 플러그인 활성화 완료 ✓')

    except ImportError as e:
        log.error(f'[BASTION] 모듈 임포트 실패: {e}')
        log.error('[BASTION] plugins/bastion/app/bastion_service.py 파일이 있는지 확인하세요')
        raise
    except Exception as e:
        log.error(f'[BASTION] 플러그인 활성화 실패: {e}', exc_info=True)
        raise


async def expansion(services):
    """
    플러그인 확장 함수 (선택사항)
    모든 플러그인 로딩 후 호출됨
    """
    log = services.get('app_svc').log
    log.debug('[BASTION] Expansion hook 호출됨')
