#!/usr/bin/env python3
"""从 mihomo 的 select 组中挑选能通过目标站点 WAF 的节点。

判断方式：通过代理请求目标站点的 JSON 接口。
- 返回 application/json（例如未登录提示）说明请求已到达业务后端；
- 返回 HTML（例如阿里云 WAF 验证页）说明该节点被拦截。
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MIHOMO_API = os.getenv('MIHOMO_API', 'http://127.0.0.1:9090').rstrip('/')
MIHOMO_SECRET = os.getenv('MIHOMO_SECRET', '').strip()
MIHOMO_GROUP = os.getenv('MIHOMO_GROUP', 'CHECKIN').strip() or 'CHECKIN'
PROBE_URL = os.getenv('PROXY_PROBE_URL', 'https://agentrouter.org/api/user/self').strip()
PROBE_TIMEOUT = float(os.getenv('PROXY_PROBE_TIMEOUT', '10'))
MAX_NODES = int(os.getenv('PROXY_MAX_SCAN_NODES', '60'))
REGION = os.getenv('PROXY_NODE_REGION', 'auto').strip().lower() or 'auto'

REGION_PATTERNS = {
	'sg': re.compile(r'(新加坡|singapore|🇸🇬|(^|[-_ ])sg([-_ ]|$))', re.I),
	'tw': re.compile(r'(tw|台湾|taiwan)', re.I),
	'jp': re.compile(r'(jp|日本|japan)', re.I),
	'us': re.compile(r'((^|[-_ ])us([-_ ]|$)|美国|united states)', re.I),
}


def _api(path: str, method: str = 'GET', payload: dict | None = None):
	data = json.dumps(payload).encode() if payload is not None else None
	req = urllib.request.Request(
		f'{MIHOMO_API}{path}',
		data=data,
		method=method,
		headers={
			'Authorization': f'Bearer {MIHOMO_SECRET}',
			'Content-Type': 'application/json',
		},
	)
	with urllib.request.urlopen(req, timeout=10) as resp:
		body = resp.read()
	if not body:
		return None
	return json.loads(body)


def _wait_api() -> bool:
	for _ in range(30):
		try:
			_api('/version')
			return True
		except Exception:  # nosec B110
			time.sleep(0.5)
	return False


def _select(name: str) -> None:
	group = urllib.parse.quote(MIHOMO_GROUP, safe='')
	_api(f'/proxies/{group}', 'PUT', {'name': name})


def _probe(proxy_url: str) -> tuple[bool, str, float]:
	opener = urllib.request.build_opener(
		urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
	)
	req = urllib.request.Request(
		PROBE_URL,
		headers={
			'Accept': 'application/json',
			'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
		},
	)
	started = time.monotonic()
	try:
		with opener.open(req, timeout=PROBE_TIMEOUT) as resp:
			status = resp.status
			headers = resp.headers
			body = resp.read(8192).decode('utf-8', 'replace')
	except urllib.error.HTTPError as exc:
		# 401/403 也可能是业务后端的 JSON 未登录响应，需要看内容类型判断是否被 WAF 拦截
		status = exc.code
		headers = exc.headers
		body = exc.read(8192).decode('utf-8', 'replace')
	except Exception as exc:
		return False, f'{type(exc).__name__}: {str(exc)[:60]}', 0
	elapsed = (time.monotonic() - started) * 1000

	content_type = headers.get('Content-Type', '') if headers else ''
	if 'application/json' in content_type.lower():
		try:
			payload = json.loads(body)
		except json.JSONDecodeError:
			return False, 'invalid JSON response', elapsed
		if isinstance(payload, dict) and ('success' in payload or 'message' in payload):
			return True, f'API reachable (HTTP {status})', elapsed
		return False, 'unexpected JSON response', elapsed

	if 'text/html' in content_type.lower():
		return False, 'WAF/HTML challenge page', elapsed
	return False, f'HTTP {status}, content-type: {content_type[:40] or "none"}', elapsed


def _priority(name: str) -> int:
	if REGION == 'auto':
		if REGION_PATTERNS['sg'].search(name):
			return 0
		if REGION_PATTERNS['tw'].search(name):
			return 1
		if REGION_PATTERNS['jp'].search(name):
			return 2
		return 3
	return 0


def main() -> int:
	if not _wait_api():
		print('[WARN] mihomo API is not ready, skip node scanning')
		return 0

	group = urllib.parse.quote(MIHOMO_GROUP, safe='')
	try:
		info = _api(f'/proxies/{group}')
	except Exception as exc:
		print(f'[WARN] Cannot read proxy group "{MIHOMO_GROUP}": {exc}')
		return 0

	nodes = [n for n in (info.get('all') or []) if isinstance(n, str)]
	if not nodes:
		print('[WARN] No proxy nodes found, skip node scanning')
		return 0

	if REGION != 'auto':
		if REGION == 'all':
			pass
		else:
			pattern = REGION_PATTERNS.get(REGION)
			if pattern is None:
				print(f'[FAILED] Unknown PROXY_NODE_REGION: {REGION} (expected auto/sg/tw/jp/us/all)')
				return 1
			nodes = [n for n in nodes if pattern.search(n)]
			if not nodes:
				print(f'[FAILED] No proxy nodes matched region "{REGION}"')
				return 1

	nodes.sort(key=_priority)
	if MAX_NODES > 0:
		nodes = nodes[:MAX_NODES]

	proxy_url = os.getenv('CHECKIN_PROXY_URL', 'http://127.0.0.1:7890').strip()
	print(f'[INFO] Scanning {len(nodes)} node(s) for WAF acceptance via {PROBE_URL}')

	for name in nodes:
		try:
			_select(name)
		except Exception as exc:
			print(f'[WARN] {name}: switch failed ({str(exc)[:50]})')
			continue
		ok, detail, elapsed = _probe(proxy_url)
		if ok:
			print(f'[SUCCESS] Selected proxy node: {name} ({detail}, {elapsed:.0f}ms)')
			return 0
		print(f'[WARN] {name}: {detail}')

	print('[FAILED] No proxy node passed the WAF probe')
	return 1


if __name__ == '__main__':
	sys.exit(main())
