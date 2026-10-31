#!/usr/bin/env python3
"""Preview or apply GitHub About/Topics metadata with a bounded API client.

Run without --apply to inspect the intended change offline. Tokens are never logged.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_METADATA = ROOT / '.github' / 'repository-metadata.json'
REPO_NAME = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
TOPIC_NAME = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)*$')


def load_metadata(filename: Path) -> dict:
    data = json.loads(filename.read_text(encoding='utf-8'))
    repo = data.get('repository')
    description = data.get('description')
    homepage = data.get('homepage')
    topics = data.get('topics')
    if not isinstance(repo, str) or not REPO_NAME.fullmatch(repo):
        raise ValueError('repository must have owner/repo form')
    if not isinstance(description, str) or not 1 <= len(description) <= 160:
        raise ValueError('description must contain 1 to 160 characters')
    if not isinstance(homepage, str) or not homepage.startswith('https://'):
        raise ValueError('homepage must be an HTTPS URL')
    if not isinstance(topics, list) or not (1 <= len(topics) <= 20):
        raise ValueError('expected 1 to 20 topics')
    if not all(isinstance(t, str) and TOPIC_NAME.fullmatch(t) for t in topics):
        raise ValueError('invalid GitHub topic name')
    if len(topics) != len(set(topics)):
        raise ValueError('duplicate topics')
    return {'repository': repo, 'description': description, 'homepage': homepage, 'topics': topics}


def github_api(method: str, path: str, token: str, payload: dict | None = None) -> dict:
    encoded = None if payload is None else json.dumps(payload, separators=(',', ':')).encode('utf-8')
    request = Request(
        'https://api.github.com' + path,
        data=encoded,
        method=method,
        headers={
            'Accept': 'application/vnd.github+json',
            'Authorization': 'Bearer ' + token,
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'rei-rea-metadata-sync/0.1',
            **({'Content-Type': 'application/json'} if encoded is not None else {}),
        },
    )
    with urlopen(request, timeout=15) as response:
        return json.load(response)


def sync(data: dict, token: str) -> dict:
    repo = data['repository']
    base = '/repos/' + repo
    github_api('PATCH', base, token, {
        'description': data['description'], 'homepage': data['homepage'],
    })
    github_api('PUT', base + '/topics', token, {'names': data['topics']})
    current = github_api('GET', base, token)
    if (current.get('description') != data['description']
            or current.get('homepage') != data['homepage']
            or set(current.get('topics', [])) != set(data['topics'])):
        raise RuntimeError('GitHub did not report the expected metadata; inspect About manually')
    return {'repository': repo, 'description': current['description'],
            'homepage': current['homepage'], 'topics': current['topics'],
            'verified': True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata', type=Path, default=DEFAULT_METADATA)
    parser.add_argument('--apply', action='store_true', help='Write metadata to GitHub (needs GH_TOKEN or GITHUB_TOKEN)')
    args = parser.parse_args(argv)
    try:
        desired = load_metadata(args.metadata)
        if not args.apply:
            print(json.dumps({'mode': 'dry-run', 'remote_changed': False, **desired}, indent=2))
            return 0
        token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
        if not token:
            raise ValueError('GH_TOKEN or GITHUB_TOKEN is required for --apply')
        print(json.dumps(sync(desired, token), indent=2))
        return 0
    except (ValueError, RuntimeError, HTTPError, URLError, OSError, json.JSONDecodeError) as exc:
        if isinstance(exc, HTTPError):
            # Do not echo response content or request headers; those can contain credentials.
            detail = f'GitHub API returned HTTP {exc.code} on metadata update'
        else:
            detail = str(exc)
        print('metadata-sync: ' + detail, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
