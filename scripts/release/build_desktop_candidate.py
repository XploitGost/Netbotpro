"""Build a fresh isolated Windows candidate; never stage over installed/runtime files."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import psutil

ROOT = Path(__file__).resolve().parents[2]
GIB = 1024**3


def folder_bytes(folder: Path) -> int:
    total = 0
    for file in folder.rglob('*'):
        try:
            if file.is_file():
                total += file.stat().st_size
        except FileNotFoundError:
            pass
    return total


def guarded_run(command: list[str], cwd: Path, folder: Path) -> None:
    with (folder / 'build.log').open('ab') as log:
        process = subprocess.Popen(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
        started = time.monotonic()
        observed = {}
        try:
            while process.poll() is None:
                owner = psutil.Process(process.pid)
                observed.update((p.pid, p) for p in owner.children(recursive=True))
                if time.monotonic() - started > 900:
                    raise RuntimeError('candidate_build_deadline_exceeded')
                if folder_bytes(folder) > 3 * GIB or shutil.disk_usage(folder).free < 2 * GIB:
                    raise RuntimeError('candidate_build_storage_budget_exceeded')
                time.sleep(2)
            if process.returncode:
                raise RuntimeError('candidate_build_step_failed; inspect bounded build.log')
        finally:
            if process.poll() is None:
                observed[process.pid] = psutil.Process(process.pid)
                for item in reversed(list(observed.values())):
                    try:
                        item.kill()
                    except psutil.NoSuchProcess:
                        pass
                psutil.wait_procs(list(observed.values()), timeout=5)
                process.wait(timeout=5)


def main() -> None:
    if os.name != 'nt':
        raise RuntimeError('Windows candidate builder requires Windows')
    destination = Path(os.environ['LOCALAPPDATA']) / 'NetBotCandidates'
    destination.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(destination).free < 5 * GIB:
        raise RuntimeError('At least 5 GiB free space is required')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip():
        raise RuntimeError('Commit candidate source changes before building an identifiable candidate')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    # Deep scientific-library paths exceed legacy Windows limits under a long checkout.
    folder = destination / f'{revision[:8]}-{stamp}'
    folder.mkdir(parents=True, exist_ok=False)
    guarded_run([sys.executable, '-m', 'PyInstaller', 'packaging/pyinstaller/netbotpro_backend.spec',
                 '--noconfirm', '--distpath', str(folder / 'backend-dist'), '--workpath', str(folder / 'work')], ROOT, folder)
    node = shutil.which('node')
    if not node:
        raise RuntimeError('Node.js is required')
    guarded_run([node, str(ROOT / 'frontend/node_modules/vite/bin/vite.js'), 'build'], ROOT / 'frontend', folder)
    package = json.loads((ROOT / 'desktop/electron/package.json').read_text())['build']
    package.update(appId='com.netbotpro.candidate', productName='NetBotPro Candidate',
                   extraMetadata={'main': 'candidate-main.cjs'},
                   directories={**package['directories'], 'output': str(folder / 'app')})
    package['files'] += ['candidate-main.cjs', 'candidate-profile.cjs']
    package['extraResources'] = [
        {'from': str(ROOT / 'frontend/dist'), 'to': 'frontend'},
        {'from': str(folder / 'backend-dist/netbotpro-backend'), 'to': 'runtime/backend'},
    ]
    config = folder / 'electron-builder.json'
    config.write_text(json.dumps(package, indent=2), encoding='utf-8')
    guarded_run([node, str(ROOT / 'desktop/electron/node_modules/electron-builder/cli.js'),
                 '--dir', '--win', '--config', str(config)], ROOT / 'desktop/electron', folder)
    executable = folder / 'app/win-unpacked/NetBotPro Candidate.exe'
    if not executable.is_file():
        raise RuntimeError('Candidate executable missing')
    report = {'revision': revision, 'executable': str(executable), 'artifact_bytes': folder_bytes(folder),
              'installed_app_modified': False, 'built_at': stamp}
    (folder / 'candidate.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
