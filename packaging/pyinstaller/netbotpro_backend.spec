# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

project_root = None
candidate_roots = [Path.cwd()]

spec_path = globals().get("SPECPATH")
if spec_path:
    candidate_roots.append(Path(spec_path))
if "__file__" in globals():
    candidate_roots.append(Path(__file__).resolve().parent)

for candidate in candidate_roots:
    candidate = candidate.resolve()
    for root in (candidate, *candidate.parents):
        if (root / "backend" / "app" / "desktop_entry.py").exists():
            project_root = root
            break
    if project_root is not None:
        break

if project_root is None:
    raise SystemExit("Could not locate the Netbotpro project root for PyInstaller")

desktop_entry = project_root / "backend" / "app" / "desktop_entry.py"
config_dir = project_root / "config"

hiddenimports = [
    "backend.app.desktop_entry",
    "backend.app.main",
    "backend.app.security",
    "core.capture",
    "core.capture.system_provider",
    "core.netbotpro_sniffer_core",
]

a = Analysis(
    [str(desktop_entry)],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        (str(config_dir), "config"),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["_tkinter", "numpy", "scipy", "setuptools", "sklearn", "tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="netbotpro-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="netbotpro-backend",
)
