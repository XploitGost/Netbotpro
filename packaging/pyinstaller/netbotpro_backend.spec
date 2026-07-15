# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.building import build_main as _build_main


_original_find_binary_dependencies = _build_main.find_binary_dependencies


def _find_binary_dependencies_without_package_imports(binaries, import_packages, symlink_suppression_patterns):
    # Windows package import scanning can hang indefinitely in our desktop build environment.
    # Netbotpro does not rely on package-side DLL path registration during boot, so skip that
    # pre-import phase and let PyInstaller resolve binary dependencies from the standard paths.
    return _original_find_binary_dependencies(binaries, [], symlink_suppression_patterns)


_build_main.find_binary_dependencies = _find_binary_dependencies_without_package_imports

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
service_registry_dir = project_root / "backend" / "app" / "data"

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
        (str(service_registry_dir), "backend/app/data"),
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
