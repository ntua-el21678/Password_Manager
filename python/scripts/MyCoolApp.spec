# -*- mode: python ; coding: utf-8 -*-

import sys
import os
from PyInstaller.utils.hooks import collect_data_files

# Collect Flet data files
datas = []
datas += collect_data_files('flet')
datas += collect_data_files('flet_desktop')

# Also include password_manager.py from the scripts directory
datas += [('password_manager.py', '.')]

a = Analysis(
    ['gui_enhanced.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=['flet', 'flet_desktop', 'flet_runtime', 'flet_core'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='MyCoolApp',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
