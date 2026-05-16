#!/usr/bin/env python3
"""Patch a Briefcase iOS Xcode project so Python can call native CryptoKit."""

from __future__ import annotations

import argparse
from pathlib import Path


def insert_before(text: str, marker: str, addition: str) -> str:
    if addition in text:
        return text
    if marker not in text:
        raise ValueError(f"marker not found: {marker}")
    return text.replace(marker, addition + marker, 1)


def replace_once(text: str, old: str, new: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise ValueError(f"anchor block not found: {old.splitlines()[0]}")
    return text.replace(old, new, 1)


def patch_native_crypto(text: str) -> str:
    text = insert_before(
        text,
        "/* End PBXBuildFile section */\n",
        "\t\t71C300000000000000000001 /* ObstacleBridgeNativeCrypto.swift in Sources */ = {isa = PBXBuildFile; fileRef = 71C300000000000000000010 /* ObstacleBridgeNativeCrypto.swift */; };\n",
    )
    text = insert_before(
        text,
        "/* End PBXFileReference section */\n",
        "\t\t71C300000000000000000010 /* ObstacleBridgeNativeCrypto.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = ObstacleBridgeNativeCrypto.swift; path = \"../../../../native/ObstacleBridgeShared/ObstacleBridgeNativeCrypto.swift\"; sourceTree = SOURCE_ROOT; };\n",
    )
    if "71C300000000000000000001 /* ObstacleBridgeNativeCrypto.swift in Sources */," not in text:
        text = replace_once(
            text,
            "\t\t60796EDE19190F4100A9926B /* Sources */ = {\n\t\t\tisa = PBXSourcesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (\n\t\t\t\t600000000000000000100100 /* main.m in Sources */,\n\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n\t\t};\n",
            "\t\t60796EDE19190F4100A9926B /* Sources */ = {\n\t\t\tisa = PBXSourcesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = (\n\t\t\t\t600000000000000000100100 /* main.m in Sources */,\n\t\t\t\t71C300000000000000000001 /* ObstacleBridgeNativeCrypto.swift in Sources */,\n\t\t\t);\n\t\t\trunOnlyForDeploymentPostprocessing = 0;\n\t\t};\n",
        )
    text = replace_once(
        text,
        "\t\t60796F0F19190F4100A9926B /* Debug */ = {\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {\n\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;\n\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;\n",
        "\t\t60796F0F19190F4100A9926B /* Debug */ = {\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {\n\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;\n\t\t\t\tCODE_SIGN_ENTITLEMENTS = \"../../../../native/ObstacleBridgeE2E/ObstacleBridgeE2E.entitlements\";\n\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;\n\t\t\t\tSWIFT_VERSION = 5.0;\n",
    )
    text = replace_once(
        text,
        "\t\t60796F1019190F4100A9926B /* Release */ = {\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {\n\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;\n\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;\n",
        "\t\t60796F1019190F4100A9926B /* Release */ = {\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {\n\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;\n\t\t\t\tCODE_SIGN_ENTITLEMENTS = \"../../../../native/ObstacleBridgeE2E/ObstacleBridgeE2E.entitlements\";\n\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;\n\t\t\t\tSWIFT_VERSION = 5.0;\n",
    )
    return text


def patch_file(path: Path) -> bool:
    original = path.read_text(encoding="utf-8")
    patched = patch_native_crypto(original)
    if patched == original:
        return False
    path.write_text(patched, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pbxproj", type=Path)
    args = parser.parse_args()
    changed = patch_file(args.pbxproj)
    print(f"{'patched' if changed else 'already configured'}: {args.pbxproj}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
