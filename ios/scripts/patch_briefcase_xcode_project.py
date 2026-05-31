#!/usr/bin/env python3
"""Patch Briefcase's generated iOS Xcode project with the IPServer extension target."""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path


DEFAULT_PROJECT = (
    Path(__file__).resolve().parents[1]
    / "build"
    / "obstacle_bridge_ios"
    / "ios"
    / "xcode"
    / "ObstacleBridge.xcodeproj"
    / "project.pbxproj"
)

GENERATED_PACKET_TUNNEL_PROVIDER_RELATIVE = Path("GeneratedSources") / "IPServer" / "PacketTunnelProvider.swift"
REPO_PACKET_TUNNEL_PROVIDER = Path(__file__).resolve().parents[1] / "native" / "IPServer" / "PacketTunnelProvider.swift"

IPSERVER_SHARED_SWIFT_SOURCES = [
    ("71C500000000000000000001", "71C500000000000000000101", "ObstacleBridgeAdminAPI.swift"),
    ("71C500000000000000000002", "71C500000000000000000102", "ObstacleBridgeChannelMuxCodec.swift"),
    ("71C500000000000000000003", "71C500000000000000000103", "ObstacleBridgeSecureLinkPskCodec.swift"),
    ("71C500000000000000000004", "71C500000000000000000104", "ObstacleBridgeSecureLinkPskRuntime.swift"),
    ("71C500000000000000000005", "71C500000000000000000105", "ObstacleBridgeSecureLinkPskTransportAdapter.swift"),
    ("71C500000000000000000006", "71C500000000000000000106", "ObstacleBridgeOverlayLayerTransportAdapter.swift"),
    ("71C500000000000000000007", "71C500000000000000000107", "ObstacleBridgeRuntimeConfig.swift"),
    ("71C500000000000000000008", "71C500000000000000000108", "ObstacleBridgeChannelMuxTunRuntime.swift"),
    ("71C500000000000000000009", "71C500000000000000000109", "ObstacleBridgeUdpOverlayCodec.swift"),
    ("71C50000000000000000000A", "71C50000000000000000010A", "ObstacleBridgeUdpOverlaySessionCodec.swift"),
    ("71C50000000000000000000B", "71C50000000000000000010B", "ObstacleBridgeUdpOverlayPeerRuntime.swift"),
    ("71C50000000000000000000C", "71C50000000000000000010C", "ObstacleBridgeChannelMuxTcpRuntime.swift"),
    ("71C50000000000000000000D", "71C50000000000000000010D", "ObstacleBridgeChannelMuxTCPTransportOwner.swift"),
    ("71C50000000000000000000E", "71C50000000000000000010E", "ObstacleBridgeCompressLayerRuntime.swift"),
    ("71C50000000000000000000F", "71C50000000000000000010F", "ObstacleBridgeOverlayStackPlanner.swift"),
    ("71C500000000000000000010", "71C500000000000000000110", "ObstacleBridgePacketTunnelConfiguration.swift"),
    ("71C500000000000000000011", "71C500000000000000000111", "ObstacleBridgeWebSocketPayloadCodec.swift"),
    ("71C500000000000000000012", "71C500000000000000000112", "ObstacleBridgeWebSocketOverlayRuntime.swift"),
    ("71C500000000000000000013", "71C500000000000000000113", "ObstacleBridgeTcpOverlayRuntime.swift"),
]

APP_SHARED_SWIFT_SOURCES = [
    ("71C600000000000000000001", "71C600000000000000000101", "ObstacleBridgeAdminAPI.swift"),
    ("71C600000000000000000002", "71C600000000000000000102", "ObstacleBridgeChannelMuxCodec.swift"),
    ("71C600000000000000000003", "71C600000000000000000103", "ObstacleBridgeRuntimeConfig.swift"),
    ("71C600000000000000000004", "71C600000000000000000104", "ObstacleBridgeWebAdminServer.swift"),
    ("71C600000000000000000005", "71C600000000000000000105", "ObstacleBridgeOverlayStackPlanner.swift"),
]


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


def add_app_native_crypto_source(text: str) -> str:
    required_entries = [
        "\t\t\t\t71C300000000000000000001 /* ObstacleBridgeNativeCrypto.swift in Sources */,\n",
        "\t\t\t\t71C400000000000000000001 /* ObstacleBridgeTunnelControl.swift in Sources */,\n",
    ]

    if all(entry in text for entry in required_entries):
        return text

    match = re.search(
        r"\t\t60796EE119190F4100A9926B /\* ObstacleBridge \*/ = \{\n"
        r"\t\t\tisa = PBXNativeTarget;.*?"
        r"\t\t\tbuildPhases = \(\n"
        r"(?P<phases>.*?)"
        r"\t\t\t\);",
        text,
        flags=re.DOTALL,
    )
    if not match:
        raise ValueError("ObstacleBridge native target not found")

    source_phase_match = re.search(
        r"\t\t\t\t(?P<id>[0-9A-F]{24}) /\* Sources \*/,\n",
        match.group("phases"),
    )
    if not source_phase_match:
        raise ValueError("ObstacleBridge Sources build phase id not found")

    source_phase_id = source_phase_match.group("id")

    phase_match = re.search(
        rf"(?P<head>\t\t{source_phase_id} /\* Sources \*/ = \{{\n"
        rf"\t\t\tisa = PBXSourcesBuildPhase;\n"
        rf"\t\t\tbuildActionMask = 2147483647;\n"
        rf"\t\t\tfiles = \(\n)"
        rf"(?P<body>.*?)"
        rf"(?P<tail>\t\t\t\);\n"
        rf"\t\t\trunOnlyForDeploymentPostprocessing = 0;\n"
        rf"\t\t\}};)",
        text,
        flags=re.DOTALL,
    )
    if not phase_match:
        raise ValueError("ObstacleBridge Sources build phase block not found")

    body = phase_match.group("body")

    for entry in required_entries:
        if entry not in body:
            body += entry

    return (
        text[:phase_match.start()]
        + phase_match.group("head")
        + body
        + phase_match.group("tail")
        + text[phase_match.end():]
    )


def add_app_shared_swift_sources(text: str) -> str:
    for build_id, file_id, name in APP_SHARED_SWIFT_SOURCES:
        text = insert_before(
            text,
            "/* End PBXBuildFile section */\n",
            f"\t\t{build_id} /* {name} in Sources */ = {{isa = PBXBuildFile; fileRef = {file_id} /* {name} */; }};\n",
        )
        text = insert_before(
            text,
            "/* End PBXFileReference section */\n",
            f"\t\t{file_id} /* {name} */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = {name}; path = \"../../../../native/ObstacleBridgeShared/{name}\"; sourceTree = SOURCE_ROOT; }};\n",
        )

    match = re.search(
        r"(?P<head>\t\t60796EDE19190F4100A9926B /\* Sources \*/ = \{\n"
        r"\t\t\tisa = PBXSourcesBuildPhase;\n"
        r"\t\t\tbuildActionMask = 2147483647;\n"
        r"\t\t\tfiles = \(\n)"
        r"(?P<body>.*?)"
        r"(?P<tail>\t\t\t\);\n"
        r"\t\t\trunOnlyForDeploymentPostprocessing = 0;\n"
        r"\t\t\};)",
        text,
        flags=re.DOTALL,
    )
    if not match:
        raise ValueError("ObstacleBridge Sources build phase block not found")

    body = match.group("body")
    for build_id, _, name in APP_SHARED_SWIFT_SOURCES:
        entry = f"\t\t\t\t{build_id} /* {name} in Sources */,\n"
        if entry not in body:
            body += entry

    return text[:match.start()] + match.group("head") + body + match.group("tail") + text[match.end():]

def add_ipserver_native_crypto_source(text: str) -> str:
    source_phase = "71C200000000000000000080 /* Sources */ = {"
    if source_phase in text:
        text = text.replace(
            "\t\t\t\t71C300000000000000000002 /* ObstacleBridgeNativeCrypto.swift in Sources */,\n",
            "",
        )
        if "71C200000000000000000002 /* ObstacleBridgePythonBridge.m in Sources */," not in text:
            text = text.replace(
                "\t\t\t\t71C200000000000000000001 /* PacketTunnelProvider.swift in Sources */,\n",
                "\t\t\t\t71C200000000000000000001 /* PacketTunnelProvider.swift in Sources */,\n"
                "\t\t\t\t71C200000000000000000002 /* ObstacleBridgePythonBridge.m in Sources */,\n",
                1,
            )
        if "71C300000000000000000002 /* ObstacleBridgeNativeCrypto.swift in IPServer Sources */," not in text:
            text = text.replace(
                "\t\t\t\t71C200000000000000000002 /* ObstacleBridgePythonBridge.m in Sources */,\n",
                "\t\t\t\t71C200000000000000000002 /* ObstacleBridgePythonBridge.m in Sources */,\n"
                "\t\t\t\t71C300000000000000000002 /* ObstacleBridgeNativeCrypto.swift in IPServer Sources */,\n",
                1,
            )
        return text
    old = (
        "\t\t71C200000000000000000080 /* Sources */ = {\n"
        "\t\t\tisa = PBXSourcesBuildPhase;\n"
        "\t\t\tbuildActionMask = 2147483647;\n"
        "\t\t\tfiles = (\n"
        "\t\t\t\t71C200000000000000000001 /* PacketTunnelProvider.swift in Sources */,\n"
        "\t\t\t\t71C200000000000000000002 /* ObstacleBridgePythonBridge.m in Sources */,\n"
        "\t\t\t);\n"
        "\t\t\trunOnlyForDeploymentPostprocessing = 0;\n"
        "\t\t};\n"
    )
    new = (
        "\t\t71C200000000000000000080 /* Sources */ = {\n"
        "\t\t\tisa = PBXSourcesBuildPhase;\n"
        "\t\t\tbuildActionMask = 2147483647;\n"
        "\t\t\tfiles = (\n"
        "\t\t\t\t71C200000000000000000001 /* PacketTunnelProvider.swift in Sources */,\n"
        "\t\t\t\t71C200000000000000000002 /* ObstacleBridgePythonBridge.m in Sources */,\n"
        "\t\t\t\t71C300000000000000000002 /* ObstacleBridgeNativeCrypto.swift in IPServer Sources */,\n"
        "\t\t\t);\n"
        "\t\t\trunOnlyForDeploymentPostprocessing = 0;\n"
        "\t\t};\n"
    )
    if old not in text:
        raise ValueError("IPServer sources build phase not found")
    return text.replace(old, new, 1)


def add_ipserver_packet_flow_bridge_source(text: str) -> str:
    source_phase = "71C200000000000000000080 /* Sources */ = {"
    if source_phase in text and "71C200000000000000000007 /* ObstacleBridgePacketFlowBridge.swift in Sources */," not in text:
        text = text.replace(
            "\t\t\t\t71C200000000000000000001 /* PacketTunnelProvider.swift in Sources */,\n",
            "\t\t\t\t71C200000000000000000001 /* PacketTunnelProvider.swift in Sources */,\n"
            "\t\t\t\t71C200000000000000000007 /* ObstacleBridgePacketFlowBridge.swift in Sources */,\n",
            1,
        )
    return text


def add_ipserver_shared_swift_sources(text: str) -> str:
    for build_id, file_id, name in IPSERVER_SHARED_SWIFT_SOURCES:
        text = insert_before(
            text,
            "/* End PBXBuildFile section */\n",
            f"\t\t{build_id} /* {name} in Sources */ = {{isa = PBXBuildFile; fileRef = {file_id} /* {name} */; }};\n",
        )
        text = insert_before(
            text,
            "/* End PBXFileReference section */\n",
            f"\t\t{file_id} /* {name} */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = {name}; path = \"../../../../native/ObstacleBridgeShared/{name}\"; sourceTree = SOURCE_ROOT; }};\n",
        )

    match = re.search(
        r"(?P<head>\t\t71C200000000000000000080 /\* Sources \*/ = \{\n"
        r"\t\t\tisa = PBXSourcesBuildPhase;\n"
        r"\t\t\tbuildActionMask = 2147483647;\n"
        r"\t\t\tfiles = \(\n)"
        r"(?P<body>.*?)"
        r"(?P<tail>\t\t\t\);\n"
        r"\t\t\trunOnlyForDeploymentPostprocessing = 0;\n"
        r"\t\t\};)",
        text,
        flags=re.DOTALL,
    )
    if not match:
        raise ValueError("IPServer Sources build phase block not found")

    body = match.group("body")
    for build_id, _, name in IPSERVER_SHARED_SWIFT_SOURCES:
        entry = f"\t\t\t\t{build_id} /* {name} in Sources */,\n"
        if entry not in body:
            body += entry

    return text[:match.start()] + match.group("head") + body + match.group("tail") + text[match.end():]


def patch_python_build_script(text: str) -> str:
    script_variants = (
        (
            'if [ \\"$EFFECTIVE_PLATFORM_NAME\\" = \\"-iphonesimulator\\" ]; then\\n',
            'source $PROJECT_DIR/Support/Python.xcframework/build/utils.sh\\n\\n'
            'if [ -z \\"${EXPANDED_CODE_SIGN_IDENTITY:-}\\" ]; then\\n'
            '    export EXPANDED_CODE_SIGN_IDENTITY=-\\n'
            '    export EXPANDED_CODE_SIGN_IDENTITY_NAME=\\"Ad Hoc\\"\\n'
            'fi\\n\\n'
            'if [ \\"$EFFECTIVE_PLATFORM_NAME\\" = \\"-iphonesimulator\\" ]; then\\n',
        ),
        (
            'if [ "$EFFECTIVE_PLATFORM_NAME" = "-iphonesimulator" ]; then\n',
            'source $PROJECT_DIR/Support/Python.xcframework/build/utils.sh\n\n'
            'if [ -z "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then\n'
            '    export EXPANDED_CODE_SIGN_IDENTITY=-\n'
            '    export EXPANDED_CODE_SIGN_IDENTITY_NAME="Ad Hoc"\n'
            'fi\n\n'
            'if [ "$EFFECTIVE_PLATFORM_NAME" = "-iphonesimulator" ]; then\n',
        ),
    )

    for old, new in script_variants:
        if new in text:
            return text
        if old in text:
            return text.replace(old, new, 1)

    if 'name = "Process Python libraries";' not in text:
        return text
    raise ValueError("Process Python libraries shell script not found")

def add_app_network_extension_framework(text: str) -> str:
    build_file = (
        "\t\t71C400000000000000000002 /* NetworkExtension.framework in App Frameworks */ = "
        "{isa = PBXBuildFile; fileRef = 71C200000000000000000030 /* NetworkExtension.framework */; };\n"
    )
    text = insert_before(text, "/* End PBXBuildFile section */\n", build_file)

    if "71C400000000000000000002 /* NetworkExtension.framework in App Frameworks */," in text:
        return text

    match = re.search(
        r"(\t\t[0-9A-F]{24} /\* ObstacleBridge \*/ = \{\n"
        r"\t\t\tisa = PBXNativeTarget;.*?"
        r"\t\t\tbuildPhases = \(\n"
        r"(?P<phases>.*?)"
        r"\t\t\t\);)",
        text,
        flags=re.DOTALL,
    )
    if not match:
        raise ValueError("ObstacleBridge native target build phases not found")

    phases = match.group("phases")
    framework_phase_match = re.search(
        r"\t\t\t\t(?P<id>[0-9A-F]{24}) /\* Frameworks \*/,\n",
        phases,
    )
    if not framework_phase_match:
        raise ValueError("ObstacleBridge Frameworks build phase id not found")

    framework_phase_id = framework_phase_match.group("id")

    phase_pattern = (
        rf"(\t\t{framework_phase_id} /\* Frameworks \*/ = \{{\n"
        rf"\t\t\tisa = PBXFrameworksBuildPhase;\n"
        rf"\t\t\tbuildActionMask = 2147483647;\n"
        rf"\t\t\tfiles = \(\n)"
    )

    replacement = (
        r"\1"
        "\t\t\t\t71C400000000000000000002 /* NetworkExtension.framework in App Frameworks */,\n"
    )

    patched, count = re.subn(phase_pattern, replacement, text, count=1)
    if count != 1:
        raise ValueError("ObstacleBridge Frameworks build phase block not found")

    return patched


def patch_app_target(text: str) -> str:
    text = insert_before(
        text,
        "/* End PBXBuildFile section */\n",
        "\t\t71C300000000000000000001 /* ObstacleBridgeNativeCrypto.swift in Sources */ = {isa = PBXBuildFile; fileRef = 71C300000000000000000010 /* ObstacleBridgeNativeCrypto.swift */; };\n"
        "\t\t71C300000000000000000002 /* ObstacleBridgeNativeCrypto.swift in IPServer Sources */ = {isa = PBXBuildFile; fileRef = 71C300000000000000000010 /* ObstacleBridgeNativeCrypto.swift */; };\n",
    )
    text = insert_before(
        text,
        "/* End PBXBuildFile section */\n",
        "\t\t71C400000000000000000001 /* ObstacleBridgeTunnelControl.swift in Sources */ = {isa = PBXBuildFile; fileRef = 71C400000000000000000010 /* ObstacleBridgeTunnelControl.swift */; };\n",
    )
    text = insert_before(
        text,
        "/* End PBXFileReference section */\n",
        "\t\t71C300000000000000000010 /* ObstacleBridgeNativeCrypto.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = ObstacleBridgeNativeCrypto.swift; path = \"../../../../native/ObstacleBridgeShared/ObstacleBridgeNativeCrypto.swift\"; sourceTree = SOURCE_ROOT; };\n",
    )
    text = insert_before(
        text,
        "/* End PBXFileReference section */\n",
        "\t\t71C400000000000000000010 /* ObstacleBridgeTunnelControl.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = ObstacleBridgeTunnelControl.swift; path = \"../../../../native/ObstacleBridgeApp/ObstacleBridgeTunnelControl.swift\"; sourceTree = SOURCE_ROOT; };\n",
    )
    text = replace_once(
        text,
        "\t\t\t\t609384A628B5B958005B2A5D /* Process Python libraries */,\n\t\t\t\t6060E7A12AF8BF4400C04AE0 /* Embed Frameworks */,\n\t\t\t);\n",
        "\t\t\t\t609384A628B5B958005B2A5D /* Process Python libraries */,\n\t\t\t\t6060E7A12AF8BF4400C04AE0 /* Embed Frameworks */,\n\t\t\t\t71C200000000000000000010 /* Embed App Extensions */,\n\t\t\t);\n",
    )
    text = replace_once(
        text,
        "\t\t\tdependencies = (\n\t\t\t);\n",
        "\t\t\tdependencies = (\n\t\t\t\t71C200000000000000000090 /* PBXTargetDependency */,\n\t\t\t);\n",
    )
    text = replace_once(
        text,
        "\t\t60796F0F19190F4100A9926B /* Debug */ = {\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {\n\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;\n\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;\n",
        "\t\t60796F0F19190F4100A9926B /* Debug */ = {\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {\n\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;\n\t\t\t\tCODE_SIGN_ENTITLEMENTS = \"../../../../native/ObstacleBridgeApp/ObstacleBridge.entitlements\";\n\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;\n\t\t\t\tSWIFT_VERSION = 5.0;\n",
    )
    text = replace_once(
        text,
        "\t\t60796F1019190F4100A9926B /* Release */ = {\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {\n\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;\n\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;\n",
        "\t\t60796F1019190F4100A9926B /* Release */ = {\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {\n\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;\n\t\t\t\tCODE_SIGN_ENTITLEMENTS = \"../../../../native/ObstacleBridgeApp/ObstacleBridge.entitlements\";\n\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;\n\t\t\t\tSWIFT_VERSION = 5.0;\n",
    )
    text = add_app_native_crypto_source(text)
    text = add_app_shared_swift_sources(text)
    text = insert_before(
        text,
        "/* End PBXGroup section */\n",
        "\t\t71C300000000000000000020 /* Shared Native */ = {\n"
        "\t\t\tisa = PBXGroup;\n"
        "\t\t\tchildren = (\n"
        "\t\t\t\t71C300000000000000000010 /* ObstacleBridgeNativeCrypto.swift */,\n"
        "\t\t\t\t71C400000000000000000010 /* ObstacleBridgeTunnelControl.swift */,\n"
        "\t\t\t);\n"
        "\t\t\tname = \"Shared Native\";\n"
        "\t\t\tsourceTree = \"<group>\";\n"
        "\t\t};\n",
    )
    text = add_app_network_extension_framework(text)
    return text


def patch_ipserver_target(text: str) -> str:
    text = text.replace("AppProxyProvider.swift", "PacketTunnelProvider.swift")
    text = text.replace("native/IPServer/AppProxyProvider.swift", "native/IPServer/PacketTunnelProvider.swift")
    text = text.replace("com.apple.networkextension.app-proxy", "com.apple.networkextension.packet-tunnel")
    text = text.replace("app-proxy-provider", "packet-tunnel-provider")
    text = text.replace("$(PRODUCT_MODULE_NAME).AppProxyProvider", "$(PRODUCT_MODULE_NAME).PacketTunnelProvider")

    text = insert_before(
        text,
        "/* End PBXBuildFile section */\n",
        "\t\t71C200000000000000000001 /* PacketTunnelProvider.swift in Sources */ = {isa = PBXBuildFile; fileRef = 71C200000000000000000032 /* PacketTunnelProvider.swift */; };\n"
        "\t\t71C200000000000000000002 /* ObstacleBridgePythonBridge.m in Sources */ = {isa = PBXBuildFile; fileRef = 71C200000000000000000033 /* ObstacleBridgePythonBridge.m */; };\n"
        "\t\t71C200000000000000000007 /* ObstacleBridgePacketFlowBridge.swift in Sources */ = {isa = PBXBuildFile; fileRef = 71C200000000000000000038 /* ObstacleBridgePacketFlowBridge.swift */; };\n"
        "\t\t71C200000000000000000003 /* Foundation.framework in Frameworks */ = {isa = PBXBuildFile; fileRef = 610000000000000000000900 /* Foundation.framework */; };\n"
        "\t\t71C200000000000000000004 /* NetworkExtension.framework in Frameworks */ = {isa = PBXBuildFile; fileRef = 71C200000000000000000030 /* NetworkExtension.framework */; };\n"
        "\t\t71C200000000000000000005 /* Python.xcframework in Frameworks */ = {isa = PBXBuildFile; fileRef = 60813D352B02EBFC00EFB492 /* Python.xcframework */; };\n"
        "\t\t71C200000000000000000006 /* IPServer.appex in Embed App Extensions */ = {isa = PBXBuildFile; fileRef = 71C200000000000000000031 /* IPServer.appex */; settings = {ATTRIBUTES = (RemoveHeadersOnCopy, ); }; };\n",
    )
    text = insert_before(
        text,
        "/* End PBXCopyFilesBuildPhase section */\n",
        "\t\t71C200000000000000000010 /* Embed App Extensions */ = {\n"
        "\t\t\tisa = PBXCopyFilesBuildPhase;\n"
        "\t\t\tbuildActionMask = 2147483647;\n"
        "\t\t\tdstPath = \"\";\n"
        "\t\t\tdstSubfolderSpec = 13;\n"
        "\t\t\tfiles = (\n"
        "\t\t\t\t71C200000000000000000006 /* IPServer.appex in Embed App Extensions */,\n"
        "\t\t\t);\n"
        "\t\t\tname = \"Embed App Extensions\";\n"
        "\t\t\trunOnlyForDeploymentPostprocessing = 0;\n"
        "\t\t};\n",
    )
    text = insert_before(
        text,
        "/* Begin PBXFileReference section */\n",
        "/* Begin PBXContainerItemProxy section */\n"
        "\t\t71C200000000000000000020 /* PBXContainerItemProxy */ = {\n"
        "\t\t\tisa = PBXContainerItemProxy;\n"
        "\t\t\tcontainerPortal = 60796EDA19190F4100A9926B /* Project object */;\n"
        "\t\t\tproxyType = 1;\n"
        "\t\t\tremoteGlobalIDString = 71C200000000000000000060;\n"
        "\t\t\tremoteInfo = IPServer;\n"
        "\t\t};\n"
        "/* End PBXContainerItemProxy section */\n\n",
    )
    text = insert_before(
        text,
        "/* End PBXFileReference section */\n",
        "\t\t71C200000000000000000030 /* NetworkExtension.framework */ = {isa = PBXFileReference; lastKnownFileType = wrapper.framework; name = NetworkExtension.framework; path = System/Library/Frameworks/NetworkExtension.framework; sourceTree = SDKROOT; };\n"
        "\t\t71C200000000000000000031 /* IPServer.appex */ = {isa = PBXFileReference; explicitFileType = \"wrapper.app-extension\"; includeInIndex = 0; path = IPServer.appex; sourceTree = BUILT_PRODUCTS_DIR; };\n"
        "\t\t71C200000000000000000032 /* PacketTunnelProvider.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = PacketTunnelProvider.swift; path = \"GeneratedSources/IPServer/PacketTunnelProvider.swift\"; sourceTree = SOURCE_ROOT; };\n"
        "\t\t71C200000000000000000033 /* ObstacleBridgePythonBridge.m */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.c.objc; name = ObstacleBridgePythonBridge.m; path = \"../../../../native/IPServer/ObstacleBridgePythonBridge.m\"; sourceTree = SOURCE_ROOT; };\n"
        "\t\t71C200000000000000000034 /* ObstacleBridgePythonBridge.h */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.c.h; name = ObstacleBridgePythonBridge.h; path = \"../../../../native/IPServer/ObstacleBridgePythonBridge.h\"; sourceTree = SOURCE_ROOT; };\n"
        "\t\t71C200000000000000000035 /* IPServer-Bridging-Header.h */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.c.h; name = \"IPServer-Bridging-Header.h\"; path = \"../../../../native/IPServer/IPServer-Bridging-Header.h\"; sourceTree = SOURCE_ROOT; };\n"
        "\t\t71C200000000000000000036 /* Info.plist */ = {isa = PBXFileReference; lastKnownFileType = text.plist.xml; name = Info.plist; path = \"../../../../native/IPServer/Info.plist\"; sourceTree = SOURCE_ROOT; };\n"
        "\t\t71C200000000000000000037 /* IPServer.entitlements */ = {isa = PBXFileReference; lastKnownFileType = text.plist.entitlements; name = IPServer.entitlements; path = \"../../../../native/IPServer/IPServer.entitlements\"; sourceTree = SOURCE_ROOT; };\n"
        "\t\t71C200000000000000000038 /* ObstacleBridgePacketFlowBridge.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = ObstacleBridgePacketFlowBridge.swift; path = \"../../../../native/IPServer/ObstacleBridgePacketFlowBridge.swift\"; sourceTree = SOURCE_ROOT; };\n",
    )
    text = insert_before(
        text,
        "/* End PBXFrameworksBuildPhase section */\n",
        "\t\t71C200000000000000000040 /* Frameworks */ = {\n"
        "\t\t\tisa = PBXFrameworksBuildPhase;\n"
        "\t\t\tbuildActionMask = 2147483647;\n"
        "\t\t\tfiles = (\n"
        "\t\t\t\t71C200000000000000000003 /* Foundation.framework in Frameworks */,\n"
        "\t\t\t\t71C200000000000000000004 /* NetworkExtension.framework in Frameworks */,\n"
        "\t\t\t\t71C200000000000000000005 /* Python.xcframework in Frameworks */,\n"
        "\t\t\t);\n"
        "\t\t\trunOnlyForDeploymentPostprocessing = 0;\n"
        "\t\t};\n",
    )
    if "71C200000000000000000050 /* IPServer Extension */" not in text:
        text = replace_once(
            text,
            "\t\t60796ED919190F4100A9926B = {\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t60A04BC228B35E9F00DAA9E5 /* Support */,\n\t\t\t\t60796EEB19190F4100A9926B /* ObstacleBridge */,\n\t\t\t\t60796EE419190F4100A9926B /* Frameworks */,\n\t\t\t\t60796EE319190F4100A9926B /* Products */,\n\t\t\t);\n\t\t\tsourceTree = \"<group>\";\n\t\t};\n",
            "\t\t60796ED919190F4100A9926B = {\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t60A04BC228B35E9F00DAA9E5 /* Support */,\n\t\t\t\t60796EEB19190F4100A9926B /* ObstacleBridge */,\n\t\t\t\t71C200000000000000000050 /* IPServer Extension */,\n\t\t\t\t60796EE419190F4100A9926B /* Frameworks */,\n\t\t\t\t60796EE319190F4100A9926B /* Products */,\n\t\t\t);\n\t\t\tsourceTree = \"<group>\";\n\t\t};\n",
        )
    if "71C200000000000000000031 /* IPServer.appex */" not in text:
        text = replace_once(
            text,
            "\t\t60796EE319190F4100A9926B /* Products */ = {\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t610000000000000000100400 /* ObstacleBridge.app */,\n\t\t\t);\n\t\t\tname = Products;\n\t\t\tsourceTree = \"<group>\";\n\t\t};\n",
            "\t\t60796EE319190F4100A9926B /* Products */ = {\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t610000000000000000100400 /* ObstacleBridge.app */,\n\t\t\t\t71C200000000000000000031 /* IPServer.appex */,\n\t\t\t);\n\t\t\tname = Products;\n\t\t\tsourceTree = \"<group>\";\n\t\t};\n",
        )
    if "71C200000000000000000030 /* NetworkExtension.framework */" not in text:
        text = replace_once(
            text,
            "\t\t60796EE419190F4100A9926B /* Frameworks */ = {\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t610000000000000000000800 /* CoreGraphics.framework */,\n\t\t\t\t610000000000000000000900 /* Foundation.framework */,\n\t\t\t\t610000000000000000000A00 /* UIKit.framework */,\n\t\t\t\t60C0057828F7DB9A008B9E84 /* WebKit.framework */,\n\t\t\t);\n\t\t\tname = Frameworks;\n\t\t\tsourceTree = \"<group>\";\n\t\t};\n",
            "\t\t60796EE419190F4100A9926B /* Frameworks */ = {\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t610000000000000000000800 /* CoreGraphics.framework */,\n\t\t\t\t610000000000000000000900 /* Foundation.framework */,\n\t\t\t\t71C200000000000000000030 /* NetworkExtension.framework */,\n\t\t\t\t610000000000000000000A00 /* UIKit.framework */,\n\t\t\t\t60C0057828F7DB9A008B9E84 /* WebKit.framework */,\n\t\t\t);\n\t\t\tname = Frameworks;\n\t\t\tsourceTree = \"<group>\";\n\t\t};\n",
        )
    text = insert_before(
        text,
        "/* End PBXGroup section */\n",
        "\t\t71C200000000000000000050 /* IPServer Extension */ = {\n"
        "\t\t\tisa = PBXGroup;\n"
        "\t\t\tchildren = (\n"
        "\t\t\t\t71C200000000000000000032 /* PacketTunnelProvider.swift */,\n"
        "\t\t\t\t71C200000000000000000038 /* ObstacleBridgePacketFlowBridge.swift */,\n"
        "\t\t\t\t71C200000000000000000033 /* ObstacleBridgePythonBridge.m */,\n"
        "\t\t\t\t71C200000000000000000034 /* ObstacleBridgePythonBridge.h */,\n"
        "\t\t\t\t71C200000000000000000035 /* IPServer-Bridging-Header.h */,\n"
        "\t\t\t\t71C200000000000000000036 /* Info.plist */,\n"
        "\t\t\t\t71C200000000000000000037 /* IPServer.entitlements */,\n"
        "\t\t\t);\n"
        "\t\t\tname = \"IPServer Extension\";\n"
        "\t\t\tsourceTree = \"<group>\";\n"
        "\t\t};\n",
    )
    text = insert_before(
        text,
        "/* End PBXNativeTarget section */\n",
        "\t\t71C200000000000000000060 /* IPServer */ = {\n"
        "\t\t\tisa = PBXNativeTarget;\n"
        "\t\t\tbuildConfigurationList = 71C2000000000000000000B0 /* Build configuration list for PBXNativeTarget \"IPServer\" */;\n"
        "\t\t\tbuildPhases = (\n"
        "\t\t\t\t71C200000000000000000080 /* Sources */,\n"
        "\t\t\t\t71C200000000000000000040 /* Frameworks */,\n"
        "\t\t\t\t71C200000000000000000070 /* Resources */,\n"
        "\t\t\t\t71C2000000000000000000C0 /* Process Python libraries for IPServer */,\n"
        "\t\t\t);\n"
        "\t\t\tbuildRules = (\n"
        "\t\t\t);\n"
        "\t\t\tdependencies = (\n"
        "\t\t\t);\n"
        "\t\t\tname = IPServer;\n"
        "\t\t\tproductName = IPServer;\n"
        "\t\t\tproductReference = 71C200000000000000000031 /* IPServer.appex */;\n"
        "\t\t\tproductType = \"com.apple.product-type.app-extension\";\n"
        "\t\t};\n",
    )
    text = replace_once(
        text,
        "\t\t\tprojectDirPath = \"\";\n\t\t\tprojectRoot = \"\";\n\t\t\ttargets = (\n\t\t\t\t60796EE119190F4100A9926B /* ObstacleBridge */,\n\t\t\t);\n",
        "\t\t\tprojectDirPath = \"\";\n\t\t\tprojectRoot = \"\";\n\t\t\ttargets = (\n\t\t\t\t60796EE119190F4100A9926B /* ObstacleBridge */,\n\t\t\t\t71C200000000000000000060 /* IPServer */,\n\t\t\t);\n",
    )
    text = insert_before(
        text,
        "/* End PBXResourcesBuildPhase section */\n",
        "\t\t71C200000000000000000070 /* Resources */ = {\n"
        "\t\t\tisa = PBXResourcesBuildPhase;\n"
        "\t\t\tbuildActionMask = 2147483647;\n"
        "\t\t\tfiles = (\n"
        "\t\t\t);\n"
        "\t\t\trunOnlyForDeploymentPostprocessing = 0;\n"
        "\t\t};\n",
    )
    text = insert_before(
        text,
        "/* End PBXShellScriptBuildPhase section */\n",
        "\t\t71C2000000000000000000C0 /* Process Python libraries for IPServer */ = {\n"
        "\t\t\tisa = PBXShellScriptBuildPhase;\n"
        "\t\t\talwaysOutOfDate = 1;\n"
        "\t\t\tbuildActionMask = 2147483647;\n"
        "\t\t\tfiles = (\n"
        "\t\t\t);\n"
        "\t\t\tinputFileListPaths = (\n"
        "\t\t\t);\n"
        "\t\t\tinputPaths = (\n"
        "\t\t\t);\n"
        "\t\t\tname = \"Process Python libraries for IPServer\";\n"
        "\t\t\toutputFileListPaths = (\n"
        "\t\t\t);\n"
        "\t\t\toutputPaths = (\n"
        "\t\t\t);\n"
        "\t\t\trunOnlyForDeploymentPostprocessing = 0;\n"
        "\t\t\tshellPath = /bin/sh;\n"
        "\t\t\tshellScript = \"set -e\\nsource $PROJECT_DIR/Support/Python.xcframework/build/utils.sh\\n\\nif [ -z \\\"${EXPANDED_CODE_SIGN_IDENTITY:-}\\\" ]; then\\n    export EXPANDED_CODE_SIGN_IDENTITY=-\\n    export EXPANDED_CODE_SIGN_IDENTITY_NAME=\\\"Ad Hoc\\\"\\nfi\\n\\nif [ \\\"$EFFECTIVE_PLATFORM_NAME\\\" = \\\"-iphonesimulator\\\" ]; then\\n    PACKAGES_PATH=\\\"app_packages.iphonesimulator\\\"\\nelse\\n    PACKAGES_PATH=\\\"app_packages.iphoneos\\\"\\nfi\\nrsync -au --delete \\\"$PROJECT_DIR/ObstacleBridge/$PACKAGES_PATH/\\\" \\\"$CODESIGNING_FOLDER_PATH/app_packages\\\"\\ninstall_python Support/Python.xcframework app_packages\\n\";\n"
        "\t\t};\n",
    )
    if "71C200000000000000000080 /* Sources */ = {" in text:
        text = add_ipserver_native_crypto_source(text)
        text = add_ipserver_packet_flow_bridge_source(text)
        text = add_ipserver_shared_swift_sources(text)
    else:
        text = insert_before(
            text,
            "/* End PBXSourcesBuildPhase section */\n",
            "\t\t71C200000000000000000080 /* Sources */ = {\n"
            "\t\t\tisa = PBXSourcesBuildPhase;\n"
            "\t\t\tbuildActionMask = 2147483647;\n"
            "\t\t\tfiles = (\n"
            "\t\t\t\t71C200000000000000000001 /* PacketTunnelProvider.swift in Sources */,\n"
            "\t\t\t\t71C200000000000000000007 /* ObstacleBridgePacketFlowBridge.swift in Sources */,\n"
            "\t\t\t\t71C200000000000000000002 /* ObstacleBridgePythonBridge.m in Sources */,\n"
            "\t\t\t\t71C300000000000000000002 /* ObstacleBridgeNativeCrypto.swift in IPServer Sources */,\n"
            "\t\t\t\t71C500000000000000000001 /* ObstacleBridgeAdminAPI.swift in Sources */,\n"
            "\t\t\t\t71C500000000000000000002 /* ObstacleBridgeChannelMuxCodec.swift in Sources */,\n"
            "\t\t\t\t71C500000000000000000003 /* ObstacleBridgeSecureLinkPskCodec.swift in Sources */,\n"
            "\t\t\t\t71C500000000000000000004 /* ObstacleBridgeSecureLinkPskRuntime.swift in Sources */,\n"
            "\t\t\t\t71C500000000000000000005 /* ObstacleBridgeSecureLinkPskTransportAdapter.swift in Sources */,\n"
            "\t\t\t\t71C500000000000000000006 /* ObstacleBridgeOverlayLayerTransportAdapter.swift in Sources */,\n"
            "\t\t\t\t71C500000000000000000007 /* ObstacleBridgeRuntimeConfig.swift in Sources */,\n"
            "\t\t\t\t71C500000000000000000008 /* ObstacleBridgeChannelMuxTunRuntime.swift in Sources */,\n"
            "\t\t\t\t71C500000000000000000009 /* ObstacleBridgeUdpOverlayCodec.swift in Sources */,\n"
            "\t\t\t\t71C50000000000000000000A /* ObstacleBridgeUdpOverlaySessionCodec.swift in Sources */,\n"
            "\t\t\t\t71C50000000000000000000B /* ObstacleBridgeUdpOverlayPeerRuntime.swift in Sources */,\n"
            "\t\t\t\t71C50000000000000000000C /* ObstacleBridgeChannelMuxTcpRuntime.swift in Sources */,\n"
            "\t\t\t\t71C50000000000000000000D /* ObstacleBridgeChannelMuxTCPTransportOwner.swift in Sources */,\n"
            "\t\t\t\t71C50000000000000000000E /* ObstacleBridgeCompressLayerRuntime.swift in Sources */,\n"
            "\t\t\t\t71C50000000000000000000F /* ObstacleBridgeOverlayStackPlanner.swift in Sources */,\n"
            "\t\t\t\t71C500000000000000000010 /* ObstacleBridgePacketTunnelConfiguration.swift in Sources */,\n"
            "\t\t\t\t71C500000000000000000011 /* ObstacleBridgeWebSocketPayloadCodec.swift in Sources */,\n"
            "\t\t\t\t71C500000000000000000012 /* ObstacleBridgeWebSocketOverlayRuntime.swift in Sources */,\n"
            "\t\t\t\t71C500000000000000000013 /* ObstacleBridgeTcpOverlayRuntime.swift in Sources */,\n"
            "\t\t\t);\n"
            "\t\t\trunOnlyForDeploymentPostprocessing = 0;\n"
            "\t\t};\n",
        )
    text = insert_before(
        text,
        "/* Begin PBXVariantGroup section */\n",
        "/* Begin PBXTargetDependency section */\n"
        "\t\t71C200000000000000000090 /* PBXTargetDependency */ = {\n"
        "\t\t\tisa = PBXTargetDependency;\n"
        "\t\t\ttarget = 71C200000000000000000060 /* IPServer */;\n"
        "\t\t\ttargetProxy = 71C200000000000000000020 /* PBXContainerItemProxy */;\n"
        "\t\t};\n"
        "/* End PBXTargetDependency section */\n\n",
    )
    text = insert_before(
        text,
        "/* End XCBuildConfiguration section */\n",
        "\t\t71C2000000000000000000A0 /* Debug */ = {\n"
        "\t\t\tisa = XCBuildConfiguration;\n"
        "\t\t\tbuildSettings = {\n"
        "\t\t\t\tAPPLICATION_EXTENSION_API_ONLY = YES;\n"
        "\t\t\t\tCODE_SIGN_ENTITLEMENTS = \"../../../../native/IPServer/IPServer.entitlements\";\n"
        "\t\t\t\tCODE_SIGN_STYLE = Automatic;\n"
        "\t\t\t\tCURRENT_PROJECT_VERSION = 1;\n"
        "\t\t\t\tDEVELOPMENT_TEAM = 99WZ498FCV;\n"
        "\t\t\t\tFRAMEWORK_SEARCH_PATHS = \"\\\"$(PROJECT_DIR)/Support\\\"\";\n"
        "\t\t\t\tGENERATE_INFOPLIST_FILE = NO;\n"
        "\t\t\t\tHEADER_SEARCH_PATHS = \"\\\"$(BUILT_PRODUCTS_DIR)/Python.framework/Headers\\\"\";\n"
        "\t\t\t\tINFOPLIST_FILE = \"../../../../native/IPServer/Info.plist\";\n"
        "\t\t\t\tIPHONEOS_DEPLOYMENT_TARGET = 13.0;\n"
        "\t\t\t\tLD_RUNPATH_SEARCH_PATHS = (\n"
        "\t\t\t\t\t\"$(inherited)\",\n"
        "\t\t\t\t\t\"@executable_path/Frameworks\",\n"
        "\t\t\t\t\t\"@executable_path/../../Frameworks\",\n"
        "\t\t\t\t);\n"
        "\t\t\t\tMARKETING_VERSION = 0.1.0;\n"
        "\t\t\t\tPRODUCT_BUNDLE_IDENTIFIER = \"com.obstaclebridge.obstacle-bridge-ios.IPServer\";\n"
        "\t\t\t\tPRODUCT_NAME = \"$(TARGET_NAME)\";\n"
        "\t\t\t\tSKIP_INSTALL = YES;\n"
        "\t\t\t\tSWIFT_OBJC_BRIDGING_HEADER = \"../../../../native/IPServer/IPServer-Bridging-Header.h\";\n"
        "\t\t\t\tSWIFT_VERSION = 5.0;\n"
        "\t\t\t\tTARGETED_DEVICE_FAMILY = \"1,2\";\n"
        "\t\t\t\tWRAPPER_EXTENSION = appex;\n"
        "\t\t\t};\n"
        "\t\t\tname = Debug;\n"
        "\t\t};\n"
        "\t\t71C2000000000000000000A1 /* Release */ = {\n"
        "\t\t\tisa = XCBuildConfiguration;\n"
        "\t\t\tbuildSettings = {\n"
        "\t\t\t\tAPPLICATION_EXTENSION_API_ONLY = YES;\n"
        "\t\t\t\tCODE_SIGN_ENTITLEMENTS = \"../../../../native/IPServer/IPServer.entitlements\";\n"
        "\t\t\t\tCODE_SIGN_STYLE = Automatic;\n"
        "\t\t\t\tCURRENT_PROJECT_VERSION = 1;\n"
        "\t\t\t\tDEVELOPMENT_TEAM = 99WZ498FCV;\n"
        "\t\t\t\tFRAMEWORK_SEARCH_PATHS = \"\\\"$(PROJECT_DIR)/Support\\\"\";\n"
        "\t\t\t\tGENERATE_INFOPLIST_FILE = NO;\n"
        "\t\t\t\tHEADER_SEARCH_PATHS = \"\\\"$(BUILT_PRODUCTS_DIR)/Python.framework/Headers\\\"\";\n"
        "\t\t\t\tINFOPLIST_FILE = \"../../../../native/IPServer/Info.plist\";\n"
        "\t\t\t\tIPHONEOS_DEPLOYMENT_TARGET = 13.0;\n"
        "\t\t\t\tLD_RUNPATH_SEARCH_PATHS = (\n"
        "\t\t\t\t\t\"$(inherited)\",\n"
        "\t\t\t\t\t\"@executable_path/Frameworks\",\n"
        "\t\t\t\t\t\"@executable_path/../../Frameworks\",\n"
        "\t\t\t\t);\n"
        "\t\t\t\tMARKETING_VERSION = 0.1.0;\n"
        "\t\t\t\tPRODUCT_BUNDLE_IDENTIFIER = \"com.obstaclebridge.obstacle-bridge-ios.IPServer\";\n"
        "\t\t\t\tPRODUCT_NAME = \"$(TARGET_NAME)\";\n"
        "\t\t\t\tSKIP_INSTALL = YES;\n"
        "\t\t\t\tSWIFT_OBJC_BRIDGING_HEADER = \"../../../../native/IPServer/IPServer-Bridging-Header.h\";\n"
        "\t\t\t\tSWIFT_VERSION = 5.0;\n"
        "\t\t\t\tTARGETED_DEVICE_FAMILY = \"1,2\";\n"
        "\t\t\t\tWRAPPER_EXTENSION = appex;\n"
        "\t\t\t};\n"
        "\t\t\tname = Release;\n"
        "\t\t};\n",
    )
    text = insert_before(
        text,
        "/* End XCConfigurationList section */\n",
        "\t\t71C2000000000000000000B0 /* Build configuration list for PBXNativeTarget \"IPServer\" */ = {\n"
        "\t\t\tisa = XCConfigurationList;\n"
        "\t\t\tbuildConfigurations = (\n"
        "\t\t\t\t71C2000000000000000000A0 /* Debug */,\n"
        "\t\t\t\t71C2000000000000000000A1 /* Release */,\n"
        "\t\t\t);\n"
        "\t\t\tdefaultConfigurationIsVisible = 0;\n"
        "\t\t\tdefaultConfigurationName = Release;\n"
        "\t\t};\n",
    )
    return text


def patch_pbxproj_text(text: str) -> str:
    # Diagnostic builds may inject these flags manually. They must never
    # persist into the normal generated project because they bypass Python
    # startup or WebAdmin startup inside the Network Extension.
    text = re.sub(r'\n\t+\t*OTHER_SWIFT_FLAGS = "-D OB_IPSERVER_(?:SWIFT_SMOKE|PYTHON_PROBE)";', "", text)
    text = patch_python_build_script(text)
    text = patch_app_target(text)
    text = patch_ipserver_target(text)
    return text


def ensure_generated_packet_tunnel_provider(pbxproj_path: Path) -> Path:
    xcode_root = pbxproj_path.resolve().parent.parent
    generated_path = xcode_root / GENERATED_PACKET_TUNNEL_PROVIDER_RELATIVE
    generated_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPO_PACKET_TUNNEL_PROVIDER, generated_path)
    return generated_path


def patch_pbxproj_file(path: Path) -> bool:
    ensure_generated_packet_tunnel_provider(path)
    original = path.read_text(encoding="utf-8")
    patched = patch_pbxproj_text(original)
    if patched == original:
        return False
    path.write_text(patched, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pbxproj", nargs="?", type=Path, default=DEFAULT_PROJECT)
    args = parser.parse_args()
    path = args.pbxproj.resolve()
    if not path.is_file():
        raise SystemExit(f"Xcode project file not found: {path}")
    changed = patch_pbxproj_file(path)
    print(f"{'patched' if changed else 'already configured'}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
