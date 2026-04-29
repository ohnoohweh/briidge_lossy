#!/usr/bin/env python3
"""Patch Briefcase's generated iOS Xcode project with the Packet Tunnel target."""

from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROJECT = ROOT / "ios" / "build" / "obstacle_bridge_ios" / "ios" / "xcode" / "ObstacleBridge.xcodeproj" / "project.pbxproj"


IDS = {
    "network_extension_framework_ref": "60F300000000000000000001",
    "network_extension_framework_build": "60F300000000000000000002",
    "provider_ref": "60F300000000000000000010",
    "flow_ref": "60F300000000000000000011",
    "status_ref": "60F300000000000000000012",
    "runtime_ref": "60F300000000000000000013",
    "webadmin_ref": "60F300000000000000000014",
    "python_runtime_header_ref": "60F300000000000000000015",
    "python_runtime_impl_ref": "60F300000000000000000016",
    "bridging_header_ref": "60F300000000000000000017",
    "provider_build": "60F300000000000000000020",
    "flow_build": "60F300000000000000000021",
    "status_build": "60F300000000000000000022",
    "runtime_build": "60F300000000000000000023",
    "webadmin_build": "60F300000000000000000024",
    "python_runtime_impl_build": "60F300000000000000000025",
    "python_framework_build": "60F300000000000000000026",
    "product_ref": "60F300000000000000000030",
    "product_embed_build": "60F300000000000000000031",
    "sources_phase": "60F300000000000000000040",
    "frameworks_phase": "60F300000000000000000041",
    "target": "60F300000000000000000050",
    "target_dep": "60F300000000000000000051",
    "container_proxy": "60F300000000000000000052",
    "copy_phase": "60F300000000000000000060",
    "ad_hoc_sign_phase": "60F300000000000000000061",
    "target_config_list": "60F300000000000000000070",
    "target_debug_config": "60F300000000000000000071",
    "target_release_config": "60F300000000000000000072",
    "group": "60F300000000000000000080",
}


MARKER = IDS["target"] + " /* ObstacleBridgeTunnel */"


def insert_before(text: str, marker: str, payload: str) -> str:
    if payload.strip() in text:
        return text
    index = text.index(marker)
    return text[:index] + payload + text[index:]


def add_list_item(text: str, section_anchor: str, item: str) -> str:
    start = text.index(section_anchor)
    item_text = f"\n\t\t\t\t{item},"
    end = text.index("\n\t\t\t);", start)
    block = text[start:end]
    if item in block:
        return text
    return text[:end] + item_text + text[end:]


def patch_ad_hoc_sign_phase(text: str) -> str:
    phase_id = IDS["ad_hoc_sign_phase"]
    if phase_id not in text:
        text = text.replace(
            "/* End PBXShellScriptBuildPhase section */",
            f"""\t\t{phase_id} /* Ad Hoc Sign Packet Tunnel Extension */ = {{
\t\t\tisa = PBXShellScriptBuildPhase;
\t\t\talwaysOutOfDate = 1;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t);
\t\t\tinputFileListPaths = (
\t\t\t);
\t\t\tinputPaths = (
\t\t\t);
\t\t\tname = "Ad Hoc Sign Packet Tunnel Extension";
\t\t\toutputFileListPaths = (
\t\t\t);
\t\t\toutputPaths = (
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t\tshellPath = /bin/sh;
\t\t\tshellScript = "set -e\\nAPPEX=\\"$TARGET_BUILD_DIR/$WRAPPER_NAME/PlugIns/ObstacleBridgeTunnel.appex\\"\\nif [ -d \\"$APPEX\\" ] && [ \\"${{EXPANDED_CODE_SIGN_IDENTITY:-}}\\" = \\"-\\" ]; then\\n    echo \\"Ad hoc signing ObstacleBridgeTunnel.appex\\"\\n    /usr/bin/codesign --force --sign - --timestamp=none \\"$APPEX\\"\\nfi\\n";
\t\t\tshowEnvVarsInLog = 0;
\t\t}};
/* End PBXShellScriptBuildPhase section */""",
            1,
        )
    phase_item = f"{phase_id} /* Ad Hoc Sign Packet Tunnel Extension */"
    anchor = f"\t\t\t\t{IDS['copy_phase']} /* Embed App Extensions */,\n"
    app_build_phase_block = text[
        text.index("\t\t60796EE119190F4100A9926B /* ObstacleBridge */ = {") :
        text.index("\t\t60F300000000000000000050 /* ObstacleBridgeTunnel */ = {")
    ]
    if phase_item not in app_build_phase_block:
        text = text.replace(anchor, anchor + f"\t\t\t\t{phase_item},\n", 1)
    return text


def patch_local_webadmin_source(text: str) -> str:
    if IDS["webadmin_build"] not in text:
        text = text.replace(
            "/* Begin PBXBuildFile section */\n",
            "/* Begin PBXBuildFile section */\n"
            f"\t\t{IDS['webadmin_build']} /* LocalWebAdminServer.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {IDS['webadmin_ref']} /* LocalWebAdminServer.swift */; }};\n",
            1,
        )
    if f"{IDS['webadmin_ref']} /* LocalWebAdminServer.swift */ = {{isa = PBXFileReference;" not in text:
        text = text.replace(
            "/* Begin PBXFileReference section */\n",
            "/* Begin PBXFileReference section */\n"
            f"\t\t{IDS['webadmin_ref']} /* LocalWebAdminServer.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = LocalWebAdminServer.swift; path = \"../../../../native/ObstacleBridgeTunnel/LocalWebAdminServer.swift\"; sourceTree = SOURCE_ROOT; }};\n",
            1,
        )
    group_anchor = f"\t\t\t\t{IDS['runtime_ref']} /* ObstacleBridgeExtensionRuntime.swift */,"
    if text.count(f"{IDS['webadmin_ref']} /* LocalWebAdminServer.swift */") < 2:
        text = text.replace(
            group_anchor,
            group_anchor + f"\n\t\t\t\t{IDS['webadmin_ref']} /* LocalWebAdminServer.swift */,",
            1,
        )
    sources_anchor = f"\t\t\t\t{IDS['runtime_build']} /* ObstacleBridgeExtensionRuntime.swift in Sources */,"
    if text.count(f"{IDS['webadmin_build']} /* LocalWebAdminServer.swift in Sources */") < 2:
        text = text.replace(
            sources_anchor,
            sources_anchor + f"\n\t\t\t\t{IDS['webadmin_build']} /* LocalWebAdminServer.swift in Sources */,",
            1,
        )
    return text


def patch_extension_python_runtime_source(text: str) -> str:
    if IDS["python_runtime_impl_build"] not in text:
        text = text.replace(
            "/* Begin PBXBuildFile section */\n",
            "/* Begin PBXBuildFile section */\n"
            f"\t\t{IDS['python_runtime_impl_build']} /* ObstacleBridgePythonRuntime.m in Sources */ = {{isa = PBXBuildFile; fileRef = {IDS['python_runtime_impl_ref']} /* ObstacleBridgePythonRuntime.m */; }};\n"
            f"\t\t{IDS['python_framework_build']} /* Python.xcframework in Frameworks */ = {{isa = PBXBuildFile; fileRef = 60813D352B02EBFC00EFB492 /* Python.xcframework */; }};\n",
            1,
        )
    for ref_id, name, file_type in (
        (IDS["python_runtime_header_ref"], "ObstacleBridgePythonRuntime.h", "sourcecode.c.h"),
        (IDS["python_runtime_impl_ref"], "ObstacleBridgePythonRuntime.m", "sourcecode.c.objc"),
        (IDS["bridging_header_ref"], "ObstacleBridgeTunnel-Bridging-Header.h", "sourcecode.c.h"),
    ):
        if f"{ref_id} /* {name} */ = {{isa = PBXFileReference;" not in text:
            text = text.replace(
                "/* Begin PBXFileReference section */\n",
                "/* Begin PBXFileReference section */\n"
                f"\t\t{ref_id} /* {name} */ = {{isa = PBXFileReference; lastKnownFileType = {file_type}; name = {name}; path = \"../../../../native/ObstacleBridgeTunnel/{name}\"; sourceTree = SOURCE_ROOT; }};\n",
                1,
            )
    group_anchor = f"\t\t\t\t{IDS['webadmin_ref']} /* LocalWebAdminServer.swift */,"
    for ref_id, name in (
        (IDS["python_runtime_header_ref"], "ObstacleBridgePythonRuntime.h"),
        (IDS["python_runtime_impl_ref"], "ObstacleBridgePythonRuntime.m"),
        (IDS["bridging_header_ref"], "ObstacleBridgeTunnel-Bridging-Header.h"),
    ):
        if text.count(f"{ref_id} /* {name} */") < 2:
            text = text.replace(group_anchor, group_anchor + f"\n\t\t\t\t{ref_id} /* {name} */,", 1)
            group_anchor = f"\t\t\t\t{ref_id} /* {name} */,"
    sources_anchor = f"\t\t\t\t{IDS['webadmin_build']} /* LocalWebAdminServer.swift in Sources */,"
    if text.count(f"{IDS['python_runtime_impl_build']} /* ObstacleBridgePythonRuntime.m in Sources */") < 2:
        text = text.replace(
            sources_anchor,
            sources_anchor + f"\n\t\t\t\t{IDS['python_runtime_impl_build']} /* ObstacleBridgePythonRuntime.m in Sources */,",
            1,
        )
    frameworks_anchor = f"\t\t\t\t{IDS['network_extension_framework_build']} /* NetworkExtension.framework in Frameworks */,"
    if text.count(f"{IDS['python_framework_build']} /* Python.xcframework in Frameworks */") < 2:
        text = text.replace(
            frameworks_anchor,
            frameworks_anchor + f"\n\t\t\t\t{IDS['python_framework_build']} /* Python.xcframework in Frameworks */,",
            1,
        )
    bridging = '\t\t\t\tSWIFT_OBJC_BRIDGING_HEADER = "../../../../native/ObstacleBridgeTunnel/ObstacleBridgeTunnel-Bridging-Header.h";\n'
    for marker in (
        f"\t\t{IDS['target_debug_config']} /* Debug */ = {{",
        f"\t\t{IDS['target_release_config']} /* Release */ = {{",
    ):
        start = text.index(marker)
        end = text.index("\t\t\t};", start)
        block = text[start:end]
        if "SWIFT_OBJC_BRIDGING_HEADER" not in block:
            insert_at = text.index("\t\t\t\tSWIFT_VERSION = 5.0;", start)
            line_end = text.index("\n", insert_at) + 1
            text = text[:line_end] + bridging + text[line_end:]
    return text


def patch_project(project_path: Path) -> bool:
    text = project_path.read_text(encoding="utf-8")
    if MARKER in text:
        updated = patch_extension_python_runtime_source(patch_local_webadmin_source(patch_ad_hoc_sign_phase(text)))
        if updated != text:
            project_path.write_text(updated, encoding="utf-8")
            return True
        return False

    text = text.replace(
        "/* Begin PBXBuildFile section */\n",
        "/* Begin PBXBuildFile section */\n"
        f"\t\t{IDS['network_extension_framework_build']} /* NetworkExtension.framework in Frameworks */ = {{isa = PBXBuildFile; fileRef = {IDS['network_extension_framework_ref']} /* NetworkExtension.framework */; }};\n"
        f"\t\t{IDS['provider_build']} /* PacketTunnelProvider.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {IDS['provider_ref']} /* PacketTunnelProvider.swift */; }};\n"
        f"\t\t{IDS['flow_build']} /* PacketFlowBridge.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {IDS['flow_ref']} /* PacketFlowBridge.swift */; }};\n"
        f"\t\t{IDS['status_build']} /* TunnelStatus.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {IDS['status_ref']} /* TunnelStatus.swift */; }};\n"
        f"\t\t{IDS['runtime_build']} /* ObstacleBridgeExtensionRuntime.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {IDS['runtime_ref']} /* ObstacleBridgeExtensionRuntime.swift */; }};\n"
        f"\t\t{IDS['webadmin_build']} /* LocalWebAdminServer.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {IDS['webadmin_ref']} /* LocalWebAdminServer.swift */; }};\n"
        f"\t\t{IDS['python_runtime_impl_build']} /* ObstacleBridgePythonRuntime.m in Sources */ = {{isa = PBXBuildFile; fileRef = {IDS['python_runtime_impl_ref']} /* ObstacleBridgePythonRuntime.m */; }};\n"
        f"\t\t{IDS['python_framework_build']} /* Python.xcframework in Frameworks */ = {{isa = PBXBuildFile; fileRef = 60813D352B02EBFC00EFB492 /* Python.xcframework */; }};\n"
        f"\t\t{IDS['product_embed_build']} /* ObstacleBridgeTunnel.appex in Embed App Extensions */ = {{isa = PBXBuildFile; fileRef = {IDS['product_ref']} /* ObstacleBridgeTunnel.appex */; settings = {{ATTRIBUTES = (CodeSignOnCopy, RemoveHeadersOnCopy, ); }}; }};\n",
        1,
    )

    text = text.replace(
        "/* End PBXCopyFilesBuildPhase section */",
        f"""\t\t{IDS['copy_phase']} /* Embed App Extensions */ = {{
\t\t\tisa = PBXCopyFilesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tdstPath = "";
\t\t\tdstSubfolderSpec = 13;
\t\t\tfiles = (
\t\t\t\t{IDS['product_embed_build']} /* ObstacleBridgeTunnel.appex in Embed App Extensions */,
\t\t\t);
\t\t\tname = "Embed App Extensions";
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t}};
/* End PBXCopyFilesBuildPhase section */""",
        1,
    )

    text = text.replace(
        "/* Begin PBXFileReference section */\n",
        "/* Begin PBXFileReference section */\n"
        f"\t\t{IDS['network_extension_framework_ref']} /* NetworkExtension.framework */ = {{isa = PBXFileReference; lastKnownFileType = wrapper.framework; name = NetworkExtension.framework; path = System/Library/Frameworks/NetworkExtension.framework; sourceTree = SDKROOT; }};\n"
        f"\t\t{IDS['provider_ref']} /* PacketTunnelProvider.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = PacketTunnelProvider.swift; path = \"../../../../native/ObstacleBridgeTunnel/PacketTunnelProvider.swift\"; sourceTree = SOURCE_ROOT; }};\n"
        f"\t\t{IDS['flow_ref']} /* PacketFlowBridge.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = PacketFlowBridge.swift; path = \"../../../../native/ObstacleBridgeTunnel/PacketFlowBridge.swift\"; sourceTree = SOURCE_ROOT; }};\n"
        f"\t\t{IDS['status_ref']} /* TunnelStatus.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = TunnelStatus.swift; path = \"../../../../native/ObstacleBridgeTunnel/TunnelStatus.swift\"; sourceTree = SOURCE_ROOT; }};\n"
        f"\t\t{IDS['runtime_ref']} /* ObstacleBridgeExtensionRuntime.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = ObstacleBridgeExtensionRuntime.swift; path = \"../../../../native/ObstacleBridgeTunnel/ObstacleBridgeExtensionRuntime.swift\"; sourceTree = SOURCE_ROOT; }};\n"
        f"\t\t{IDS['webadmin_ref']} /* LocalWebAdminServer.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = LocalWebAdminServer.swift; path = \"../../../../native/ObstacleBridgeTunnel/LocalWebAdminServer.swift\"; sourceTree = SOURCE_ROOT; }};\n"
        f"\t\t{IDS['python_runtime_header_ref']} /* ObstacleBridgePythonRuntime.h */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.c.h; name = ObstacleBridgePythonRuntime.h; path = \"../../../../native/ObstacleBridgeTunnel/ObstacleBridgePythonRuntime.h\"; sourceTree = SOURCE_ROOT; }};\n"
        f"\t\t{IDS['python_runtime_impl_ref']} /* ObstacleBridgePythonRuntime.m */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.c.objc; name = ObstacleBridgePythonRuntime.m; path = \"../../../../native/ObstacleBridgeTunnel/ObstacleBridgePythonRuntime.m\"; sourceTree = SOURCE_ROOT; }};\n"
        f"\t\t{IDS['bridging_header_ref']} /* ObstacleBridgeTunnel-Bridging-Header.h */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.c.h; name = ObstacleBridgeTunnel-Bridging-Header.h; path = \"../../../../native/ObstacleBridgeTunnel/ObstacleBridgeTunnel-Bridging-Header.h\"; sourceTree = SOURCE_ROOT; }};\n"
        f"\t\t{IDS['product_ref']} /* ObstacleBridgeTunnel.appex */ = {{isa = PBXFileReference; explicitFileType = \"wrapper.app-extension\"; includeInIndex = 0; path = ObstacleBridgeTunnel.appex; sourceTree = BUILT_PRODUCTS_DIR; }};\n",
        1,
    )

    text = text.replace(
        "/* End PBXFrameworksBuildPhase section */",
        f"""\t\t{IDS['frameworks_phase']} /* Frameworks */ = {{
\t\t\tisa = PBXFrameworksBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t\t{IDS['network_extension_framework_build']} /* NetworkExtension.framework in Frameworks */,
\t\t\t\t{IDS['python_framework_build']} /* Python.xcframework in Frameworks */,
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t}};
/* End PBXFrameworksBuildPhase section */""",
        1,
    )

    text = text.replace(
        "\t\t60796EE319190F4100A9926B /* Products */ = {\n"
        "\t\t\tisa = PBXGroup;\n"
        "\t\t\tchildren = (\n"
        "\t\t\t\t610000000000000000100400 /* ObstacleBridge.app */,\n",
        "\t\t60796EE319190F4100A9926B /* Products */ = {\n"
        "\t\t\tisa = PBXGroup;\n"
        "\t\t\tchildren = (\n"
        "\t\t\t\t610000000000000000100400 /* ObstacleBridge.app */,\n"
        f"\t\t\t\t{IDS['product_ref']} /* ObstacleBridgeTunnel.appex */,\n",
        1,
    )
    text = text.replace(
        "\t\t\tchildren = (\n"
        "\t\t\t\t610000000000000000000800 /* CoreGraphics.framework */,\n",
        "\t\t\tchildren = (\n"
        f"\t\t\t\t{IDS['network_extension_framework_ref']} /* NetworkExtension.framework */,\n"
        "\t\t\t\t610000000000000000000800 /* CoreGraphics.framework */,\n",
        1,
    )
    text = text.replace(
        "\t\t\t\t60796EEC19190F4100A9926B /* Supporting Files */,\n",
        f"\t\t\t\t{IDS['group']} /* ObstacleBridgeTunnel */,\n"
        "\t\t\t\t60796EEC19190F4100A9926B /* Supporting Files */,\n",
        1,
    )
    native_group = f"""\t\t{IDS['group']} /* ObstacleBridgeTunnel */ = {{
\t\t\tisa = PBXGroup;
\t\t\tchildren = (
\t\t\t\t{IDS['provider_ref']} /* PacketTunnelProvider.swift */,
\t\t\t\t{IDS['flow_ref']} /* PacketFlowBridge.swift */,
\t\t\t\t{IDS['status_ref']} /* TunnelStatus.swift */,
\t\t\t\t{IDS['runtime_ref']} /* ObstacleBridgeExtensionRuntime.swift */,
\t\t\t\t{IDS['webadmin_ref']} /* LocalWebAdminServer.swift */,
\t\t\t\t{IDS['python_runtime_header_ref']} /* ObstacleBridgePythonRuntime.h */,
\t\t\t\t{IDS['python_runtime_impl_ref']} /* ObstacleBridgePythonRuntime.m */,
\t\t\t\t{IDS['bridging_header_ref']} /* ObstacleBridgeTunnel-Bridging-Header.h */,
\t\t\t);
\t\t\tname = ObstacleBridgeTunnel;
\t\t\tsourceTree = "<group>";
\t\t}};
"""
    text = insert_before(text, "\t\t60796EEC19190F4100A9926B /* Supporting Files */ = {", native_group)

    target = f"""\t\t{IDS['target']} /* ObstacleBridgeTunnel */ = {{
\t\t\tisa = PBXNativeTarget;
\t\t\tbuildConfigurationList = {IDS['target_config_list']} /* Build configuration list for PBXNativeTarget "ObstacleBridgeTunnel" */;
\t\t\tbuildPhases = (
\t\t\t\t{IDS['sources_phase']} /* Sources */,
\t\t\t\t{IDS['frameworks_phase']} /* Frameworks */,
\t\t\t);
\t\t\tbuildRules = (
\t\t\t);
\t\t\tdependencies = (
\t\t\t);
\t\t\tname = ObstacleBridgeTunnel;
\t\t\tproductName = ObstacleBridgeTunnel;
\t\t\tproductReference = {IDS['product_ref']} /* ObstacleBridgeTunnel.appex */;
\t\t\tproductType = "com.apple.product-type.app-extension";
\t\t}};
"""
    text = insert_before(text, "/* End PBXNativeTarget section */", target)

    text = text.replace(
        "\t\t\tbuildPhases = (\n"
        "\t\t\t\t60796EDE19190F4100A9926B /* Sources */,\n"
        "\t\t\t\t60796EDF19190F4100A9926B /* Frameworks */,\n"
        "\t\t\t\t60796EE019190F4100A9926B /* Resources */,\n"
        "\t\t\t\t609384A628B5B958005B2A5D /* Process Python libraries */,\n"
        "\t\t\t\t6060E7A12AF8BF4400C04AE0 /* Embed Frameworks */,\n"
        "\t\t\t);\n",
        "\t\t\tbuildPhases = (\n"
        "\t\t\t\t60796EDE19190F4100A9926B /* Sources */,\n"
        "\t\t\t\t60796EDF19190F4100A9926B /* Frameworks */,\n"
        "\t\t\t\t60796EE019190F4100A9926B /* Resources */,\n"
        "\t\t\t\t609384A628B5B958005B2A5D /* Process Python libraries */,\n"
        "\t\t\t\t6060E7A12AF8BF4400C04AE0 /* Embed Frameworks */,\n"
        f"\t\t\t\t{IDS['copy_phase']} /* Embed App Extensions */,\n"
        "\t\t\t);\n",
        1,
    )
    text = text.replace(
        "\t\t\tdependencies = (\n\t\t\t);\n",
        f"\t\t\tdependencies = (\n\t\t\t\t{IDS['target_dep']} /* PBXTargetDependency */,\n\t\t\t);\n",
        1,
    )

    dep_sections = f"""/* Begin PBXContainerItemProxy section */
\t\t{IDS['container_proxy']} /* PBXContainerItemProxy */ = {{
\t\t\tisa = PBXContainerItemProxy;
\t\t\tcontainerPortal = 60796EDA19190F4100A9926B /* Project object */;
\t\t\tproxyType = 1;
\t\t\tremoteGlobalIDString = {IDS['target']};
\t\t\tremoteInfo = ObstacleBridgeTunnel;
\t\t}};
/* End PBXContainerItemProxy section */

/* Begin PBXTargetDependency section */
\t\t{IDS['target_dep']} /* PBXTargetDependency */ = {{
\t\t\tisa = PBXTargetDependency;
\t\t\ttarget = {IDS['target']} /* ObstacleBridgeTunnel */;
\t\t\ttargetProxy = {IDS['container_proxy']} /* PBXContainerItemProxy */;
\t\t}};
/* End PBXTargetDependency section */

"""
    text = text.replace("/* Begin PBXCopyFilesBuildPhase section */", dep_sections + "/* Begin PBXCopyFilesBuildPhase section */", 1)

    text = text.replace(
        "/* End PBXSourcesBuildPhase section */",
        f"""\t\t{IDS['sources_phase']} /* Sources */ = {{
\t\t\tisa = PBXSourcesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t\t{IDS['provider_build']} /* PacketTunnelProvider.swift in Sources */,
\t\t\t\t{IDS['flow_build']} /* PacketFlowBridge.swift in Sources */,
\t\t\t\t{IDS['status_build']} /* TunnelStatus.swift in Sources */,
\t\t\t\t{IDS['runtime_build']} /* ObstacleBridgeExtensionRuntime.swift in Sources */,
\t\t\t\t{IDS['webadmin_build']} /* LocalWebAdminServer.swift in Sources */,
\t\t\t\t{IDS['python_runtime_impl_build']} /* ObstacleBridgePythonRuntime.m in Sources */,
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t}};
/* End PBXSourcesBuildPhase section */""",
        1,
    )

    text = add_list_item(text, "\t\t\ttargets = (", f"{IDS['target']} /* ObstacleBridgeTunnel */")

    text = text.replace(
        "\t\t\t\tSWIFT_VERSION = 5.0;\n\t\t\t\tWRAPPER_EXTENSION = app;\n",
        "\t\t\t\tSWIFT_VERSION = 5.0;\n"
        "\t\t\t\tCODE_SIGN_ENTITLEMENTS = \"../../../../native/ObstacleBridgeTunnel/ObstacleBridge.entitlements\";\n"
        "\t\t\t\tWRAPPER_EXTENSION = app;\n",
        1,
    )
    text = text.replace(
        "\t\t\t\tSWIFT_VERSION = 5.0;\n\t\t\t\tWRAPPER_EXTENSION = app;\n",
        "\t\t\t\tSWIFT_VERSION = 5.0;\n"
        "\t\t\t\tCODE_SIGN_ENTITLEMENTS = \"../../../../native/ObstacleBridgeTunnel/ObstacleBridge.entitlements\";\n"
        "\t\t\t\tWRAPPER_EXTENSION = app;\n",
        1,
    )

    target_configs = f"""\t\t{IDS['target_debug_config']} /* Debug */ = {{
\t\t\tisa = XCBuildConfiguration;
\t\t\tbuildSettings = {{
\t\t\t\tAPPLICATION_EXTENSION_API_ONLY = YES;
\t\t\t\tCODE_SIGN_ENTITLEMENTS = "../../../../native/ObstacleBridgeTunnel/PacketTunnel.entitlements";
\t\t\t\tCURRENT_PROJECT_VERSION = 1;
\t\t\t\tGENERATE_INFOPLIST_FILE = NO;
\t\t\t\tINFOPLIST_FILE = "../../../../native/ObstacleBridgeTunnel/Info.plist";
\t\t\t\tIPHONEOS_DEPLOYMENT_TARGET = 13.0;
\t\t\t\tLD_RUNPATH_SEARCH_PATHS = (
\t\t\t\t\t"$(inherited)",
\t\t\t\t\t"@executable_path/Frameworks",
\t\t\t\t\t"@executable_path/../../Frameworks",
\t\t\t\t);
\t\t\t\tMARKETING_VERSION = 0.1.0;
\t\t\t\tPRODUCT_BUNDLE_IDENTIFIER = "com.obstaclebridge.obstacle-bridge-ios.PacketTunnel";
\t\t\t\tPRODUCT_NAME = "$(TARGET_NAME)";
\t\t\t\tSKIP_INSTALL = YES;
\t\t\t\tSWIFT_VERSION = 5.0;
\t\t\t\tSWIFT_OBJC_BRIDGING_HEADER = "../../../../native/ObstacleBridgeTunnel/ObstacleBridgeTunnel-Bridging-Header.h";
\t\t\t}};
\t\t\tname = Debug;
\t\t}};
\t\t{IDS['target_release_config']} /* Release */ = {{
\t\t\tisa = XCBuildConfiguration;
\t\t\tbuildSettings = {{
\t\t\t\tAPPLICATION_EXTENSION_API_ONLY = YES;
\t\t\t\tCODE_SIGN_ENTITLEMENTS = "../../../../native/ObstacleBridgeTunnel/PacketTunnel.entitlements";
\t\t\t\tCURRENT_PROJECT_VERSION = 1;
\t\t\t\tGENERATE_INFOPLIST_FILE = NO;
\t\t\t\tINFOPLIST_FILE = "../../../../native/ObstacleBridgeTunnel/Info.plist";
\t\t\t\tIPHONEOS_DEPLOYMENT_TARGET = 13.0;
\t\t\t\tLD_RUNPATH_SEARCH_PATHS = (
\t\t\t\t\t"$(inherited)",
\t\t\t\t\t"@executable_path/Frameworks",
\t\t\t\t\t"@executable_path/../../Frameworks",
\t\t\t\t);
\t\t\t\tMARKETING_VERSION = 0.1.0;
\t\t\t\tPRODUCT_BUNDLE_IDENTIFIER = "com.obstaclebridge.obstacle-bridge-ios.PacketTunnel";
\t\t\t\tPRODUCT_NAME = "$(TARGET_NAME)";
\t\t\t\tSKIP_INSTALL = YES;
\t\t\t\tSWIFT_VERSION = 5.0;
\t\t\t\tSWIFT_OBJC_BRIDGING_HEADER = "../../../../native/ObstacleBridgeTunnel/ObstacleBridgeTunnel-Bridging-Header.h";
\t\t\t}};
\t\t\tname = Release;
\t\t}};
"""
    text = insert_before(text, "/* End XCBuildConfiguration section */", target_configs)

    config_list = f"""\t\t{IDS['target_config_list']} /* Build configuration list for PBXNativeTarget "ObstacleBridgeTunnel" */ = {{
\t\t\tisa = XCConfigurationList;
\t\t\tbuildConfigurations = (
\t\t\t\t{IDS['target_debug_config']} /* Debug */,
\t\t\t\t{IDS['target_release_config']} /* Release */,
\t\t\t);
\t\t\tdefaultConfigurationIsVisible = 0;
\t\t\tdefaultConfigurationName = Release;
\t\t}};
"""
    text = insert_before(text, "/* End XCConfigurationList section */", config_list)
    text = patch_ad_hoc_sign_phase(text)

    project_path.write_text(text, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=DEFAULT_PROJECT)
    args = parser.parse_args()
    changed = patch_project(args.project)
    print(f"{'patched' if changed else 'already patched'}: {args.project}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
