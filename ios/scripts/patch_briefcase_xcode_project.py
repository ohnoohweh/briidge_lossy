#!/usr/bin/env python3
"""Patch Briefcase's generated iOS Xcode project with the IPServer extension target."""

from __future__ import annotations

import argparse
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


def patch_python_build_script(text: str) -> str:
    script_variants = (
        (
            'PACKAGES_PATH=\\"app_packages.iphonesimulator\\"\\n',
            'PACKAGES_PATH=\\"app_packages.iphonesimulator\\"\\n'
            '    if [ -z \\"${EXPANDED_CODE_SIGN_IDENTITY:-}\\" ]; then\\n'
            '        export EXPANDED_CODE_SIGN_IDENTITY=-\\n'
            '        export EXPANDED_CODE_SIGN_IDENTITY_NAME=\\"Ad Hoc\\"\\n'
            '    fi\\n',
        ),
        (
            'PACKAGES_PATH="app_packages.iphonesimulator"\n',
            'PACKAGES_PATH="app_packages.iphonesimulator"\n'
            '    if [ -z "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then\n'
            '        export EXPANDED_CODE_SIGN_IDENTITY=-\n'
            '        export EXPANDED_CODE_SIGN_IDENTITY_NAME="Ad Hoc"\n'
            '    fi\n',
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


def patch_app_target(text: str) -> str:
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
        "\t\t60796F0F19190F4100A9926B /* Debug */ = {\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {\n\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;\n\t\t\t\tCODE_SIGN_ENTITLEMENTS = \"../../../../native/ObstacleBridgeApp/ObstacleBridge.entitlements\";\n\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;\n",
    )
    text = replace_once(
        text,
        "\t\t60796F1019190F4100A9926B /* Release */ = {\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {\n\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;\n\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;\n",
        "\t\t60796F1019190F4100A9926B /* Release */ = {\n\t\t\tisa = XCBuildConfiguration;\n\t\t\tbuildSettings = {\n\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;\n\t\t\t\tCODE_SIGN_ENTITLEMENTS = \"../../../../native/ObstacleBridgeApp/ObstacleBridge.entitlements\";\n\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;\n",
    )
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
        "\t\t71C200000000000000000032 /* PacketTunnelProvider.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = PacketTunnelProvider.swift; path = \"../../../../native/IPServer/PacketTunnelProvider.swift\"; sourceTree = SOURCE_ROOT; };\n"
        "\t\t71C200000000000000000033 /* ObstacleBridgePythonBridge.m */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.c.objc; name = ObstacleBridgePythonBridge.m; path = \"../../../../native/IPServer/ObstacleBridgePythonBridge.m\"; sourceTree = SOURCE_ROOT; };\n"
        "\t\t71C200000000000000000034 /* ObstacleBridgePythonBridge.h */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.c.h; name = ObstacleBridgePythonBridge.h; path = \"../../../../native/IPServer/ObstacleBridgePythonBridge.h\"; sourceTree = SOURCE_ROOT; };\n"
        "\t\t71C200000000000000000035 /* IPServer-Bridging-Header.h */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.c.h; name = \"IPServer-Bridging-Header.h\"; path = \"../../../../native/IPServer/IPServer-Bridging-Header.h\"; sourceTree = SOURCE_ROOT; };\n"
        "\t\t71C200000000000000000036 /* Info.plist */ = {isa = PBXFileReference; lastKnownFileType = text.plist.xml; name = Info.plist; path = \"../../../../native/IPServer/Info.plist\"; sourceTree = SOURCE_ROOT; };\n"
        "\t\t71C200000000000000000037 /* IPServer.entitlements */ = {isa = PBXFileReference; lastKnownFileType = text.plist.entitlements; name = IPServer.entitlements; path = \"../../../../native/IPServer/IPServer.entitlements\"; sourceTree = SOURCE_ROOT; };\n",
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
    text = replace_once(
        text,
        "\t\t60796ED919190F4100A9926B = {\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t60A04BC228B35E9F00DAA9E5 /* Support */,\n\t\t\t\t60796EEB19190F4100A9926B /* ObstacleBridge */,\n\t\t\t\t60796EE419190F4100A9926B /* Frameworks */,\n\t\t\t\t60796EE319190F4100A9926B /* Products */,\n\t\t\t);\n\t\t\tsourceTree = \"<group>\";\n\t\t};\n",
        "\t\t60796ED919190F4100A9926B = {\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t60A04BC228B35E9F00DAA9E5 /* Support */,\n\t\t\t\t60796EEB19190F4100A9926B /* ObstacleBridge */,\n\t\t\t\t71C200000000000000000050 /* IPServer Extension */,\n\t\t\t\t60796EE419190F4100A9926B /* Frameworks */,\n\t\t\t\t60796EE319190F4100A9926B /* Products */,\n\t\t\t);\n\t\t\tsourceTree = \"<group>\";\n\t\t};\n",
    )
    text = replace_once(
        text,
        "\t\t60796EE319190F4100A9926B /* Products */ = {\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t610000000000000000100400 /* ObstacleBridge.app */,\n\t\t\t);\n\t\t\tname = Products;\n\t\t\tsourceTree = \"<group>\";\n\t\t};\n",
        "\t\t60796EE319190F4100A9926B /* Products */ = {\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n\t\t\t\t610000000000000000100400 /* ObstacleBridge.app */,\n\t\t\t\t71C200000000000000000031 /* IPServer.appex */,\n\t\t\t);\n\t\t\tname = Products;\n\t\t\tsourceTree = \"<group>\";\n\t\t};\n",
    )
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
        "/* End PBXSourcesBuildPhase section */\n",
        "\t\t71C200000000000000000080 /* Sources */ = {\n"
        "\t\t\tisa = PBXSourcesBuildPhase;\n"
        "\t\t\tbuildActionMask = 2147483647;\n"
        "\t\t\tfiles = (\n"
        "\t\t\t\t71C200000000000000000001 /* PacketTunnelProvider.swift in Sources */,\n"
        "\t\t\t\t71C200000000000000000002 /* ObstacleBridgePythonBridge.m in Sources */,\n"
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
    text = patch_python_build_script(text)
    text = patch_app_target(text)
    text = patch_ipserver_target(text)
    return text


def patch_pbxproj_file(path: Path) -> bool:
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
