from __future__ import annotations

import sys
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ios" / "scripts"))

import patch_ios_xcode_project as patcher
from patch_ios_xcode_project import patch_pbxproj_file, patch_pbxproj_text


BASELINE_PROJECT = """// !$*UTF8*$!
{
/* Begin PBXBuildFile section */
\t\t60C0057928F7DB9A008B9E84 /* WebKit.framework in Frameworks */ = {isa = PBXBuildFile; fileRef = 60C0057828F7DB9A008B9E84 /* WebKit.framework */; };
/* End PBXBuildFile section */

/* Begin PBXCopyFilesBuildPhase section */
\t\t6060E7A12AF8BF4400C04AE0 /* Embed Frameworks */ = {
\t\t\tisa = PBXCopyFilesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tdstPath = "";
\t\t\tdstSubfolderSpec = 10;
\t\t\tfiles = (
\t\t\t\t60813D382B02EED200EFB492 /* Python.xcframework in Embed Frameworks */,
\t\t\t);
\t\t\tname = "Embed Frameworks";
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t};
/* End PBXCopyFilesBuildPhase section */

/* Begin PBXFileReference section */
\t\t610000000000000000100900 /* Launch Screen.storyboard */ = {isa = PBXFileReference; lastKnownFileType = file.storyboard; path = "Launch Screen.storyboard"; sourceTree = "<group>"; };
/* End PBXFileReference section */

/* Begin PBXFrameworksBuildPhase section */
\t\t60796EDF19190F4100A9926B /* Frameworks */ = {
\t\t\tisa = PBXFrameworksBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t\t600000000000000000000800 /* CoreGraphics.framework in Frameworks */,
\t\t\t\t600000000000000000000900 /* Foundation.framework in Frameworks */,
\t\t\t\t60813D372B02EED200EFB492 /* Python.xcframework in Frameworks */,
\t\t\t\t600000000000000000000A00 /* UIKit.framework in Frameworks */,
\t\t\t\t60C0057928F7DB9A008B9E84 /* WebKit.framework in Frameworks */,
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t};
/* End PBXFrameworksBuildPhase section */

/* Begin PBXGroup section */
\t\t60796ED919190F4100A9926B = {
\t\t\tisa = PBXGroup;
\t\t\tchildren = (
\t\t\t\t60A04BC228B35E9F00DAA9E5 /* Support */,
\t\t\t\t60796EEB19190F4100A9926B /* ObstacleBridge */,
\t\t\t\t60796EE419190F4100A9926B /* Frameworks */,
\t\t\t\t60796EE319190F4100A9926B /* Products */,
\t\t\t);
\t\t\tsourceTree = "<group>";
\t\t};
\t\t60796EE319190F4100A9926B /* Products */ = {
\t\t\tisa = PBXGroup;
\t\t\tchildren = (
\t\t\t\t610000000000000000100400 /* ObstacleBridge.app */,
\t\t\t);
\t\t\tname = Products;
\t\t\tsourceTree = "<group>";
\t\t};
\t\t60796EE419190F4100A9926B /* Frameworks */ = {
\t\t\tisa = PBXGroup;
\t\t\tchildren = (
\t\t\t\t610000000000000000000800 /* CoreGraphics.framework */,
\t\t\t\t610000000000000000000900 /* Foundation.framework */,
\t\t\t\t610000000000000000000A00 /* UIKit.framework */,
\t\t\t\t60C0057828F7DB9A008B9E84 /* WebKit.framework */,
\t\t\t);
\t\t\tname = Frameworks;
\t\t\tsourceTree = "<group>";
\t\t};
/* End PBXGroup section */

/* Begin PBXNativeTarget section */
\t\t60796EE119190F4100A9926B /* ObstacleBridge */ = {
\t\t\tisa = PBXNativeTarget;
\t\t\tbuildConfigurationList = 60796F0E19190F4100A9926B /* Build configuration list for PBXNativeTarget "ObstacleBridge" */;
\t\t\tbuildPhases = (
\t\t\t\t60796EDE19190F4100A9926B /* Sources */,
\t\t\t\t60796EDF19190F4100A9926B /* Frameworks */,
\t\t\t\t60796EE019190F4100A9926B /* Resources */,
\t\t\t\t609384A628B5B958005B2A5D /* Process Python libraries */,
\t\t\t\t6060E7A12AF8BF4400C04AE0 /* Embed Frameworks */,
\t\t\t);
\t\t\tbuildRules = (
\t\t\t);
\t\t\tdependencies = (
\t\t\t);
\t\t\tname = ObstacleBridge;
\t\t\tproductName = obstacle_bridge_ios;
\t\t\tproductReference = 610000000000000000100400 /* ObstacleBridge.app */;
\t\t\tproductType = "com.apple.product-type.application";
\t\t};
/* End PBXNativeTarget section */

/* Begin PBXShellScriptBuildPhase section */
\t\t609384A628B5B958005B2A5D /* Process Python libraries */ = {
\t\t\tisa = PBXShellScriptBuildPhase;
\t\t\talwaysOutOfDate = 1;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t);
\t\t\tinputFileListPaths = (
\t\t\t);
\t\t\tinputPaths = (
\t\t\t);
\t\t\tname = "Process Python libraries";
\t\t\toutputFileListPaths = (
\t\t\t);
\t\t\toutputPaths = (
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t\tshellPath = /bin/sh;
\t\t\tshellScript = "set -e\nsource $PROJECT_DIR/Support/Python.xcframework/build/utils.sh\n\nif [ \"$EFFECTIVE_PLATFORM_NAME\" = \"-iphonesimulator\" ]; then\n    echo \"Installing app packages for iOS Simulator\"\n    PACKAGES_PATH=\"app_packages.iphonesimulator\"\nelse\n    echo \"Installing app packages for iOS Device\"\n    PACKAGES_PATH=\"app_packages.iphoneos\"\nfi\nrsync -au --delete \"$PROJECT_DIR/ObstacleBridge/$PACKAGES_PATH/\" \"$CODESIGNING_FOLDER_PATH/app_packages\"\n\ninstall_python Support/Python.xcframework app app_packages\n";
\t\t\tshowEnvVarsInLog = 0;
\t\t};
/* End PBXShellScriptBuildPhase section */

/* Begin PBXProject section */
\t\t60796EDA19190F4100A9926B /* Project object */ = {
\t\t\tisa = PBXProject;
\t\t\tprojectDirPath = "";
\t\t\tprojectRoot = "";
\t\t\ttargets = (
\t\t\t\t60796EE119190F4100A9926B /* ObstacleBridge */,
\t\t\t);
\t\t};
/* End PBXProject section */

/* Begin PBXResourcesBuildPhase section */
\t\t60796EE019190F4100A9926B /* Resources */ = {
\t\t\tisa = PBXResourcesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t};
/* End PBXResourcesBuildPhase section */

/* Begin PBXSourcesBuildPhase section */
\t\t60796EDE19190F4100A9926B /* Sources */ = {
\t\t\tisa = PBXSourcesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t};
/* End PBXSourcesBuildPhase section */

/* Begin PBXVariantGroup section */
/* End PBXVariantGroup section */

/* Begin XCBuildConfiguration section */
\t\t60796F0F19190F4100A9926B /* Debug */ = {
\t\t\tisa = XCBuildConfiguration;
\t\t\tbuildSettings = {
\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;
\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;
\t\t\t\tDEVELOPMENT_TEAM = 99WZ498FCV;
\t\t\t};
\t\t\tname = Debug;
\t\t};
\t\t60796F1019190F4100A9926B /* Release */ = {
\t\t\tisa = XCBuildConfiguration;
\t\t\tbuildSettings = {
\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;
\t\t\t\tCLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER = NO;
\t\t\t\tDEVELOPMENT_TEAM = 99WZ498FCV;
\t\t\t};
\t\t\tname = Release;
\t\t};
/* End XCBuildConfiguration section */

/* Begin XCConfigurationList section */
\t\t60796F0E19190F4100A9926B /* Build configuration list for PBXNativeTarget "ObstacleBridge" */ = {
\t\t\tisa = XCConfigurationList;
\t\t\tbuildConfigurations = (
\t\t\t\t60796F0F19190F4100A9926B /* Debug */,
\t\t\t\t60796F1019190F4100A9926B /* Release */,
\t\t\t);
\t\t\tdefaultConfigurationIsVisible = 0;
\t\t\tdefaultConfigurationName = Release;
\t\t};
/* End XCConfigurationList section */
}
"""


def test_patch_pbxproj_text_injects_extension_target() -> None:
    patched = patch_pbxproj_text(BASELINE_PROJECT)

    assert "IPServer.appex" in patched
    assert 'PBXNativeTarget "IPServer"' in patched
    assert "NetworkExtension.framework" in patched
    assert "Embed App Extensions" in patched
    assert "GeneratedSources/IPServer/PacketTunnelProvider.swift" in patched
    assert "native/IPServer/IPServer.entitlements" in patched
    assert "native/ObstacleBridgeShared/ObstacleBridgeNativeCrypto.swift" in patched
    assert "ObstacleBridgeNativeCrypto.swift in Sources" in patched
    assert "ObstacleBridgeNativeCrypto.swift in IPServer Sources" in patched
    assert "SWIFT_VERSION = 5.0;" in patched
    assert 'CODE_SIGN_ENTITLEMENTS = "../../../../native/ObstacleBridgeApp/ObstacleBridge.entitlements";' in patched
    assert 'export EXPANDED_CODE_SIGN_IDENTITY=-' in patched
    assert "Process Python libraries for IPServer" not in patched
    assert "ObstacleBridgePythonBridge.m" not in patched
    assert "IPServer-Bridging-Header.h" not in patched
    assert "ObstacleBridgeTunnel.appex" not in patched


def test_patch_pbxproj_text_is_idempotent() -> None:
    once = patch_pbxproj_text(BASELINE_PROJECT)
    twice = patch_pbxproj_text(once)

    assert once == twice


def test_patch_pbxproj_file_generates_packet_tunnel_provider_copy(tmp_path, monkeypatch) -> None:
    project_root = tmp_path / "build" / "obstacle_bridge_ios" / "ios" / "xcode"
    xcodeproj = project_root / "ObstacleBridge.xcodeproj"
    xcodeproj.mkdir(parents=True)
    pbxproj = xcodeproj / "project.pbxproj"
    pbxproj.write_text(BASELINE_PROJECT, encoding="utf-8")

    source_provider = tmp_path / "repo" / "ios" / "native" / "IPServer" / "PacketTunnelProvider.swift"
    source_provider.parent.mkdir(parents=True)
    source_provider.write_text("// generated source fixture\n", encoding="utf-8")
    monkeypatch.setattr(patcher, "REPO_PACKET_TUNNEL_PROVIDER", source_provider)

    changed = patch_pbxproj_file(pbxproj)

    generated_provider = project_root / patcher.GENERATED_PACKET_TUNNEL_PROVIDER_RELATIVE
    assert changed is True
    assert generated_provider.read_text(encoding="utf-8") == source_provider.read_text(encoding="utf-8")
    patched = pbxproj.read_text(encoding="utf-8")
    assert "GeneratedSources/IPServer/PacketTunnelProvider.swift" in patched
