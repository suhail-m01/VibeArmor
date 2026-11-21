"""Compile & package the VibeArmor Multi-Editor Extension into a valid OpenVSX / VS Code `.vsix` file."""

from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

EXT_ROOT = Path(__file__).resolve().parent
ESBUILD_BIN = EXT_ROOT.parent / "studio" / "node_modules" / ".bin" / "esbuild"

CONTENT_TYPES_XML = """<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension=".json" ContentType="application/json" />
  <Default Extension=".js" ContentType="application/javascript" />
  <Default Extension=".ts" ContentType="text/plain" />
  <Default Extension=".md" ContentType="text/markdown" />
  <Default Extension=".svg" ContentType="image/svg+xml" />
  <Default Extension=".vsixmanifest" ContentType="text/xml" />
</Types>
"""


def build_vsixmanifest(pkg: dict) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="{pkg['name']}" Version="{pkg['version']}" Publisher="{pkg['publisher']}" />
    <DisplayName>{pkg['displayName']}</DisplayName>
    <Description xml:space="preserve">{pkg['description']}</Description>
    <Tags>security,devsecops,vibe-coding,supabase,rls,git-push,deploy</Tags>
    <Categories>Linters,Security,Testing</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="{pkg['engines']['vscode']}" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />
    </Properties>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code" />
  </Installation>
  <Dependencies />
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true" />
  </Assets>
</PackageManifest>
"""


def main() -> Path:
    import shutil as _shutil

    bundle_dir = EXT_ROOT / "bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    out_js = bundle_dir / "extension.js"
    src_ts = EXT_ROOT / "src" / "extension.ts"

    esbuild_cmd = str(ESBUILD_BIN) if ESBUILD_BIN.exists() else _shutil.which("esbuild")
    if esbuild_cmd:
        subprocess.run(
            [
                esbuild_cmd,
                str(src_ts),
                "--bundle",
                "--minify",
                "--platform=node",
                "--format=cjs",
                "--target=node18",
                "--external:vscode",
                f"--outfile={out_js}",
            ],
            check=True,
        )
    elif not out_js.exists() or src_ts.stat().st_mtime > out_js.stat().st_mtime:
        raise RuntimeError(
            "esbuild binary not found and extension.ts was modified! Run `cd studio && npm install` before build_vsix.py."
        )

    pkg = json.loads((EXT_ROOT / "package.json").read_text(encoding="utf-8"))
    vsix_out = EXT_ROOT / f"vibearmor-guard-{pkg['version']}.vsix"

    with zipfile.ZipFile(vsix_out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("[Content_Types].xml", CONTENT_TYPES_XML)
        zf.writestr("extension.vsixmanifest", build_vsixmanifest(pkg))
        zf.write(EXT_ROOT / "package.json", "extension/package.json")
        zf.write(EXT_ROOT / "README.md", "extension/README.md")
        zf.write(EXT_ROOT / "media" / "shield.svg", "extension/media/shield.svg")
        if (EXT_ROOT / "vibearmor_bridge.py").exists():
            zf.write(EXT_ROOT / "vibearmor_bridge.py", "extension/vibearmor_bridge.py")
        zf.write(out_js, "extension/bundle/extension.js")

    legacy_alias = EXT_ROOT / "vibearmor-guard-3.0.0.vsix"
    if legacy_alias != vsix_out:
        _shutil.copy2(vsix_out, legacy_alias)

    print(f"Built VSIX: {vsix_out} ({vsix_out.stat().st_size} bytes)")
    return vsix_out


if __name__ == "__main__":
    main()
