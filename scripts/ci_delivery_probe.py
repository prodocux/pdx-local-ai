"""Test an exact delivery ZIP using its installed executable (not RG-1).

The Python interpreter drives the probe only; product execution must use the
installed frozen EXE. All subprocess/RPC waits are bounded. Evidence is retained
on failure; no real user profile or source directory is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
import traceback
import zipfile


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_package(path: Path, expected: str, target: Path) -> Path:
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected) or digest(path) != expected.lower():
        raise ValueError("Delivery ZIP SHA-256 mismatch")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate archive entries")
        for name in names:
            resolved = (target / name).resolve()
            if not resolved.is_relative_to(target.resolve()) or "\\" in name:
                raise ValueError("Unsafe ZIP path")
        manifests = [n for n in names if n.endswith("/RELEASE_MANIFEST.json")]
        if len(manifests) != 1:
            raise ValueError("Expected one release manifest")
        prefix = manifests[0].removesuffix("RELEASE_MANIFEST.json")
        manifest = json.loads(archive.read(manifests[0]))
        actual = {n for n in names if not n.endswith("/")}
        expected_names = {prefix + n for n in manifest["files"]} | {manifests[0]}
        if actual != expected_names or manifest["files_count"] != len(manifest["files"]):
            raise ValueError("Manifest inventory mismatch")
        for name, record in manifest["files"].items():
            data = archive.read(prefix + name)
            if len(data) != record["size_bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise ValueError(f"Manifest digest mismatch: {name}")
        archive.extractall(target)
    return target / prefix


class RpcClient:
    def __init__(self, command: list[str], cwd: Path, env: dict[str, str], evidence: Path):
        self.proc = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, encoding="utf-8")
        self.responses: queue.Queue[str | None] = queue.Queue()
        self.threads: list[threading.Thread] = []
        self.evidence = evidence
        for label, stream in (("stdout", self.proc.stdout), ("stderr", self.proc.stderr)):
            def drain(label=label, stream=stream):
                try:
                    with (evidence / f"mcp-{label}.log").open("x", encoding="utf-8") as out:
                        for line in stream:
                            out.write(line)
                            out.flush()
                            if label == "stdout":
                                self.responses.put(line)
                finally:
                    stream.close()
                    if label == "stdout":
                        self.responses.put(None)
            thread = threading.Thread(target=drain, daemon=True)
            thread.start()
            self.threads.append(thread)

    def send(self, message: dict) -> None:
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def call(self, rpc_id: int, method: str, params: dict) -> dict:
        self.send({"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params})
        end = time.monotonic() + 20
        while True:
            line = self.responses.get(timeout=max(0.001, end - time.monotonic()))
            if line is None:
                raise RuntimeError("MCP stdout closed before response")
            response = json.loads(line)
            if response.get("id") != rpc_id:
                raise RuntimeError("Unexpected response id")
            if "error" in response or response.get("result", {}).get("isError"):
                raise RuntimeError(f"MCP error: {response}")
            with (self.evidence / f"rpc-{rpc_id}.json").open("x", encoding="utf-8") as out:
                json.dump(response, out, indent=2)
            return response["result"]

    def close(self) -> None:
        forced = False
        try:
            self.proc.stdin.close()
            try:
                code = self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                forced = True
                self.proc.kill()
                code = self.proc.wait(timeout=5)
        finally:
            for thread in self.threads:
                thread.join(timeout=5)
        if forced or code != 0 or any(t.is_alive() for t in self.threads):
            raise RuntimeError(f"MCP shutdown failed: exit={code}, forced={forced}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    evidence = work / "evidence"
    evidence.mkdir()
    env = {key.upper(): value for key, value in os.environ.items()}
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env["PYTHONNOUSERSITE"] = "1"
    system_root = env["SYSTEMROOT"]
    env["PATH"] = os.pathsep.join([str(Path(system_root) / "System32"), system_root])
    powershell = str(Path(system_root) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    records: list[dict] = []
    def run(command: list[str], label: str) -> str:
        result = subprocess.run(command, cwd=work, env=env, text=True, encoding="utf-8",
                                capture_output=True, timeout=90)
        for channel in ("stdout", "stderr"):
            with (evidence / f"{label}-{channel}.log").open("x", encoding="utf-8") as out:
                out.write(getattr(result, channel))
        records.append({"step": label, "command": command, "exit_code": result.returncode})
        if result.returncode:
            raise RuntimeError(f"{label} failed: {result.returncode}")
        return result.stdout
    success = False
    installed = work / "installed"
    profile = work / "profile"
    package = None
    client = None
    try:
        package = verify_package(args.zip.resolve(), args.sha256, work / "extracted")
        run([powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(package / "install.ps1"),
             "-TargetDir", str(installed), "-ProfileDir", str(profile),
             "-AcceptWindowsRuntimeTerms"], "install")
        exe = str(installed / "pdx-local.exe")
        if not (installed / "install-manifest.json").is_file():
            raise RuntimeError("Missing installed manifest")
        run([exe, "init", "--profile-dir", str(profile), "--principal-id", "ci-user"], "init")
        workspace = json.loads((profile / "config.json").read_text(encoding="utf-8"))["workspace_id"]
        docs = work / "corpus"
        docs.mkdir()
        token = "DeliveryProbeUniqueToken"
        with (docs / "hello.txt").open("x", encoding="utf-8") as out:
            out.write(f"{token} delivery probe document.\n")
        output = run([exe, "source", "add", str(docs), "--profile-dir", str(profile),
                      "--workspace-id", workspace, "--principal-id", "ci-user", "--inherit-read"], "source-add")
        match = re.search(r"Root ID:\s*([0-9a-f-]{36})", output)
        if not match:
            raise RuntimeError("Source add did not return root UUID")
        root = match.group(1)
        run([exe, "source", "scan", root, "--profile-dir", str(profile)], "scan")
        client = RpcClient([exe, "service", "--catalog-path", str(profile / "catalog.sqlite"),
                            "--workspace-id", workspace, "--principal-id", "ci-user"], work, env, evidence)
        client.call(1, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                      "clientInfo": {"name": "delivery-probe", "version": "1"}})
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = client.call(2, "tools/list", {})
        if "search_documents" not in {t["name"] for t in tools["tools"]}:
            raise RuntimeError("Search tool missing")
        response = client.call(3, "tools/call", {"name": "search_documents", "arguments": {
            "source_root_ids": [root], "query": token, "timeout_ms": 6000, "limit": 8}})
        payload = json.loads(response["content"][0]["text"])
        if payload["status"] != "completed" or not payload.get("receipt_id"):
            raise RuntimeError("Search did not complete with receipt")
        hits = payload.get("results", [])
        if not any(token in item["text"] and item.get("citation") for item in hits):
            raise RuntimeError("Search missing expected text or citation")
        success = True
    except Exception:
        with (evidence / "failure.log").open("x", encoding="utf-8") as out:
            traceback.print_exc(file=out)
    finally:
        try:
            if client:
                client.close()
            if package and installed.exists():
                run([powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(package / "uninstall.ps1"),
                     "-TargetDir", str(installed), "-ProfileDir", str(profile)], "uninstall")
                if (installed / "pdx-local.exe").exists() or not (profile / "catalog.sqlite").exists():
                    raise RuntimeError("Uninstall did not preserve expected boundary")
        except Exception:
            success = False
            with (evidence / "cleanup-failure.log").open("x", encoding="utf-8") as out:
                traceback.print_exc(file=out)
        with (evidence / "summary.json").open("x", encoding="utf-8") as out:
            json.dump({"passed": success, "zip_sha256": args.sha256, "steps": records,
                       "rg1_satisfied": False, "boundary": "CI driver uses Python; not a clean OS image",
                       "commit": os.environ.get("GITHUB_SHA"), "image": os.environ.get("ImageVersion")}, out, indent=2)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
