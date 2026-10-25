"""Local, read-only distribution probe. Requires packaging in the chosen Python.

The probe does not install software or explicitly import target distributions.
Interpreter startup, site hooks and packaging remain trusted, not sandboxed.
A probe failure emits no raw exception or package metadata body.
"""
import hashlib
import importlib.metadata as metadata
import json
import os
import platform
import re
import sys
import site
import sysconfig


def _classify_sites(selected_site, expected_root):
    active_sites = {os.path.realpath(p) for p in site.getsitepackages() if os.path.isdir(p)}
    interpreter_root = ""
    if os.name == "nt":
        interpreter_root = os.path.realpath(sys.prefix)
        if (not expected_root or interpreter_root != os.path.realpath(expected_root)
                or interpreter_root == os.path.realpath(sys.base_prefix)
                or selected_site != os.path.realpath(os.path.join(interpreter_root, "Lib", "site-packages"))
                or not os.path.isfile(os.path.join(interpreter_root, "pyvenv.cfg"))
                or os.path.realpath(sys.executable) != os.path.realpath(os.path.join(interpreter_root, "Scripts", "python.exe"))):
            raise ValueError()
    elif expected_root:
        raise ValueError()
    expected_sites = {selected_site} | ({interpreter_root} if interpreter_root else set())
    if site.ENABLE_USER_SITE or active_sites != expected_sites:
        raise ValueError()
    standard = {os.path.realpath(sysconfig.get_path(k)) for k in ("stdlib", "platstdlib")}
    allowed = standard | expected_sites
    if os.name == "nt":
        allowed |= {os.path.realpath(sys.base_prefix), os.path.realpath(os.path.join(sys.base_prefix, "DLLs"))}
    for path in standard:
        allowed.add(os.path.realpath(os.path.join(path, "lib-dynload")))
        allowed.add(os.path.realpath(os.path.join(os.path.dirname(path), "python%d%d.zip" % sys.version_info[:2])))
    if any(os.path.exists(p) and os.path.realpath(p) not in allowed for p in sys.path):
        raise ValueError()
    return interpreter_root


def _windows_machine():
    import ctypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    current_process = kernel.GetCurrentProcess
    current_process.argtypes = []
    current_process.restype = ctypes.c_void_p
    process = current_process()
    if not process:
        raise ValueError()
    machine_info = kernel.IsWow64Process2
    machine_info.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint16)]
    machine_info.restype = ctypes.c_int32
    process_machine, native_machine = ctypes.c_uint16(0xffff), ctypes.c_uint16(0xffff)
    if not machine_info(process, ctypes.byref(process_machine), ctypes.byref(native_machine)):
        raise ValueError()
    machine = {0x014c: "x86", 0x01c0: "ARM", 0x01c4: "ARM", 0x0200: "ia64",
               0x8664: "AMD64", 0xaa64: "ARM64"}.get(native_machine.value)
    if not machine:
        raise ValueError()
    return machine


def _marker_environment():
    from packaging.markers import default_environment

    environment = default_environment()
    if os.name == "nt":
        environment["platform_machine"] = _windows_machine()
    return environment


def main():
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet
    from packaging.utils import canonicalize_name
    from packaging.version import Version

    request = json.load(sys.stdin)
    roots = request["declarations"]
    selected_site = os.path.realpath(request["site_packages"])
    interpreter_root = _classify_sites(selected_site, request["interpreter_root"])
    if not isinstance(roots, list) or len(roots) > 1024:
        raise ValueError()
    environment = _marker_environment()
    installed = {}
    # Duplicate distributions make importlib.metadata's first-match selection
    # ambiguous. Do not silently choose one from sys.path order.
    for index, dist in enumerate(metadata.distributions()):
        if index >= 8192:
            raise ValueError()
        for filename in ("METADATA", "RECORD"):
            location = os.path.join(os.fspath(dist._path), filename)
            if os.path.exists(location) and (not os.path.isfile(location) or os.path.getsize(location) > 1048576):
                raise ValueError()
        name = canonicalize_name(dist.metadata['Name'])
        if name in installed:
            raise ValueError()
        installed[name] = dist
    queue = []
    for item in roots:
        name = item['name']
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name):
            raise ValueError()
        canonical = canonicalize_name(name)
        queue.append((canonical, SpecifierSet(item['constraint']), frozenset()))
    selected = {}
    expanded = {}
    count = 0
    while queue:
        count += 1
        if count > 4096 or len(selected) > 1024:
            raise ValueError()
        name, spec, extras = queue.pop(0)
        dist = installed.get(name)
        if dist is None or not spec.contains(Version(dist.version)):
            raise ValueError()
        requires_python = dist.metadata.get('Requires-Python')
        if requires_python and not SpecifierSet(requires_python).contains(Version(platform.python_version())):
            raise ValueError()
        available_extras = {canonicalize_name(x) for x in dist.metadata.get_all("Provides-Extra", [])}
        if not set(extras).issubset(available_extras):
            raise ValueError()
        selected[name] = dist
        old = expanded.get(name)
        current = (old or frozenset()) | extras
        if old is not None and current == old:
            continue
        expanded[name] = current
        requirements = dist.requires or []
        if len(requirements) > 1024:
            raise ValueError()
        for text in requirements:
            requirement = Requirement(text)
            if requirement.url:
                raise ValueError()
            contexts = [''] + sorted(current)
            if requirement.marker and not any(requirement.marker.evaluate(dict(environment, extra=x)) for x in contexts):
                continue
            queue.append((canonicalize_name(requirement.name), requirement.specifier, frozenset(requirement.extras)))
    selected["packaging"] = metadata.distribution("packaging")
    Version(selected["packaging"].version)
    prefix = os.path.realpath(sys.prefix)
    total = 0
    files_count = 0
    packages = []
    for name, dist in sorted(selected.items()):
        info = os.path.realpath(os.fspath(dist._path))
        required = {os.path.join(info, "METADATA"), os.path.join(info, "RECORD")}
        if os.path.commonpath([selected_site, info]) != selected_site:
            raise ValueError()
        if not all(os.path.isfile(p) and not os.path.islink(p) and os.path.getsize(p) <= 1048576 for p in required):
            raise ValueError()
        files = dist.files
        if not files:
            raise ValueError()
        evidence = []
        paths = set()
        payload = False
        for item in sorted(files, key=str):
            path = os.path.realpath(dist.locate_file(item))
            if os.path.commonpath([selected_site, path]) != selected_site or not os.path.isfile(path) or path in paths:
                raise ValueError()
            paths.add(path)
            parts = os.path.relpath(path, selected_site).split(os.sep)
            if not any(p.endswith((".dist-info", ".egg-info")) or p == "__pycache__" for p in parts) and not path.endswith(".pyc"):
                payload = True
            files_count += 1
            if files_count > 100000:
                raise ValueError()
            h = hashlib.sha256()
            with open(path, 'rb') as stream:
                while True:
                    block = stream.read(65536)
                    if not block:
                        break
                    total += len(block)
                    if total > 268435456:
                        raise ValueError()
                    h.update(block)
            evidence.append([str(item), h.hexdigest()])
        if not required.issubset(paths) or not payload:
            raise ValueError()
        # Required metadata is bound independently from the untrusted inventory.
        for path in sorted(required):
            with open(path, "rb") as stream:
                body = stream.read(1048577)
            if len(body) > 1048576:
                raise ValueError()
            evidence.append([os.path.relpath(path, selected_site), hashlib.sha256(body).hexdigest()])
        blob = json.dumps(evidence, ensure_ascii=True, separators=(',', ':')).encode()
        packages.append(dict(name=name, version=dist.version, evidence_digest=hashlib.sha256(blob).hexdigest()))
    print(json.dumps(dict(schema='m3c.python-runtime/v1', version=platform.python_version(), prefix=prefix, packages=packages, environment=environment, site_packages=selected_site, interpreter_root=interpreter_root), sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
