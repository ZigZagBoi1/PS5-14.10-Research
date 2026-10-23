"""Build a guarded PS5 PUP research ELF from a pinned upstream revision.

Run on Windows with Python 3 and Ubuntu WSL (gcc and make installed).
The upstream source stays in a temporary build directory; no console access occurs.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import shlex
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "artifacts" / "pup14"
UPSTREAM = "https://github.com/zecoxao/ps5-pup-decrypt.git"
COMMIT = "290f5dd216b6878223457f51b32127acc480964a"


def replace_once(path: pathlib.Path, old: str, new: str) -> None:
    data = path.read_text(encoding="utf-8")
    if data.count(old) != 1:
        raise RuntimeError(f"Expected one occurrence in {path.name}: {old[:70]!r}")
    path.write_text(data.replace(old, new), encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pup14-build-") as td:
        source = pathlib.Path(td) / "upstream"
        subprocess.run(["git", "clone", "--quiet", UPSTREAM, str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "checkout", "--quiet", COMMIT], check=True)

        defines = source / "include" / "defines.h"
        replace_once(defines, '/mnt/usb0/%s.dec', '/mnt/usb0/PS5_1410_%s.dec')
        replace_once(defines, '/mnt/usb0/safe.PS5UPDATE.PUP', '/mnt/usb0/PS5_1410_RESEARCH.PUP')

        debug = source / "include" / "debug.h"
        replace_once(debug, "extern int sock;", "extern int sock;\nextern int research_log_fd;")
        replace_once(
            debug,
            "  f_sceNetSend(sock, __printfsocket_buffer, __printfsocket_size, 0);\\",
            "  if (research_log_fd >= 0) f_write(research_log_fd, __printfsocket_buffer, __printfsocket_size);\\",
        )

        decrypt = source / "source" / "decrypt.c"
        replace_once(decrypt, "if (result < 0)\n    {\n      int errcode = errno;", "if (result != 0)\n    {\n      int errcode = errno;")
        replace_once(decrypt, "      result = 0;\n      //goto end;", "      goto end;")
        replace_once(decrypt, '      printfsocket("  Failed to read block %d for segment #%d! %d\\n", i, index, bytesread);\n      goto end;', '      printfsocket("  Failed to read block %d for segment #%d! %d\\n", i, index, bytesread);\n      result = -1;\n      goto end;')
        replace_once(decrypt, '      printfsocket("  Failed to write block %d for segment #%d!\\n", i, index);\n      goto end;', '      printfsocket("  Failed to write block %d for segment #%d!\\n", i, index);\n      result = -1;\n      goto end;')
        replace_once(decrypt, '        printfsocket("Failed to find table for segment #%d!\\n", i);\n        continue;', '        printfsocket("Failed to find table for segment #%d!\\n", i);\n        goto end;')
        replace_once(decrypt, '  result = verify_segments(state, segments, header->segment_count);\n  if (result < 0)', '  result = verify_segments(state, segments, header->segment_count);\n  if (result != 0)')
        replace_once(decrypt, "int decrypt_pup_data(const decrypt_state * state)\n{\n  int result;", "int decrypt_pup_data(const decrypt_state * state)\n{\n  int result;\n  int status = -1;")
        replace_once(decrypt, "    if (result < 0) {\n       goto end;\n    }\n\n\n  }\n\nend:", "    if (result != 0) {\n       goto end;\n    }\n\n\n  }\n\n  status = 0;\nend:")
        replace_once(decrypt, "  return 0;\n}\n\nvoid decrypt_pup", "  return status;\n}\n\nint decrypt_pup")
        replace_once(decrypt, "int decrypt_pup(decrypt_state * state, const char * OutputPath)\n{", "int decrypt_pup(decrypt_state * state, const char * OutputPath)\n{\n  int status = -1;")
        replace_once(decrypt, "  decrypt_pup_data(state);", "  status = decrypt_pup_data(state);")
        replace_once(decrypt, "  if (state->output_file != -1)\n  {\n    f_close(state->output_file);\n  }\n\n}\n\n\nvoid decrypt_pups", "  if (state->output_file != -1)\n  {\n    f_close(state->output_file);\n  }\n  return status;\n}\n\n\nint decrypt_pups")
        replace_once(decrypt, "int decrypt_pups(const char * InputPath, const char * OutputPath)\n{", "int decrypt_pups(const char * InputPath, const char * OutputPath)\n{\n  int status = -1;")
        replace_once(decrypt, "    decrypt_pup(&state, OutputPath);", "    if (decrypt_pup(&state, OutputPath) != 0) {\n      printfsocket(\"PUP entry decryption FAILED\\n\");\n      goto end;\n    }")
        replace_once(decrypt, "    state.device_fd = -1;\n\n  }\n\nend:", "    state.device_fd = -1;\n\n  }\n\n  status = 0;\nend:")
        # The final return sits at the end of decrypt_pups.
        data = decrypt.read_text(encoding="utf-8")
        if not data.rstrip().endswith("}"):
            raise RuntimeError("Unexpected decrypt.c ending")
        tail = data.rfind("\n}")
        data = data[:tail] + "\n  return status;" + data[tail:]
        decrypt.write_text(data, encoding="utf-8")

        main_c = source / "source" / "main.c"
        replace_once(main_c, "void decrypt_pups();", "int decrypt_pups();")
        replace_once(main_c, "int sock;", "int sock;\nint research_log_fd = -1;")
        replace_once(main_c,
                     "int payload_main(struct payload_args *args) {\n    dlsym_t* dlsym = args->dlsym;",
                     '''/* Relapse elfldr passes a getpid syscall stub at args[0], not dlsym.
 * Resolve symbols with the stable dynlib_dlsym syscall (591) directly. */
static int research_dlsym(int handle, const char *name, void *out) {
    long result = 591;
    __asm__ volatile("syscall" : "+a"(result)
                     : "D"((long)handle), "S"(name), "d"(out)
                     : "rcx", "r11", "memory", "cc");
    return (int)result;
}
static void research_raw_write(const char *message, unsigned long length) {
    long result = 4;
    __asm__ volatile("syscall" : "+a"(result)
                     : "D"(1L), "S"(message), "d"(length)
                     : "rcx", "r11", "memory", "cc");
}

int payload_main(struct payload_args *args) {
    (void)args;
    dlsym_t* dlsym = research_dlsym;''')
        replace_once(main_c,
                     'dlsym(libKernel, "sceKernelLoadStartModule", &f_sceKernelLoadStartModule);',
                     'dlsym(libKernel, "sceKernelLoadStartModule", &f_sceKernelLoadStartModule);\n'
                     '    if (!f_sceKernelLoadStartModule) {\n'
                     '        research_raw_write("PUP research: symbol resolution failed\\n", 39);\n'
                     '        return -1;\n'
                     '    }')
        data = main_c.read_text(encoding="utf-8")
        start = data.index('\tprintf_notification("PUP Decrypt started!");')
        data = data[:start] + '''
    research_log_fd = f_open("/mnt/usb0/PS5_1410_RESEARCH.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (research_log_fd < 0) {
        printf_notification("PUP research: cannot write USB log");
        return -1;
    }
    printfsocket("PS5 14.10 PUP research extraction; no updater API\\n");
    printf_notification("PUP research extraction started");
    int result = decrypt_pups(INPUTPATH, OUTPUTPATH);
    if (result == 0) {
        printfsocket("RESEARCH EXTRACTION SUCCESS\\n");
        printf_notification("PUP extraction complete: check USB log");
    } else {
        printfsocket("RESEARCH EXTRACTION FAILED\\n");
        printf_notification("PUP extraction failed: check USB log");
    }
    f_close(research_log_fd);
    return result;
}
'''
        main_c.write_text(data, encoding="utf-8")

        # Static guard: only the five documented PUP crypto/verification ioctls.
        enc = (source / "source" / "encryptsrv.c").read_text(encoding="utf-8")
        ioctls = set(re.findall(r"f_ioctl\(fd,\s*(0x[0-9A-Fa-f]+)", enc))
        expected = {"0xC0104401", "0xC0184402", "0xC0184405", "0xC0284406"}
        if ioctls != expected:
            raise RuntimeError(f"Unexpected ioctl set: {ioctls}")
        if "additional != 0 ? 0xC0184403 : 0xC0184404" not in enc:
            raise RuntimeError("Unexpected segment verification ioctl dispatch")
        for forbidden in ("sceUpdate", "install_update", "firmware_write", "flash_write"):
            if forbidden in "".join(p.read_text(encoding="utf-8", errors="ignore") for p in (source / "source").glob("*.c")):
                raise RuntimeError(f"Forbidden updater symbol: {forbidden}")

        linux_path = subprocess.check_output(
            ["wsl.exe", "bash", "-lc", f"wslpath -a {shlex.quote(str(source))}"], text=True
        ).strip()
        command = f"cd {shlex.quote(linux_path)} && make CC=gcc AS=gcc CFLAGS='-I. -Iinclude -fno-builtin -nostdlib -Wall -m64 -fPIC -mcmodel=small -fcommon'"
        subprocess.run(["wsl.exe", "bash", "-lc", command], check=True)
        audit = OUT / "build-audit"
        audit.mkdir(exist_ok=True)
        for name in ("main.c", "decrypt.c", "decryptio.c", "encryptsrv.c"):
            shutil.copyfile(source / "source" / name, audit / name)
        for name in ("debug.h", "defines.h"):
            shutil.copyfile(source / "include" / name, audit / name)
        elf = source / "ps5_pup_decrypt.elf"
        target = OUT / "PS5_1410_RESEARCH.elf"
        shutil.copyfile(elf, target)
        print(target)
        print("sha256", hashlib.sha256(target.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
