"""Build the server-streamed research ELF. Requires the offline USB build audit."""

from __future__ import annotations

import hashlib
import pathlib
import shlex
import shutil
import subprocess
import tempfile

from build_payload import COMMIT, OUT, UPSTREAM, replace_once

NETWORK = pathlib.Path(__file__).resolve().parent / "network"


def main() -> None:
    audit = OUT / "build-audit"
    if not (audit / "decrypt.c").is_file():
        raise RuntimeError("Run build_payload.py first to create the reviewed common source")
    with tempfile.TemporaryDirectory(prefix="pup14-net-") as td:
        source = pathlib.Path(td) / "upstream"
        subprocess.run(["git", "clone", "--quiet", UPSTREAM, str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "checkout", "--quiet", COMMIT], check=True)
        for name in ("main.c", "decrypt.c", "encryptsrv.c"):
            shutil.copyfile(audit / name, source / "source" / name)
        for name in ("defines.h", "debug.h"):
            shutil.copyfile(audit / name, source / "include" / name)
        for name in ("research_net.c", "decryptio.c"):
            shutil.copyfile(NETWORK / name, source / "source" / name)
        shutil.copyfile(NETWORK / "research_net.h", source / "include" / "research_net.h")

        debug = source / "include" / "debug.h"
        replace_once(debug, "extern int research_log_fd;", "")
        replace_once(debug, "f_sprintf(__printfsocket_buffer, format, ##__VA_ARGS__)",
                     "f_snprintf(__printfsocket_buffer, sizeof(__printfsocket_buffer), format, ##__VA_ARGS__)")
        replace_once(debug, "if (research_log_fd >= 0) f_write(research_log_fd, __printfsocket_buffer, __printfsocket_size);\\",
                     "if (__printfsocket_size > 0) research_net_log(__printfsocket_buffer, __printfsocket_size);\\")
        replace_once(debug, "#ifndef __DEBUG_H__", "#ifndef __DEBUG_H__\n#include \"research_net.h\"")

        decrypt = source / "source" / "decrypt.c"
        replace_once(decrypt, "#include \"debug.h\"", "#include \"debug.h\"\n#include \"research_net.h\"")
        replace_once(decrypt,
                     '  state->output_file = f_open(state->output_path, O_WRONLY | O_CREAT | O_TRUNC, 0777);',
                     '  state->output_file = RESEARCH_VIRTUAL_FD;')
        replace_once(decrypt,
                     '  status = decrypt_pup_data(state);',
                     '  if (research_net_begin(state->pup_type == 1 ? 1 : 2) != 0) goto end;\n  status = decrypt_pup_data(state);')
        replace_once(decrypt, "  if (state->output_file != -1)\n  {\n    f_close(state->output_file);",
                     "  if (state->output_file != -1 && state->output_file != RESEARCH_VIRTUAL_FD)\n  {\n    f_close(state->output_file);")
        replace_once(decrypt,
                     '  state.input_file = f_open(state.input_path, O_RDONLY, 0);',
                     '  state.input_file = RESEARCH_VIRTUAL_FD;')
        replace_once(decrypt, "  if (state.input_file != -1)\n  {\n    f_close(state.input_file);",
                     "  if (state.input_file != -1 && state.input_file != RESEARCH_VIRTUAL_FD)\n  {\n    f_close(state.input_file);")
        replace_once(decrypt,
                     '  if (header_data == NULL) {\n    printfsocket("Failed to allocate memory!\\n");\n  }',
                     '  if (header_data == NULL) {\n    printfsocket("Failed to allocate memory!\\n");\n    goto end;\n  }')
        replace_once(decrypt, '       printfsocket(state->notifystr);', '       printfsocket("%s", state->notifystr);')
        replace_once(decrypt, '    printfsocket(state.notifystr);', '    printfsocket("%s", state.notifystr);')
        replace_once(decrypt, '"  Strange segment #%d table: %llu vs %llu\\n",',
                     '"  Strange segment #%d table: %zu vs %zu\\n",')
        replace_once(decrypt, '"  Decrypting %d blocks...\\n   ", block_count',
                     '"  Decrypting %zu blocks...\\n   ", block_count')
        replace_once(decrypt, '"  Decrypting block %d/%d...\\n", i, block_count',
                     '"  Decrypting block %d/%zu...\\n", i, block_count')
        replace_once(decrypt, '"  Failed to read block %d for segment #%d! %d\\n", i, index, bytesread',
                     '"  Failed to read block %d for segment #%d! %zd\\n", i, index, bytesread')
        replace_once(decrypt,
                     '  buffer = f_memalign(0x4000, segment->compressed_size);\n  ssize_t bytesread',
                     '  buffer = f_memalign(0x4000, segment->compressed_size);\n  if (buffer == NULL) return -1;\n  ssize_t bytesread')
        replace_once(decrypt,
                     '  uint8_t* buffer = f_memalign(0x4000, segment->compressed_size);\n\n  int is_compressed',
                     '  uint8_t* buffer = f_memalign(0x4000, segment->compressed_size);\n  if (buffer == NULL) return -1;\n\n  int is_compressed')
        replace_once(decrypt,
                     '  table_buffer = f_memalign(0x4000, table_length);\n\n  ssize_t bytesread',
                     '  table_buffer = f_memalign(0x4000, table_length);\n  if (table_buffer == NULL) return -1;\n\n  ssize_t bytesread')
        replace_once(decrypt,
                     '  block_buffer = f_memalign(0x4000, block_size);',
                     '  block_buffer = f_memalign(0x4000, block_size);\n  if (block_buffer == NULL) goto end;')
        replace_once(decrypt,
                     '  int header_size = file_header.unknown_0C + file_header.unknown_0E;\n\n  header_data = f_memalign(0x4000, header_size);',
                     '  int header_size = file_header.unknown_0C + file_header.unknown_0E;\n  if (header_size < (int)sizeof(file_header) || header_size > 131070) goto end;\n\n  header_data = f_memalign(0x4000, header_size);\n  if (header_data == NULL) goto end;')
        replace_once(decrypt,
                     '  state.device_fd = -1;\n\n  char * strings = (char*)f_malloc(2048);',
                     '  state.device_fd = -1;\n  state.input_file = -1;\n\n  char * strings = (char*)f_malloc(2048);\n  if (strings == NULL) return -1;')

        main_c = source / "source" / "main.c"
        replace_once(main_c, "int research_log_fd = -1;", "")
        data = main_c.read_text(encoding="utf-8")
        start = data.index('    research_log_fd = f_open("/mnt/usb0/PS5_1410_RESEARCH.log"')
        data = data[:start] + '''    if (!f_sceNetSocket || !f_sceNetConnect || !f_sceNetHtons || !f_sceNetSocketClose) {
        research_raw_write("PUP research: network symbols missing\\n", 38);
        return -1;
    }
    int connect_result = research_net_connect();
    if (connect_result != 0) {
        char error_message[128];
        int net_error = f_sceNetErrnoLoc ? *f_sceNetErrnoLoc() : -1;
        f_snprintf(error_message, sizeof(error_message),
                   "PUP research: network connect failed (%d), errno=%d\\n", connect_result, net_error);
        research_raw_write(error_message, f_strlen(error_message));
        printf_notification("PUP research: server connection failed");
        return -1;
    }
    printfsocket("PS5 14.10 full PUP extraction over LAN; no updater API\\n");
    printf_notification("PUP research extraction started");
    int result = decrypt_pups(INPUTPATH, OUTPUTPATH);
    printfsocket(result == 0 ? "RESEARCH EXTRACTION SUCCESS\\n" : "RESEARCH EXTRACTION FAILED\\n");
    research_net_finish(result == 0);
    research_net_close();
    printf_notification(result == 0 ? "PUP extraction sent to server" : "PUP extraction failed: check server log");
    return result;
}
'''
        main_c.write_text(data, encoding="utf-8")

        enc = (source / "source" / "encryptsrv.c").read_text(encoding="utf-8")
        for forbidden in ("sceUpdate", "install_update", "firmware_write", "flash_write"):
            if forbidden in enc + decrypt.read_text(encoding="utf-8") + main_c.read_text(encoding="utf-8"):
                raise RuntimeError(f"Unexpected updater symbol {forbidden}")
        linux_path = subprocess.check_output(
            ["wsl.exe", "bash", "-lc", f"wslpath -a {shlex.quote(str(source))}"], text=True
        ).strip()
        command = f"cd {shlex.quote(linux_path)} && make CC=gcc AS=gcc CFLAGS='-I. -Iinclude -fno-builtin -nostdlib -Wall -m64 -fPIC -mcmodel=small -fcommon'"
        subprocess.run(["wsl.exe", "bash", "-lc", command], check=True)
        net_audit = OUT / "network-build-audit"
        net_audit.mkdir(exist_ok=True)
        for name in ("main.c", "decrypt.c", "decryptio.c", "research_net.c", "encryptsrv.c"):
            shutil.copyfile(source / "source" / name, net_audit / name)
        for name in ("debug.h", "research_net.h"):
            shutil.copyfile(source / "include" / name, net_audit / name)
        target = OUT / "PS5_1410_RESEARCH_LAN.elf"
        shutil.copyfile(source / "ps5_pup_decrypt.elf", target)
        print(target)
        print("sha256", hashlib.sha256(target.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
