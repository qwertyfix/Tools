# Basic functions
- This script is for reconnaissance, primarily for files. CTF categories like reverse and pwn
- Works with five instruments (file, strings, nm, objdump, checksec)
- Provides all the main information in a convenient form on the terminal
- Can automatically find function locations, offsets, and suspicious objects using keywords (You can change the keywords in the code as you wish)

# Source 
```python
import subprocess
import platform
import sys
import os
import re

import subprocess

def objdump(target):
    resR = subprocess.run(["objdump", "-R", target], capture_output=True, text=True)
    resh = subprocess.run(["objdump", "-h", target], capture_output=True, text=True)
    
    linesR = resR.stdout.splitlines()
    linesh = resh.stdout.splitlines()

    keywords = ["system", "gets", "printf", "scanf", "strcpy", "exec", "puts"]
    print(f"\n--- [ Analysis: objdump -R (GOT Targets) ] ---")
    found_any = False

    for line in linesR:
        for func in keywords:
            if func in line:
                parts = line.split()
                if len(parts) >= 3:
                    addr = parts[0]
                    name = parts[-1]
                    print(f"  [!] Target: {name:<20} | GOT Address: {addr}")
                    
                    if "gets" in name: print("      Danger: Classic Buffer Overflow (no bounds check).")
                    if "system" in name: print("      Danger: Direct Shell Execution available.")
                    if "printf" in name: print("      Danger: Check for Format String vulnerability.")
                    found_any = True
                break

    if not found_any: print("  [+] No critical external functions found.")

    keywords2 = [".text", ".bss", ".data", ".got", ".plt"]
    print(f"\n--- [ Analysis: objdump -h (Memory Map) ] ---")
    
    for i in range(len(linesh)):
        line = linesh[i]
        for sec in keywords2:
            if f" {sec} " in f" {line} ":
                parts = line.split()
                if len(parts) >= 4:
                    name, size, vma = parts[1], parts[2], parts[3]
                    
                    flags = linesh[i+1].strip() if i+1 < len(linesh) else "N/A"
                    
                    print(f"  [>] Section: {name:<10} | VMA: {vma} | Size: {size}")
                    print(f"      Perms: {flags}")
                    
                    if ".bss" in name: print("      Note: Writable area (good for /bin/sh or shellcode).")
                    if ".text" in name: print("      Note: Executable code (search ROP gadgets here).")
                break

def nm(target):
    keywords = ["main", "win", "flag", "shell", "admin", "secret", "backdoor"]
    result = subprocess.run(["nm", "-C", target], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    print("\n--- [ Coordinates & Entry Points ] ---")
    found_any = False

    for line in lines:
        parts = line.split()
        
        if len(parts) >= 3:
            addr = parts[0]
            sym_type = parts[1]
            name = parts[2]

            for keyword in keywords:
                if keyword.lower() in name.lower():
                    print(f"  [+] {name:<15} | Address: 0x{addr} | Type: {sym_type}")
                    found_any = True
                    break

    if not found_any:
        print("  [-] Specific functions not found.")


def checksec(target):
    result = subprocess.run(["checksec", "file", target], capture_output=True, text=True)

    output = result.stdout

    print(f"\n[***] Security Analysis for: {target}")
    
    if "Canary Found" in output:
        print("[+] Canary: FOUND ")
    else:
        print("[-] Canary: NOT FOUND (Classic Stack Overflow possible)")

    if "NX enabled" in output:
        print("[+] NX: ENABLED")
    else:
        print("[-] NX: DISABLED")

    if "PIE enabled" in output:
        print("[+] PIE: ENABLED")
    else:
        print("[-] PIE: DISABLED")

    if "Full RELRO" in output:
        print("[+] RELRO: FULL")
    elif "Partial RELRO" in output:
        print("[/] RELRO: PARTIAL")
    else:
        print("[-] RELRO: DISABLED")

def strings(target, show_all):

    result = subprocess.run(["strings", target], capture_output=True, text=True)

    output = result.stdout.splitlines()

    keywords = {
    "Exploitation": ["system", "exec", "shell", "bin/sh", "bin/bash", "passthru", "popen"],
    "Logic/Flags": ["Usage:", "cracked", "flag", "password", "Try again", "Enter your", "correct", "wrong"],
    "Networking": ["socket", "connect", "bind", "listen", "port", "sockaddr"],
    "Debug/Errors": ["construction from null", "logic_error", "stack_chk_fail", "debug"],
    "Library_Calls": ["strlen", "memcmp", "malloc", "free", "printf", "scanf"]
    }

    found_highlights = {cat: [] for cat in keywords}

    for s in output:
        for category, words in keywords.items():
            for word in words:
                if word.lower() in s.lower():
                    found_highlights[category].append(s.strip())



    for category, matches in found_highlights.items():
        if matches:
            unique_matches = list(set(matches))
            print(f"\n--- {category} ({len(unique_matches)} found) ---")


            to_print = unique_matches if show_all else unique_matches[:10]
            
            for match in to_print:
                print(f"  [>] {match}")
            
            if not show_all and len(unique_matches) > 10:
                print(f"  ... and {len(unique_matches) - 10} more. Use --all or -a to see them.")


def analyze_file(target):
    result = subprocess.run(["file", target], capture_output=True, text=True)

    output = result.stdout

    string = False

    print(f"\n[***] Analysis for: {target}")

    if "LSB" in output:
            print("[+] Endianness: Little-endian")
    else:
            print("[+] Endianness: Big-endian")

    if "32-bit" in output:
            print("[+] Arch: x86 (32-bit)")
    elif "64-bit" in output:
            print("[+] Arch: x64 (64-bit)")

    if "dynamically linked" in output:
            print("[+] Linking: Dynamic")
            if "interpreter" in output:
                interp = output.split("interpreter")[1].split(",")[0].strip()
                print(f"    └─ Loader: {interp}")
    else:
            print("[+] Linking: Static")

    if "not stripped" in output:
            print("[+] Symbols: Not stripped")
            string = True
    else:
            print("[!] Symbols: Stripped")

    if "BuildID" in output:
            bid = output.split("BuildID[sha1]=")[1].split(",")[0].strip()
            print(f"[+] Build ID: {bid}")

    if "for GNU/Linux" in output:
            version = output.split("for GNU/Linux")[1].split(",")[0].strip()
            print(f"[+] Target OS: Linux {version}")

    return string

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <filename> [--all or --a]")
        sys.exit(1)

    target = sys.argv[1]

    show_all = "--all" in sys.argv or "-a" in sys.argv

    if not os.path.exists(target):
        print(f"Error: {target} not found.")
        sys.exit(1)
    else:
        string = analyze_file(target)

        checksec(target)

        if string:
            strings(target, show_all)

        nm(target)

        objdump(target)

if __name__ == "__main__":
    main()
```



# The code is generally working, but there's room for improvement. If you'd like to use it, please provide feedback and rate it.
