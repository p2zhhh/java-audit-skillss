#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量反编译与源码映射脚本 (Batch Decompile Mapper)
用途: 针对只有 .class 文件和 .jar 文件的生产包（如 Tomcat WEB-INF 目录），
      批量将其反编译为可供 AST 工具和 AI 审计的 .java 源码目录结构。
依赖: 需要环境中安装有 java (JRE)，并在 .trae/skills/shared/tools/ 目录下准备好 cfr.jar。
"""

import sys
import os
import subprocess
import shutil

TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
CFR_JAR_PATH = os.path.join(TOOLS_DIR, "cfr.jar")

def check_cfr():
    if not os.path.exists(CFR_JAR_PATH):
        print(f"[-] Error: CFR decompiler not found at {CFR_JAR_PATH}")
        print("[!] Please run `python auto_decompile.py` first to trigger auto-download.")
        sys.exit(1)

def batch_decompile(target_dir, output_dir):
    """
    使用 CFR 的批量反编译功能，将目标目录下的所有 .class 还原并保持目录结构。
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    print(f"[*] Starting batch decompilation from: {target_dir}")
    print(f"[*] Output directory: {output_dir}")
    print("[*] This may take a few minutes depending on the project size...")
    
    # CFR 的参数 --outputdir 可以直接将反编译结果按照原有的包结构写入指定目录
    cmd = [
        "java", "-jar", CFR_JAR_PATH,
        target_dir,
        "--outputdir", output_dir,
        "--silent", "true",
        "--hideutf", "false",
        "--renamedupmembers", "true" # 解决一些混淆代码的重名问题
    ]
    
    try:
        # 使用 Popen 实时输出进度
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        count = 0
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                # 简单打印进度条
                count += 1
                if count % 50 == 0:
                    print(f"    ... decompiled {count} files")
                    
        if process.returncode == 0:
            print(f"\n[+] Batch decompilation completed successfully!")
            print(f"[+] You can now run `batch_ast_scanner.py {output_dir}` to analyze the source code.")
        else:
            print("\n[-] Decompilation finished with some errors (check manually if needed).")
            
    except Exception as e:
        print(f"[-] Execution error: {e}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python batch_decompile_mapper.py <target_classes_or_jar_dir> <output_src_dir>")
        print("Example: python batch_decompile_mapper.py /var/www/html/WEB-INF/classes /tmp/audit_src")
        sys.exit(1)
        
    check_cfr()
    
    target_dir = sys.argv[1]
    output_dir = sys.argv[2]
    
    if not os.path.exists(target_dir):
        print(f"[-] Error: Target directory not found - {target_dir}")
        sys.exit(1)
        
    batch_decompile(target_dir, output_dir)

if __name__ == "__main__":
    main()