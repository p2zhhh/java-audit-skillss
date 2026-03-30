#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动反编译脚本 (Auto Decompiler)
用途: 当 AI 在追踪数据流时遇到没有源码的 .class 或 .jar 文件，可以调用此脚本快速获取近似 Java 源码。
依赖: 需要环境中安装有 java (JRE)，并在 .trae/skills/shared/tools/ 目录下准备好 cfr.jar (自动下载)。
"""

import sys
import os
import subprocess
import urllib.request

TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
CFR_JAR_PATH = os.path.join(TOOLS_DIR, "cfr.jar")
CFR_DOWNLOAD_URL = "https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"

def ensure_cfr_exists():
    """如果 CFR 反编译器不存在，则自动下载"""
    if not os.path.exists(TOOLS_DIR):
        os.makedirs(TOOLS_DIR)
    
    if not os.path.exists(CFR_JAR_PATH):
        print(f"[*] CFR decompiler not found. Downloading from {CFR_DOWNLOAD_URL}...")
        try:
            # 增加超时以防网络问题
            urllib.request.urlretrieve(CFR_DOWNLOAD_URL, CFR_JAR_PATH)
            print("[+] Download complete.")
        except Exception as e:
            print(f"[-] Error downloading CFR: {e}")
            print("Please download it manually and place it at: " + CFR_JAR_PATH)
            sys.exit(1)

def decompile_file(target_path, specific_class=None):
    """
    反编译指定的文件
    :param target_path: .class 文件或 .jar 文件的绝对路径
    :param specific_class: 如果是 .jar 文件，可以指定只反编译其中的某个类（如 com.example.MyClass）
    """
    if not os.path.exists(target_path):
        print(f"[-] Error: Target file not found: {target_path}")
        sys.exit(1)

    # 构建 CFR 命令行参数
    # --silent true 减少无用输出
    # --hideutf false 防止中文字符被转义
    cmd = ["java", "-jar", CFR_JAR_PATH, target_path, "--silent", "true", "--hideutf", "false"]
    
    if specific_class and target_path.endswith(".jar"):
        cmd.extend(["--extraclasspath", target_path, specific_class])
        
    print(f"[*] Executing decompilation: {' '.join(cmd)}\n")
    print("-" * 50)
    
    try:
        # 执行反编译并捕获输出
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        
        if result.returncode == 0:
            # 成功，输出反编译后的源码
            print(result.stdout)
        else:
            # 失败，输出错误信息
            print("[-] Decompilation failed.")
            print(result.stderr)
            
    except Exception as e:
        print(f"[-] Execution error: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python auto_decompile.py <path_to_class_or_jar> [specific_class_name_in_jar]")
        print("Example 1: python auto_decompile.py /path/to/Target.class")
        print("Example 2: python auto_decompile.py /path/to/lib.jar com.example.utils.SecretUtil")
        sys.exit(1)
        
    ensure_cfr_exists()
    
    target_path = sys.argv[1]
    specific_class = sys.argv[2] if len(sys.argv) > 2 else None
    
    decompile_file(target_path, specific_class)

if __name__ == "__main__":
    main()