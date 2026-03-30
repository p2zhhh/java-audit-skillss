import os
import re
import json
import xml.etree.ElementTree as ET
import argparse
from typing import List, Dict

# Match ${...} but ignore #{...}
VULNERABLE_PARAM_RE = re.compile(r'\$\{([^}]+)}')

def parse_mybatis_xml(filepath: str) -> List[Dict]:
    findings = []
    try:
        # Some XMLs might not have proper root or DTDs that cause issues.
        # Simple string matching can be more robust, but let's try ET first.
        tree = ET.parse(filepath)
        root = tree.getroot()
        
        # MyBatis mapper root is typically <mapper namespace="...">
        if root.tag != 'mapper':
            return findings
            
        namespace = root.get('namespace', 'UnknownNamespace')
        
        # Tags that contain SQL
        sql_tags = ['select', 'update', 'insert', 'delete', 'sql']
        
        for child in root:
            if child.tag in sql_tags:
                sql_id = child.get('id', 'UnknownID')
                
                # To get all text inside the tag including nested tags like <if>, <where>
                # ET.tostring is a quick way to get the raw content
                raw_xml_str = ET.tostring(child, encoding='unicode', method='xml')
                
                # Strip out the wrapper tag to get inner content
                inner_content = re.sub(f'^<{child.tag}[^>]*>', '', raw_xml_str)
                inner_content = re.sub(f'</{child.tag}>$', '', inner_content)
                
                # Look for ${}
                matches = VULNERABLE_PARAM_RE.findall(inner_content)
                if matches:
                    findings.append({
                        "file": filepath,
                        "namespace": namespace,
                        "id": sql_id,
                        "type": child.tag,
                        "vulnerable_params": list(set(matches)),
                        "sql_snippet": inner_content.strip()
                    })
    except ET.ParseError:
        # Fallback to regex if XML is malformed or has unresolved entities
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
            if '<mapper' not in content:
                return findings
                
            # Basic regex fallback
            matches = VULNERABLE_PARAM_RE.findall(content)
            if matches:
                findings.append({
                    "file": filepath,
                    "namespace": "Unknown (Regex Fallback)",
                    "id": "Unknown",
                    "type": "Unknown",
                    "vulnerable_params": list(set(matches)),
                    "sql_snippet": "Found ${...} but XML parsing failed. Check file manually."
                })
        except Exception as e:
            print(f"[-] Fallback read failed for {filepath}: {e}")
    except Exception as e:
        print(f"[-] Error parsing {filepath}: {e}")
        
    return findings

def scan_directory(directory: str) -> List[Dict]:
    all_findings = []
    for root_dir, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.xml'):
                filepath = os.path.join(root_dir, file)
                # Quick check to avoid parsing non-mybatis XMLs (like pom.xml, web.xml)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        head = f.read(1024)
                        if 'mapper' in head or 'DOCTYPE mapper' in head:
                            findings = parse_mybatis_xml(filepath)
                            all_findings.extend(findings)
                except Exception:
                    pass
    return all_findings

def main():
    parser = argparse.ArgumentParser(description="Extract potential SQL injection points (${...}) from MyBatis XMLs")
    parser.add_argument("-d", "--directory", required=True, help="Directory to scan for .xml files")
    parser.add_argument("-o", "--output", help="Output JSON file path (optional)")
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"[-] Directory not found: {args.directory}")
        return

    print(f"[*] Scanning {args.directory} for MyBatis SQL injection risks (${{...}})...")
    findings = scan_directory(args.directory)
    
    if not findings:
        print("[+] No ${...} usages found in MyBatis XMLs.")
        return
        
    print(f"[!] Found {len(findings)} potential SQL injection points.")
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=4)
        print(f"[+] Findings saved to {args.output}")
    else:
        for f in findings:
            print(f"\n{'-'*60}")
            print(f"File:      {f['file']}")
            print(f"Mapper:    {f['namespace']}.{f['id']} [{f['type']}]")
            print(f"Params:    {', '.join(f['vulnerable_params'])}")
            print(f"Snippet:\n{f['sql_snippet'][:200]}...") # truncate for display

if __name__ == "__main__":
    main()
