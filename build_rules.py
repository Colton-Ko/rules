import json
import urllib.request
import subprocess
import os

# File paths
REMOTE_LISTS_FILE = "remote-lists.txt"
CUSTOM_RULES_FILE = "custom-rules.txt"
TEMP_JSON_FILE = "temp_rules.json"
OUTPUT_SRS_FILE = "block_rules.srs"
SHADOWROCKET_FILE = "shadowrocket_rules.conf"
SING_BOX_EXEC = "./sing-box"

# Use a set to automatically deduplicate domains
domains = set()

def parse_line(line):
    """Extracts clean domains from various AdBlock and host list formats."""
    line = line.strip()
    
    # Ignore empty lines and comments/headers
    if not line or line.startswith(('!', '#', '[')):
        return
    
    # Handle AdBlock format: ||example.com^ or ||example.com^$important
    if line.startswith('||'):
        # Strip '||' and split by '^' to drop the trailing modifiers
        domain = line[2:].split('^')[0]
        # Ignore complex network rules containing wildcards or paths
        if '/' not in domain and '*' not in domain:
            domains.add(domain)
            
    # Handle standard Hosts file format: 0.0.0.0 example.com
    elif line.startswith(('0.0.0.0 ', '127.0.0.1 ')):
        parts = line.split()
        if len(parts) >= 2:
            domains.add(parts[1])
            
    # Handle plain domain lists (like some OISD endpoints)
    elif not any(c in line for c in ['/', '*', '=', ':', ' ']):
        domain = line.split('^')[0]
        domains.add(domain)

def main():
    print("--- Starting Rule-Set Builder ---")
    
    # 1. Fetch and Parse Remote Lists
    if os.path.exists(REMOTE_LISTS_FILE):
        with open(REMOTE_LISTS_FILE, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
            
        for url in urls:
            print(f"Fetching: {url}")
            try:
                # Disguise as a browser to avoid 403 Forbidden errors
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15) as response:
                    for line in response.read().decode('utf-8').splitlines():
                        parse_line(line)
            except Exception as e:
                print(f"  [!] Error fetching {url}: {e}")
    else:
        print(f"  [!] {REMOTE_LISTS_FILE} not found.")

    # 2. Read and Parse Custom Rules
    if os.path.exists(CUSTOM_RULES_FILE):
        print(f"Reading local: {CUSTOM_RULES_FILE}")
        with open(CUSTOM_RULES_FILE, 'r') as f:
            for line in f:
                parse_line(line)
    else:
        print(f"  [!] {CUSTOM_RULES_FILE} not found.")

    print(f"Total unique domains extracted: {len(domains)}")

    if not domains:
        print("No domains found. Exiting.")
        return

    # 3. Format and export Shadowrocket rules
    print(f"Generating Shadowrocket rules: {SHADOWROCKET_FILE}")
    with open(SHADOWROCKET_FILE, "w", encoding="utf-8") as f:
        f.write("[Rule]\n")
        for domain in sorted(domains):
            f.write(f"DOMAIN-SUFFIX,{domain},REJECT\n")
    print(f"Success! {SHADOWROCKET_FILE} has been created.")

    # 4. Format as Sing-box v3 JSON
    print(f"Writing to temporary JSON: {TEMP_JSON_FILE}")
    ruleset = {
        "version": 3,
        "rules": [
            {
                "domain_suffix": list(domains)
            }
        ]
    }

    with open(TEMP_JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(ruleset, f)

    # 5. Compile into binary using local sing-box
    print(f"Compiling binary rule-set: {OUTPUT_SRS_FILE}")
    try:
        subprocess.run(
            [SING_BOX_EXEC, "rule-set", "compile", "--output", OUTPUT_SRS_FILE, TEMP_JSON_FILE], 
            check=True
        )
        print(f"Success! {OUTPUT_SRS_FILE} has been created.")
    except subprocess.CalledProcessError:
        print(f"  [!] Compilation failed: Sing-box returned an error.")
    except FileNotFoundError:
        print(f"  [!] '{SING_BOX_EXEC}' executable not found in the current directory.")

    # 6. Clean up temporary JSON file
    if os.path.exists(TEMP_JSON_FILE):
        os.remove(TEMP_JSON_FILE)
        print("Cleaned up temporary files.")

if __name__ == "__main__":
    main()
