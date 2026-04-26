import json
import urllib.request
import subprocess
import os

# File paths
REMOTE_LISTS_FILE = "remote-lists.txt"
CUSTOM_RULES_FILE = "custom-rules.txt"

# Output paths for blocked domains
TEMP_BLOCK_JSON = "temp_block.json"
OUTPUT_BLOCK_SRS = "block_rules.srs"

# Output paths for allowed/whitelisted domains
TEMP_ALLOW_JSON = "temp_allow.json"
OUTPUT_ALLOW_SRS = "allow_rules.srs"

SHADOWROCKET_FILE = "shadowrocket_rules.conf"
SING_BOX_EXEC = "./sing-box"

# Use separate sets to automatically deduplicate and route domains
blocked_domains = set()
allowed_domains = set()

def parse_line(line):
    """Extracts clean domains from various AdBlock and host list formats."""
    line = line.strip()
    
    # Ignore empty lines and comments/headers
    if not line or line.startswith(('!', '#', '[')):
        return
    
    # Handle Whitelist/Exception format: @@||example.com^
    if line.startswith('@@||'):
        domain = line[4:].split('^')[0]
        # Ignore complex network rules containing wildcards or paths
        if '/' not in domain and '*' not in domain:
            allowed_domains.add(domain)
            
    # Handle standard AdBlock format: ||example.com^
    elif line.startswith('||'):
        domain = line[2:].split('^')[0]
        if '/' not in domain and '*' not in domain:
            blocked_domains.add(domain)
            
    # Handle standard Hosts file format: 0.0.0.0 example.com
    elif line.startswith(('0.0.0.0 ', '127.0.0.1 ')):
        parts = line.split()
        if len(parts) >= 2:
            blocked_domains.add(parts[1])
            
    # Handle plain domain lists
    elif not any(c in line for c in ['/', '*', '=', ':', ' ']):
        domain = line.split('^')[0]
        # Ensure we don't accidentally catch improperly formatted whitelists
        if not line.startswith('@@'):
            blocked_domains.add(domain)

def compile_singbox_ruleset(domain_set, temp_json, output_srs, name_label):
    """Helper function to compile a Sing-box ruleset."""
    if not domain_set:
        print(f"No {name_label} domains to compile.")
        return

    print(f"Writing {name_label} to JSON: {temp_json}")
    ruleset = {
        "version": 3,
        "rules": [
            {
                "domain_suffix": list(domain_set)
            }
        ]
    }

    with open(temp_json, "w", encoding="utf-8") as f:
        json.dump(ruleset, f)

    print(f"Compiling binary {name_label} rule-set: {output_srs}")
    try:
        subprocess.run(
            [SING_BOX_EXEC, "rule-set", "compile", "--output", output_srs, temp_json], 
            check=True
        )
        print(f"Success! {output_srs} has been created.")
    except subprocess.CalledProcessError:
        print(f"  [!] Compilation failed: Sing-box returned an error for {name_label} rules.")
    except FileNotFoundError:
        print(f"  [!] '{SING_BOX_EXEC}' executable not found. Ensure it is in the current directory.")


def main():
    print("--- Starting Rule-Set Builder ---")
    
    # 1. Fetch and Parse Remote Lists
    if os.path.exists(REMOTE_LISTS_FILE):
        with open(REMOTE_LISTS_FILE, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
            
        for url in urls:
            print(f"Fetching: {url}")
            try:
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

    print(f"Total allowed domains extracted: {len(allowed_domains)}")
    print(f"Total blocked domains extracted: {len(blocked_domains)}")

    if not blocked_domains and not allowed_domains:
        print("No domains found. Exiting.")
        return

    # 3. Format and export Shadowrocket rules
    print(f"\nGenerating Shadowrocket rules: {SHADOWROCKET_FILE}")
    with open(SHADOWROCKET_FILE, "w", encoding="utf-8") as f:
        f.write("[Rule]\n")
        
        # Write DIRECT rules first to ensure they bypass the blocklist
        for domain in sorted(allowed_domains):
            f.write(f"DOMAIN-SUFFIX,{domain},DIRECT\n")
            
        # Write REJECT rules
        for domain in sorted(blocked_domains):
            f.write(f"DOMAIN-SUFFIX,{domain},REJECT\n")
            
    print(f"Success! {SHADOWROCKET_FILE} has been created.")

    # 4 & 5. Format and Compile Sing-box v3 JSONs
    print("\nProcessing Sing-box rules...")
    compile_singbox_ruleset(allowed_domains, TEMP_ALLOW_JSON, OUTPUT_ALLOW_SRS, "Allowed")
    compile_singbox_ruleset(blocked_domains, TEMP_BLOCK_JSON, OUTPUT_BLOCK_SRS, "Blocked")

    # Optional: Clean up temporary JSON files
    # for tmp_file in [TEMP_BLOCK_JSON, TEMP_ALLOW_JSON]:
    #     if os.path.exists(tmp_file):
    #         os.remove(tmp_file)
    # print("Cleaned up temporary files.")

if __name__ == "__main__":
    main()
