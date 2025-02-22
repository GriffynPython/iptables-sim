import re

def parse_iptables_save(iptables_save_output):
    """Parses iptables-save output into a Python data structure."""

    tables = {}
    current_table = None
    current_chain = None

    for line in iptables_save_output.splitlines():
        line = line.strip()  # Remove leading/trailing whitespace

        if line.startswith("*"):  # Start of a table
            current_table = line[1:]  # Extract table name
            tables[current_table] = {}  # Initialize table dictionary
        elif line.startswith(":"):  # Chain definition
            parts = line[1:].split()
            current_chain = parts[0]
            policy = parts[1]
            tables[current_table][current_chain] = {"policy": policy, "rules": []}
        elif line.startswith("-A"):  # Rule
            if current_table and current_chain:
                rule_data = parse_rule(line) # Function to parse individual rule
                tables[current_table][current_chain]["rules"].append(rule_data)
    return tables

def parse_rule(rule_line):
    """Parses a single iptables rule string."""
    rule_parts = shlex.split(rule_line) # Use shlex to correctly split the line
    rule = {}
    rule["rule"] = rule_line # Store original rule
    matches = []
    actions = []

    i = 0
    while i < len(rule_parts):
        part = rule_parts[i]
        if part.startswith("--"): # Long option
            match = {}
            match["option"] = part[2:] # Get option name
            if rule_parts[i+1].startswith("-"): # No value
                match["value"] = None
                i += 1
            else: # Has value
                match["value"] = rule_parts[i+1]
                i += 2
            matches.append(match)
        elif part.startswith("-"): # Short option
            match = {}
            match["option"] = part[1:] # Get option name
            if i+1 < len(rule_parts) and not rule_parts[i+1].startswith("-"): # Has value
                match["value"] = rule_parts[i+1]
                i += 2
            else:
                match["value"] = None
                i += 1
            matches.append(match)
        elif part == "-j": # Jump to target
            action = {}
            action["type"] = "jump"
            action["target"] = rule_parts[i+1]
            actions.append(action)
            i += 2
        else: # Other actions
            action = {}
            action["type"] = part
            actions.append(action)
            i += 1
    rule["matches"] = matches
    rule["actions"] = actions
    return rule


with open("iptables.rules", "r") as f:
    iptables_output = f.read()

parsed_rules = parse_iptables_save(iptables_output)
print(parsed_rules)
