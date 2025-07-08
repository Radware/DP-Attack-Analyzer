import json
import os
import subprocess
import sys

# Define the path to the main script and the JSON file
json_file_path = 'launcher.json'
main_script_path = 'main.py'

def load_json(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"\nJSON decoding error in file '{filepath}':")
        print(f"  → {e.msg}")
        print(f"  → Line {e.lineno}, Column {e.colno}")
        
        # Optional: Show a line preview
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if 0 < e.lineno <= len(lines):
                error_line = lines[e.lineno - 1]
                print(f"\nProblematic line:\n    {error_line.strip()}")
                col_index = e.colno - 1  # Convert 1-based col to 0-based index
                print("\nLine with <error> inserted:")
                print("    \"" + (error_line[:col_index] + "<error>" + error_line[col_index:]).strip() + "\"")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error while loading JSON: {e}")
        sys.exit(0)

def substitute_env_vars(value):
    """Replace placeholders with actual environment variables."""
    if isinstance(value, str) and value.startswith('$'):
        env_var = value[1:]
        return os.getenv(env_var, value)  # Use the environment variable, fallback to original if not found
    return value

def build_arguments(json_entry):
    """Convert a JSON entry to command-line arguments for the main script."""
    args = []

    #Include the environment name:
    env = json_entry.get('environment')
    if env:
        args.extend(["--environment", env])

    # Check if using cached credentials
    if json_entry.get('use_cached') or json_entry.get('use_cached_credentials'):
        args.append('--use-cached')
    else:
        # Add Vision IP, vision_username, vision_password, vision_root_password with env var substitution
        args.append(substitute_env_vars(json_entry['vision_ip']))
        args.append(substitute_env_vars(json_entry['vision_username']))
        args.append(substitute_env_vars(json_entry['vision_password']))
        args.append(substitute_env_vars(json_entry['vision_root_password']))

    # Add time-range argument
    time_range = json_entry.get('time_range')
    if time_range:
        args.append(time_range['type'])
        if isinstance(time_range['value'], list):
            args.extend(map(str, time_range['value']))  # Add start and end for ranges
        else:
            args.append(str(time_range['value']))  # Add single value (e.g., hours)

    # Add defensepro-list and corresponding policies
    defensepros_policies = json_entry.get('defensepros_policies', {})
    defensepro_list = ",".join(defensepros_policies.keys())
    args.append(defensepro_list)

    for policies in defensepros_policies.values():
        args.append(policies)

    return args

def run_main_script(args):
    """Run the main.py script with the provided arguments."""
    command = [sys.executable, main_script_path] + args
    print(f"Command: {command}", flush=True)
    result = subprocess.run(
        command,
        capture_output=True,
        text=True  # Ensures output is returned as string
    )
    print("Command execution complete.")
    print("[STDOUT]:")
    print(result.stdout)

    if result.returncode != 0:
        print(f"\n[ERROR] main.py failed with return code {result.returncode}", flush=True)
        print(f"[STDERR]:\n{result.stderr.strip()}", flush=True)
        print(f"[STDOUT]:\n{result.stdout.strip()}", flush=True)
        print("Exiting json_launcher.py", flush=True)
        sys.exit(0)

if __name__ == "__main__":
    # Load JSON data
    json_data = load_json(json_file_path)

    # Iterate over each entry in the JSON list and call main.py
    for index, json_entry in enumerate(json_data):
        print(f"Running main.py for entry {index + 1}/{len(json_data)}...", flush=True)
        
        # Build arguments from the current JSON entry
        arguments = build_arguments(json_entry)
        print("Args:", flush=True)
        print(arguments, flush=True)

        # Run the main script with the arguments
        run_main_script(arguments)
            
    print("All entries processed successfully.")
