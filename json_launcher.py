import json
import os
import subprocess
import sys

# Define the path to the main script and the JSON file
json_file_path = 'launcher.json'
main_script_path = 'main.py'

def load_json(file_path):
    """Load the JSON file and return its contents."""
    with open(file_path, 'r') as f:
        return json.load(f)

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
    if json_entry.get('use_cached'):
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
    result = subprocess.run(command)

    if result.returncode != 0:
        print(f"Error: main.py failed with return code {result.returncode}. Exiting json_launcher.py", flush=True)
        sys.exit(0)

if __name__ == "__main__":
    # Load JSON data
    json_data = load_json(json_file_path)

    # Iterate over each entry in the JSON list and call main.py
    for index, json_entry in enumerate(json_data):
        print(f"Running main.py for entry {index + 1}/{len(json_data)}...", flush=True)
        
        # Build arguments from the current JSON entry
        arguments = build_arguments(json_entry)

        # Run the main script with the arguments
        run_main_script(arguments)
            
    print("All entries processed successfully.")
