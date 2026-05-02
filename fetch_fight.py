import requests
import yaml
import os


def fetch_fight_data(output_dir="raw_data"):
    """Fetch FiGHT framework data and save as YAML"""
    fight_techniques_url = "https://fight.mitre.org/fight.yaml"
    
    try:
        response = requests.get(fight_techniques_url, timeout=30)
        response.raise_for_status()
        
        data = yaml.safe_load(response.text)
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, "fight_data.yaml")
        with open(output_file, "w") as f:
            yaml.dump(data, f)
        
        print(f"✓ Successfully fetched FiGHT data")
        print(f"✓ Saved to: {output_file}")
        return data
        
    except requests.RequestException as e:
        print(f"✗ Error fetching FiGHT: {e}")
        raise
    except yaml.YAMLError as e:
        print(f"✗ Error parsing FiGHT YAML: {e}")
        raise


if __name__ == "__main__":
    fetch_fight_data()