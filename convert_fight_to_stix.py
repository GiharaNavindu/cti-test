from stix2 import AttackPattern, Bundle, ExtensionDefinition, Identity
import yaml
import uuid
import json
from datetime import datetime, UTC
import os


def convert_fight_yaml_to_stix(input_file="raw_data/fight_data.yaml", output_file="raw_data/fight_stix_bundle.json"):
    """Convert FiGHT YAML data to STIX format"""
    
    # Load FiGHT YAML
    with open(input_file, "r") as f:
        fight_data = yaml.safe_load(f)

    # Create an identity for the creator
    identity = Identity(
        id=f"identity--{uuid.uuid4()}",
        name="FiGHT to STIX Converter",
        identity_class="organization"
    )

    # Custom extension for FiGHT tiers
    extension_def = ExtensionDefinition(
        id=f"extension-definition--{uuid.uuid4()}",
        created_by_ref=identity.id,
        name="FiGHT Tier Extension",
        version="1.0",
        created=datetime.now(UTC).isoformat(timespec='seconds')[:-6] + "Z",
        modified=datetime.now(UTC).isoformat(timespec='seconds')[:-6] + "Z",
        schema="https://fight.mitre.org/extensions",
        extension_types=["property-extension"]
    )

    stix_objects = [identity, extension_def]
    
    # Extract techniques from FiGHT data
    techniques = fight_data.get("techniques", []) if isinstance(fight_data, dict) else []
    
    for technique in techniques:
        ap = AttackPattern(
            id=f"attack-pattern--{uuid.uuid4()}",
            created_by_ref=identity.id,
            created=datetime.now(UTC).isoformat(timespec='seconds')[:-6] + "Z",
            modified=datetime.now(UTC).isoformat(timespec='seconds')[:-6] + "Z",
            name=technique.get("name", "Unknown") if isinstance(technique, dict) else str(technique),
            description=technique.get("description", "") if isinstance(technique, dict) else "",
            extensions={extension_def.id: {"fight_tier": technique.get("tier", "observed") if isinstance(technique, dict) else "observed"}}
        )
        stix_objects.append(ap)

    # Create bundle
    bundle = Bundle(objects=stix_objects)
    
    # Save bundle
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w") as f:
        f.write(bundle.serialize(pretty=True))
    
    print(f"✓ Converted {len(stix_objects)} FiGHT objects to STIX")
    print(f"✓ Saved to: {output_file}")
    return bundle


if __name__ == "__main__":
    convert_fight_yaml_to_stix()