"""
Automated CTI Pipeline
Complete workflow: Fetch -> Convert -> Visualize -> Prune
"""

import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path

# Import pipeline modules
from fetch_attack import get_attack_bundle, save_bundle_to_file
from fetch_fight import fetch_fight_data
from convert_fight_to_stix import convert_fight_yaml_to_stix
from visualize_stix import STIXVisualizer, visualize_and_print_summary
from prune_stix import prune_stix_bundle


class CTIPipeline:
    """Orchestrates complete CTI processing pipeline"""
    
    def __init__(self, config=None):
        """Initialize pipeline with optional configuration"""
        self.config = config or self._default_config()
        self.base_dir = Path(self.config['base_dir'])
        self.raw_data_dir = self.base_dir / self.config['raw_data_dir']
        self.processed_data_dir = self.base_dir / self.config['processed_data_dir']
        self.viz_dir = self.processed_data_dir / "visualizations"
        
        # Create directories
        self._setup_directories()
        
        self.start_time = None
        self.logs = []
        
    def _default_config(self) -> dict:
        """Default configuration"""
        return {
            'base_dir': '.',
            'raw_data_dir': 'raw_data',
            'processed_data_dir': 'processed_data',
            'fetch_attack': True,
            'fetch_fight': True,
            'convert_fight': True,
            'visualize': True,
            'prune': True,
            'log_file': 'pipeline.log'
        }
    
    def _setup_directories(self):
        """Create required directories"""
        self.raw_data_dir.mkdir(parents=True, exist_ok=True)
        self.processed_data_dir.mkdir(parents=True, exist_ok=True)
        self.viz_dir.mkdir(parents=True, exist_ok=True)
    
    def _log(self, message: str, level: str = "INFO"):
        """Log message to console and file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"
        print(log_message)
        self.logs.append(log_message)
    
    def _save_logs(self):
        """Save logs to file"""
        log_file = self.base_dir / self.config['log_file']
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.logs))
    
    def step_1_fetch_attack_data(self) -> bool:
        """Step 1: Fetch ATT&CK data from TAXII server"""
        if not self.config['fetch_attack']:
            self._log("Skipping ATT&CK fetch (disabled in config)")
            return True
        
        self._log("="*70)
        self._log("STEP 1: Fetching ATT&CK Data from MITRE TAXII Server")
        self._log("="*70)
        
        try:
            bundle_path = self.raw_data_dir / 'attck_bundle.json'
            
            if bundle_path.exists():
                self._log(f"✓ ATT&CK bundle already exists at {bundle_path}")
                return True
            
            self._log("Connecting to MITRE ATT&CK TAXII server...")
            bundle = get_attack_bundle()
            
            # Save bundle
            save_bundle_to_file(bundle, str(bundle_path))
            
            self._log(f"✓ Successfully fetched {len(bundle)} objects from ATT&CK")
            self._log(f"✓ Saved to: {bundle_path}")
            return True
            
        except Exception as e:
            self._log(f"✗ Error fetching ATT&CK data: {str(e)}", "ERROR")
            return False
    
    def step_2_fetch_fight_data(self) -> bool:
        """Step 2: Fetch FiGHT data from MITRE"""
        if not self.config['fetch_fight']:
            self._log("Skipping FiGHT fetch (disabled in config)")
            return True
        
        self._log("\n" + "="*70)
        self._log("STEP 2: Fetching FiGHT Data")
        self._log("="*70)
        
        try:
            fight_file = self.raw_data_dir / 'fight_data.yaml'
            
            if fight_file.exists():
                self._log(f"✓ FiGHT data already exists at {fight_file}")
                return True
            
            self._log("Fetching FiGHT framework data...")
            fetch_fight_data(str(self.raw_data_dir))
            
            self._log(f"✓ Successfully fetched FiGHT data")
            self._log(f"✓ Saved to: {fight_file}")
            return True
            
        except Exception as e:
            self._log(f"✗ Error fetching FiGHT data: {str(e)}", "ERROR")
            return False
    
    def step_3_convert_fight_to_stix(self) -> bool:
        """Step 3: Convert FiGHT YAML to STIX format"""
        if not self.config['convert_fight']:
            self._log("Skipping FiGHT to STIX conversion (disabled in config)")
            return True
        
        self._log("\n" + "="*70)
        self._log("STEP 3: Converting FiGHT YAML to STIX Format")
        self._log("="*70)
        
        try:
            fight_yaml = self.raw_data_dir / 'fight_data.yaml'
            fight_stix = self.raw_data_dir / 'fight_stix_bundle.json'
            
            if not fight_yaml.exists():
                self._log(f"✗ FiGHT YAML not found at {fight_yaml}", "ERROR")
                return False
            
            self._log("Converting FiGHT YAML to STIX objects...")
            
            # Change to raw_data directory for the conversion script
            original_cwd = os.getcwd()
            os.chdir(self.raw_data_dir.parent)
            
            try:
                convert_fight_yaml_to_stix()
                self._log(f"✓ Successfully converted FiGHT to STIX")
                self._log(f"✓ Saved to: {fight_stix}")
                return True
            finally:
                os.chdir(original_cwd)
                
        except Exception as e:
            self._log(f"✗ Error converting FiGHT to STIX: {str(e)}", "ERROR")
            return False
    
    def step_4_visualize_threat_data(self) -> bool:
        """Step 4: Visualize both ATT&CK and FiGHT data"""
        if not self.config['visualize']:
            self._log("Skipping visualization (disabled in config)")
            return True
        
        self._log("\n" + "="*70)
        self._log("STEP 4: Visualizing Threat Data")
        self._log("="*70)
        
        try:
            attack_bundle = self.raw_data_dir / 'attck_bundle.json'
            fight_bundle = self.raw_data_dir / 'fight_stix_bundle.json'
            
            # Check if bundles exist
            if not attack_bundle.exists():
                self._log(f"✗ ATT&CK bundle not found at {attack_bundle}", "ERROR")
                return False
            
            if not fight_bundle.exists():
                self._log(f"✗ FiGHT STIX bundle not found at {fight_bundle}", "ERROR")
                return False
            
            self._log("Generating threat data visualizations...")
            self._log(f"  - Creating interactive network graphs")
            self._log(f"  - Generating statistics dashboards")
            self._log(f"  - Building relationship heatmaps")
            
            # Visualize
            visualizer = STIXVisualizer(str(self.viz_dir))
            results = visualizer.visualize_threat_data(str(attack_bundle), str(fight_bundle))
            
            self._log(f"\n✓ Visualization Summary:")
            self._log(f"  - ATT&CK Objects: {len(results['attack_objects'])}")
            self._log(f"  - FiGHT Objects: {len(results['fight_objects'])}")
            self._log(f"  - ATT&CK Relationships: {len(results['attack_graph'].edges())}")
            self._log(f"  - FiGHT Relationships: {len(results['fight_graph'].edges())}")
            self._log(f"✓ Visualizations saved to: {self.viz_dir}")
            
            return True
            
        except Exception as e:
            self._log(f"✗ Error during visualization: {str(e)}", "ERROR")
            import traceback
            self._log(traceback.format_exc(), "ERROR")
            return False
    
    def step_5_prune_stix_data(self) -> bool:
        """Step 5: Prune STIX data using semantic similarity"""
        if not self.config['prune']:
            self._log("Skipping pruning (disabled in config)")
            return True
        
        self._log("\n" + "="*70)
        self._log("STEP 5: Pruning STIX Data Using Semantic Similarity")
        self._log("="*70)
        
        try:
            attack_bundle = self.raw_data_dir / 'attck_bundle.json'
            ontology_file = Path(__file__).parent / 'oran_ontology.json'
            
            if not attack_bundle.exists():
                self._log(f"✗ ATT&CK bundle not found", "ERROR")
                return False
            
            if not ontology_file.exists():
                self._log(f"✗ ORAN ontology not found at {ontology_file}", "ERROR")
                return False
            
            self._log("Pruning using ORAN ontology semantic similarity...")
            self._log("  - Max-Sim strategy for ontology matching")
            self._log("  - 25% minimum relevance threshold")
            
            # Change to pipeline directory for prune script
            original_cwd = os.getcwd()
            os.chdir(Path(__file__).parent)
            
            try:
                prune_stix_bundle(str(attack_bundle), str(self.processed_data_dir))
                self._log(f"✓ Successfully pruned STIX data")
                self._log(f"✓ Pruned bundle saved to: {self.processed_data_dir}/lite_bundle.json.gz")
                return True
            finally:
                os.chdir(original_cwd)
                
        except Exception as e:
            self._log(f"✗ Error during pruning: {str(e)}", "ERROR")
            import traceback
            self._log(traceback.format_exc(), "ERROR")
            return False
    
    def run(self) -> bool:
        """Execute complete pipeline"""
        self.start_time = datetime.now()
        
        self._log("\n")
        self._log("█" * 70)
        self._log("█" + " " * 68 + "█")
        self._log("█" + "  STIXX-CTI PIPELINE - COMPLETE THREAT INTELLIGENCE WORKFLOW".center(68) + "█")
        self._log("█" + " " * 68 + "█")
        self._log("█" * 70)
        self._log(f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        steps = [
            ("ATT&CK Data Fetch", self.step_1_fetch_attack_data),
            ("FiGHT Data Fetch", self.step_2_fetch_fight_data),
            ("FiGHT to STIX Conversion", self.step_3_convert_fight_to_stix),
            ("Threat Data Visualization", self.step_4_visualize_threat_data),
            ("STIX Data Pruning", self.step_5_prune_stix_data),
        ]
        
        results = {}
        for step_name, step_func in steps:
            result = step_func()
            results[step_name] = result
            
            if not result:
                self._log(f"\n⚠️  Pipeline halted at step: {step_name}", "WARNING")
                break
        
        # Final summary
        self._log("\n" + "="*70)
        self._log("PIPELINE EXECUTION SUMMARY")
        self._log("="*70)
        
        for step_name, result in results.items():
            status = "✓ PASSED" if result else "✗ FAILED"
            self._log(f"{status}: {step_name}")
        
        end_time = datetime.now()
        elapsed = (end_time - self.start_time).total_seconds()
        
        self._log(f"\nCompleted: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self._log(f"Total Time: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")
        
        overall_success = all(results.values())
        if overall_success:
            self._log("\n✓ Pipeline completed successfully!")
        else:
            self._log("\n✗ Pipeline completed with errors. Check logs for details.")
        
        self._log("="*70 + "\n")
        
        # Save logs
        self._save_logs()
        self._log(f"Logs saved to: {self.base_dir / self.config['log_file']}")
        
        return overall_success


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='STIXX-CTI Threat Intelligence Pipeline')
    parser.add_argument('--skip-fetch-attack', action='store_true', help='Skip ATT&CK data fetch')
    parser.add_argument('--skip-fetch-fight', action='store_true', help='Skip FiGHT data fetch')
    parser.add_argument('--skip-convert', action='store_true', help='Skip FiGHT to STIX conversion')
    parser.add_argument('--skip-viz', action='store_true', help='Skip visualization')
    parser.add_argument('--skip-prune', action='store_true', help='Skip pruning')
    parser.add_argument('--only', type=str, help='Run only specific step (fetch-attack, fetch-fight, convert, viz, prune)')
    
    args = parser.parse_args()
    
    # Create config
    config = {
        'base_dir': '.',
        'raw_data_dir': 'raw_data',
        'processed_data_dir': 'processed_data',
        'fetch_attack': not args.skip_fetch_attack,
        'fetch_fight': not args.skip_fetch_fight,
        'convert_fight': not args.skip_convert,
        'visualize': not args.skip_viz,
        'prune': not args.skip_prune,
        'log_file': 'pipeline.log'
    }
    
    # Apply --only filter if specified
    if args.only:
        only_step = args.only.lower()
        config['fetch_attack'] = only_step == 'fetch-attack'
        config['fetch_fight'] = only_step == 'fetch-fight'
        config['convert_fight'] = only_step == 'convert'
        config['visualize'] = only_step == 'viz'
        config['prune'] = only_step == 'prune'
    
    # Initialize and run pipeline
    pipeline = CTIPipeline(config)
    success = pipeline.run()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
