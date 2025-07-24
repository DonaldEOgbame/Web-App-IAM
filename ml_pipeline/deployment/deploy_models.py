import os
import shutil
import joblib
import json
import datetime
import numpy as np
from sklearn.metrics import mean_absolute_error
from ml_pipeline.validation.validate_models import validate_models

class ModelDeployer:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.trained_dir = os.path.join(self.base_dir, "../../models/trained")
        self.prod_dir = os.path.join(self.base_dir, "../../models/production")
        self.archive_dir = os.path.join(self.base_dir, "../../models/archive")
        self.reports_dir = os.path.join(self.base_dir, "../../validation_reports")
        
        # Create directories if they don't exist
        os.makedirs(self.trained_dir, exist_ok=True)
        os.makedirs(self.prod_dir, exist_ok=True)
        os.makedirs(self.archive_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Deployment thresholds
        self.acceptance_criteria = {
            "risk_model": {
                "max_mae": 0.05,
                "min_high_risk_recall": 0.95,
                "max_false_positive_rate": 0.02
            },
            "behavior_model": {
                "max_mae": 0.04,
                "min_attack_detection": 0.95
            }
        }

    def get_latest_models(self):
        """Find the latest trained models"""
        models = {}
        for model_type in ["risk", "behavior"]:
            model_files = [f for f in os.listdir(self.trained_dir) 
                          if f.startswith(f"{model_type}_model_") and f.endswith(".pkl")]
            
            if not model_files:
                return None
                
            # Sort by version number (model_v1.2.pkl -> 1.2)
            model_files.sort(key=lambda x: float(x.split("_v")[1].split(".pkl")[0]))
            models[f"{model_type}_model"] = os.path.join(self.trained_dir, model_files[-1])
            
        return models

    def validate_model(self, model_path, model_type):
        """Run validation checks on a model"""
        # Load model and get validation report
        risk_data = os.path.join(self.base_dir, "../data/synthetic_risk_data.parquet")
        behavior_data = os.path.join(self.base_dir, "../data/synthetic_behavior_data.parquet")
        report = validate_models(
            risk_model_path=model_path if "risk" in model_type else None,
            behavior_model_path=model_path if "behavior" in model_type else None,
            risk_data_path=risk_data,
            behavior_data_path=behavior_data,
        )
        
        # Save validation report
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.reports_dir, f"{model_type}_validation_{timestamp}.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
            
        return report, report_path

    def meets_criteria(self, report, model_type):
        """Check if model meets deployment criteria"""
        criteria = self.acceptance_criteria[model_type]
        
        if "risk_model" in model_type:
            metrics = report["risk_model_metrics"]
            scenarios = report["attack_scenarios"]
            
            return (
                metrics["MAE"] <= criteria["max_mae"] and
                metrics["high_risk_recall"] >= criteria["min_high_risk_recall"] and
                all(scenario["false_positive_rate"] <= criteria["max_false_positive_rate"] 
                    for scenario in scenarios.values())
            )
            
        elif "behavior_model" in model_type:
            metrics = report.get("behavior_model_metrics", {})
            return (
                metrics.get("MAE", float("inf")) <= criteria["max_mae"] and
                metrics.get("attack_detection", 0) >= criteria["min_attack_detection"]
            )
            
        return False

    def deploy_model(self, model_path, model_type, report_path):
        """Deploy model to production environment"""
        # Create versioned archive
        version = os.path.basename(model_path).split("_v")[1].split(".pkl")[0]
        archive_path = os.path.join(self.archive_dir, f"{model_type}_v{version}")
        os.makedirs(archive_path, exist_ok=True)
        
        # Copy files to archive
        shutil.copy(model_path, archive_path)
        shutil.copy(report_path, archive_path)
        
        # Copy to production
        prod_path = os.path.join(self.prod_dir, f"{model_type}.pkl")
        shutil.copy(model_path, prod_path)
        
        # Update current version symlink
        symlink_path = os.path.join(self.prod_dir, f"current_{model_type}.pkl")
        if os.path.exists(symlink_path):
            os.remove(symlink_path)
        os.symlink(prod_path, symlink_path)
        
        print(f"✅ Successfully deployed {model_type} version v{version} to production")
        return version

    def deploy_latest_models(self):
        """Deploy the latest validated models to production"""
        models = self.get_latest_models()
        if not models:
            print("⚠️ No trained models found for deployment")
            return False
            
        deployment_results = {}
        
        for model_type, model_path in models.items():
            print(f"\n🔍 Validating {model_type} at {model_path}")
            
            # Validate model
            report, report_path = self.validate_model(model_path, model_type)
            
            # Check if meets criteria
            if self.meets_criteria(report, model_type):
                print(f"✅ Validation passed for {model_type}")
                version = self.deploy_model(model_path, model_type, report_path)
                deployment_results[model_type] = {
                    "version": version,
                    "report_path": report_path
                }
            else:
                print(f"❌ Validation failed for {model_type}")
                print("Reasons:")
                if "risk_model" in model_type:
                    metrics = report["risk_model_metrics"]
                    print(f"  - MAE: {metrics['MAE']:.4f} (max allowed: {self.acceptance_criteria['risk_model']['max_mae']})")
                    print(f"  - High Risk Recall: {metrics['high_risk_recall']:.2%} (min: {self.acceptance_criteria['risk_model']['min_high_risk_recall']:.0%})")
                    for name, scenario in report["attack_scenarios"].items():
                        print(f"  - {name} FP Rate: {scenario['false_positive_rate']:.2%} (max: {self.acceptance_criteria['risk_model']['max_false_positive_rate']:.0%})")
                
                deployment_results[model_type] = {
                    "status": "failed",
                    "report_path": report_path
                }
                
        return deployment_results

    def rollback_model(self, model_type, version):
        """Rollback to a previous model version"""
        archive_path = os.path.join(self.archive_dir, f"{model_type}_v{version}")
        model_path = os.path.join(archive_path, f"{model_type}_v{version}.pkl")
        
        if not os.path.exists(model_path):
            print(f"❌ Version v{version} not found for {model_type}")
            return False
            
        # Deploy the archived version
        prod_path = os.path.join(self.prod_dir, f"{model_type}.pkl")
        shutil.copy(model_path, prod_path)
        
        # Update symlink
        symlink_path = os.path.join(self.prod_dir, f"current_{model_type}.pkl")
        if os.path.exists(symlink_path):
            os.remove(symlink_path)
        os.symlink(prod_path, symlink_path)
        
        print(f"✅ Rolled back {model_type} to version v{version}")
        return True


if __name__ == "__main__":
    deployer = ModelDeployer()
    
    print("""
    ██████╗ ███████╗██████╗ ██╗      ██████╗ ██╗   ██╗
    ██╔══██╗██╔════╝██╔══██╗██║     ██╔═══██╗╚██╗ ██╔╝
    ██║  ██║█████╗  ██████╔╝██║     ██║   ██║ ╚████╔╝ 
    ██║  ██║██╔══╝  ██╔═══╝ ██║     ██║   ██║  ╚██╔╝  
    ██████╔╝███████╗██║     ███████╗╚██████╔╝   ██║   
    ╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝    ╚═╝   
    """)
    
    print("Starting model deployment process...")
    results = deployer.deploy_latest_models()
    
    if results:
        print("\nDeployment Summary:")
        for model, result in results.items():
            if "version" in result:
                print(f"  - {model}: ✅ Deployed version v{result['version']}")
            else:
                print(f"  - {model}: ❌ Deployment failed (see {result['report_path']})")
    else:
        print("⚠️ No models were deployed")

