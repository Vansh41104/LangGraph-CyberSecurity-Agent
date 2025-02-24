"""
Main entry point for the Agentic Cybersecurity Pipeline.
"""

import os
import argparse
import logging
import json
from dotenv import load_dotenv
from typing import Dict, List, Any

from utils.logger import setup_logger
from langgraph.workflow import CybersecurityWorkflow

# Load environment variables
load_dotenv()

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Agentic Cybersecurity Pipeline")
    
    # Core arguments
    parser.add_argument("--objective", type=str, required=True,
                        help="High-level security objective (e.g., 'Scan example.com for open ports and directories')")
    
    # Scope configuration
    parser.add_argument("--domains", type=str, nargs="+", default=[],
                        help="List of domains to include in scope")
    parser.add_argument("--wildcard-domains", type=str, nargs="+", default=[],
                        help="List of wildcard domains to include in scope (e.g., '.example.com')")
    parser.add_argument("--ip-ranges", type=str, nargs="+", default=[],
                        help="List of IP ranges to include in scope (CIDR notation)")
    parser.add_argument("--ips", type=str, nargs="+", default=[],
                        help="List of individual IP addresses to include in scope")
    
    # Configuration options
    parser.add_argument("--disable-scope", action="store_true",
                        help="Disable scope enforcement (not recommended for production)")
    parser.add_argument("--config", type=str,
                        help="Path to configuration file (JSON)")
    parser.add_argument("--output", type=str, default="report.md",
                        help="Path to output report file")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level")
    
    # Parse arguments
    return parser.parse_args()

def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from a JSON file."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, "r") as f:
        return json.load(f)

def main():
    """Main entry point."""
    # Parse command line arguments
    args = parse_args()
    
    # Setup logging
    setup_logger(log_level=args.log_level)
    logger = logging.getLogger(__name__)
    
    # Load configuration from file if provided
    config = {}
    if args.config and os.path.exists(args.config):
        logger.info(f"Loading configuration from {args.config}")
        config = load_config(args.config)
    
    # Override configuration with command line arguments
    objectives = [args.objective]
    if "objectives" in config:
        objectives = config.get("objectives", [])
        if args.objective and args.objective not in objectives:
            objectives.append(args.objective)
    
    # Setup scope configuration
    scope_config = config.get("scope", {})
    if args.domains:
        scope_config["domains"] = args.domains
    if args.wildcard_domains:
        scope_config["wildcard_domains"] = args.wildcard_domains
    if args.ip_ranges:
        scope_config["ip_ranges"] = args.ip_ranges
    if args.ips:
        scope_config["ips"] = args.ips
    if args.disable_scope:
        scope_config["enabled"] = False
    
    # Print summary of configuration
    logger.info(f"Objectives: {objectives}")
    logger.info(f"Scope configuration: {scope_config}")
    
    # Initialize and run the workflow
    workflow = CybersecurityWorkflow()
    results = workflow.run(objectives=objectives, scope_config=scope_config)
    
    # Save the report
    with open(args.output, "w") as f:
        f.write(results["report"]["content"])
    
    logger.info(f"Report saved to {args.output}")
    
    # Print summary
    print(f"\nSecurity audit completed!")
    print(f"Total tasks: {results['report']['execution_summary']['total_tasks']}")
    print(f"Completed tasks: {results['report']['execution_summary']['completed_tasks']}")
    print(f"Failed tasks: {results['report']['execution_summary']['failed_tasks']}")
    print(f"Skipped tasks: {results['report']['execution_summary']['skipped_tasks']}")
    print(f"Report saved to: {args.output}")

if __name__ == "__main__":
    main()