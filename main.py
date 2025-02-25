#!/usr/bin/env python3
import os
import sys
import argparse
import logging
from datetime import datetime
import json

# Import the components of the system
from utils.task_manager import TaskManager
from utils.scope import ScopeValidator
from langgraph.workflow import CybersecurityWorkflow

# Set up logging
from utils.logger import setup_logger
logger = setup_logger()

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Agentic Cybersecurity Pipeline")
    
    # Define command line arguments
    parser.add_argument("-t", "--task", help="Security task description (e.g., 'Scan for open ports')")
    parser.add_argument("-d", "--domains", nargs="+", default=[], help="Target domains (e.g., example.com *.example.org)")
    parser.add_argument("-i", "--ip-ranges", nargs="+", default=[], help="Target IP ranges (e.g., 192.168.1.0/24 10.0.0.1)")
    parser.add_argument("-o", "--output", help="Output file for the report (default: report_YYYYMMDD_HHMMSS.json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--stream", action="store_true", help="Stream task output to console")
    parser.add_argument("--streamlit", action="store_true", help="Launch the Streamlit UI")
    
    return parser.parse_args()

def validate_inputs(args):
    """Validate command line inputs"""
    if not args.domains and not args.ip_ranges:
        logger.error("At least one domain or IP range must be specified")
        return False
    
    return True

def run_workflow(security_task, domains, ip_ranges, stream=False):
    """Run the cybersecurity workflow with given inputs"""
    try:
        logger.info(f"Starting cybersecurity pipeline with task: {security_task}")
        logger.info(f"Target scope: domains={domains}, ip_ranges={ip_ranges}")
        
        # Initialize the workflow
        workflow = CybersecurityWorkflow()
        result = workflow.run(
            objectives=[security_task],  # Changed from fixed list to the actual security task
            scope_config={
                "domains": domains,
                "ip_ranges": ip_ranges
            }
        )
        
        # Return the result directly from the workflow run
        return result
        
    except Exception as e:
        logger.error(f"Error running workflow: {str(e)}")
        return None

def generate_report(task_manager):
    """Generate a final report based on task execution"""
    tasks = task_manager.get_all_tasks()
    
    # Generate report with all task information
    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_tasks": len(tasks),
            "completed_tasks": sum(1 for t in tasks if t.status.name == "COMPLETED"),
            "failed_tasks": sum(1 for t in tasks if t.status.name == "FAILED"),
            "pending_tasks": sum(1 for t in tasks if t.status.name == "PENDING"),
            "running_tasks": sum(1 for t in tasks if t.status.name == "RUNNING"),
        },
        "vulnerabilities": [],
        "tasks": []
    }
    
    # Add task details
    for task in tasks:
        task_details = {
            "id": task.id,
            "description": task.description,
            "status": task.status.name,
            "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S") if task.created_at else None,
            "started_at": task.started_at.strftime("%Y-%m-%d %H:%M:%S") if task.started_at else None,
            "completed_at": task.completed_at.strftime("%Y-%m-%d %H:%M:%S") if task.completed_at else None,
            "attempts": task.attempts,
            "result": task.result,
            "error": task.error_message
        }
        report["tasks"].append(task_details)
        
        # Check for vulnerabilities in task results
        if task.status.name == "COMPLETED" and task.result:
            # Parse the result for vulnerability information
            try:
                # This is a simplified example - you would need to parse actual tool outputs
                if 'vulnerability' in str(task.result).lower() or 'open port' in str(task.result).lower():
                    report["vulnerabilities"].append({
                        "task_id": task.id,
                        "description": task.description,
                        "details": str(task.result)
                    })
            except Exception:
                pass
    
    return report

def save_report(report, output_file=None):
    """Save the report to a file"""
    if not output_file:
        output_file = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    try:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Report saved to {output_file}")
        return True
    except Exception as e:
        logger.error(f"Error saving report: {str(e)}")
        return False

def launch_streamlit():
    """Launch the Streamlit UI"""
    try:
        import subprocess
        streamlit_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "streamlit_app", "app.py")
        logger.info(f"Launching Streamlit UI from {streamlit_path}")
        subprocess.run(["streamlit", "run", streamlit_path])
    except Exception as e:
        logger.error(f"Error launching Streamlit UI: {str(e)}")
        print(f"Error: {str(e)}")
        print("To launch Streamlit manually, run: streamlit run streamlit_app/app.py")

def print_example_commands():
    """Print example commands for reference"""
    print("\nExample commands:")
    print("-----------------")
    print("1. Scan a single domain for open ports:")
    print("   python main.py -t \"Scan for open ports\" -d example.com")
    print()
    print("2. Scan multiple domains with directory discovery:")
    print("   python main.py -t \"Scan for open ports and discover directories\" -d example.com test.org -v")
    print()
    print("3. Scan an IP range for vulnerabilities:")
    print("   python main.py -t \"Find vulnerabilities in the internal network\" -i 192.168.1.0/24 -o network_scan.json")
    print()
    print("4. Launch the Streamlit UI:")
    print("   python main.py --streamlit")
    print()

def main():
    """Main entry point for the cybersecurity pipeline"""
    # Parse command line arguments
    args = parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Launch Streamlit UI if requested
    if args.streamlit:
        launch_streamlit()
        return
    
    # Validate inputs
    if not validate_inputs(args):
        print("Invalid inputs. Please check command line arguments.")
        print_example_commands()
        return
    
    # Run the workflow
    result = run_workflow(
        security_task=args.task,
        domains=args.domains,
        ip_ranges=args.ip_ranges,
        stream=args.stream
    )
    
    # Process the workflow result
    if result and "report" in result:
        report = result["report"]
        save_report(report, args.output)
        
        # Print summary to console
        print("\nExecution Summary:")
        print("-----------------")
        if "execution_summary" in report:
            print(f"Total Tasks: {report['execution_summary']['total_tasks']}")
            print(f"Completed Tasks: {report['execution_summary']['completed_tasks']}")
            print(f"Failed Tasks: {report['execution_summary']['failed_tasks']}")
            print(f"Skipped Tasks: {report['execution_summary']['skipped_tasks']}")
        
        # Display report content
        print("\nReport Content:")
        print("--------------")
        print(report.get("content", "No content available"))
    else:
        print("Workflow execution failed. Check logs for details.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExecution interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        logger.exception("Unexpected error occurred")
        sys.exit(1)