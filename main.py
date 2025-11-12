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
try:
    from langgraph.multi_agent_workflow import MultiAgentWorkflow
    USE_MULTI_AGENT = True
except ImportError:
    from langgraph.workflow import CybersecurityWorkflow
    USE_MULTI_AGENT = False

from utils.logger import setup_logger
from dotenv import load_dotenv

load_dotenv()

logger = setup_logger()

def parse_args():
    parser = argparse.ArgumentParser(description="Agentic Cybersecurity Pipeline")
    
    parser.add_argument("-t", "--task", help="Security task description (e.g., 'Scan for open ports')")
    parser.add_argument("-d", "--domains", nargs="+", default=[], help="Target domains (e.g., example.com *.example.org)")
    parser.add_argument("-i", "--ip-ranges", nargs="+", default=[], help="Target IP ranges (e.g., 192.168.1.0/24 10.0.0.1)")
    parser.add_argument("-o", "--output", help="Output file for the report (default: report_YYYYMMDD_HHMMSS.json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--stream", action="store_true", help="Stream task output to console")
    parser.add_argument("--streamlit", action="store_true", help="Launch the Streamlit UI")
    
    return parser.parse_args()

def validate_inputs(args):
    if not args.domains and not args.ip_ranges:
        logger.error("At least one domain or IP range must be specified")
        return False
    
    return True

def run_workflow(security_task, domains, ip_ranges, stream=False):
    try:
        logger.info(f"Starting cybersecurity pipeline with task: {security_task}")
        logger.info(f"Target scope: domains={domains}, ip_ranges={ip_ranges}")
        
        if USE_MULTI_AGENT:
            logger.info("Using Multi-Agent Architecture")
            workflow = MultiAgentWorkflow(parallel_execution=True)
        else:
            logger.info("Using Legacy Workflow")
            workflow = CybersecurityWorkflow()
        
        result = workflow.run(
            objectives=[security_task],
            scope_config={
                "domains": domains,
                "ip_ranges": ip_ranges
            }
        )
        
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
        
        if task.status.name == "COMPLETED" and task.result:
            try:
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
    args = parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.streamlit:
        launch_streamlit()
        return
    
    if not validate_inputs(args):
        print("Invalid inputs. Please check command line arguments.")
        print_example_commands()
        return
    
    result = run_workflow(
        security_task=args.task,
        domains=args.domains,
        ip_ranges=args.ip_ranges,
        stream=args.stream
    )
    
    if result and "report" in result:
        report = result["report"]
        save_report(report, args.output)
        
        print("\nExecution Summary:")
        print("-----------------")
        if "execution_summary" in report:
            print(f"Total Tasks: {report['execution_summary']['total_tasks']}")
            print(f"Completed Tasks: {report['execution_summary']['completed_tasks']}")
            print(f"Failed Tasks: {report['execution_summary']['failed_tasks']}")
            print(f"Skipped Tasks: {report['execution_summary']['skipped_tasks']}")
        
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