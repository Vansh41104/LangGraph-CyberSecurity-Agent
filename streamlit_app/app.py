import streamlit as st
import time
import pandas as pd
import json
import sys
import os
from datetime import datetime

# Add parent directory to path to import from other modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.task_manager import Task, TaskManager, TaskStatus
from utils.scope import ScopeValidator
from langgraph.workflow import CybersecurityWorkflow

# Page configuration
st.set_page_config(
    page_title="Cybersecurity Pipeline",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state variables if they don't exist
if 'task_manager' not in st.session_state:
    st.session_state.task_manager = None
if 'workflow' not in st.session_state:
    st.session_state.workflow = None
if 'scope_validator' not in st.session_state:
    st.session_state.scope_validator = None
if 'logs' not in st.session_state:
    st.session_state.logs = []
if 'is_running' not in st.session_state:
    st.session_state.is_running = False
if 'final_report' not in st.session_state:
    st.session_state.final_report = None
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

# Functions to manage workflow execution
def start_workflow(security_task, domains, ip_ranges):
    """Start the cybersecurity workflow with defined scope"""
    try:
        # Initialize scope validator and add domains/IP ranges
        st.session_state.scope_validator = ScopeValidator()
        for domain in domains:
            st.session_state.scope_validator.add_domain(domain)
        for ip in ip_ranges:
            st.session_state.scope_validator.add_ip_range(ip)
        
        # Initialize task manager
        st.session_state.task_manager = TaskManager()
        
        # Initialize workflow (which will use the internal task manager and scope validator)
        st.session_state.workflow = CybersecurityWorkflow()
        
        # Reset logs and state
        st.session_state.logs = []
        st.session_state.final_report = None
        st.session_state.is_running = True
        
        # Log the starting of the workflow
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": "INFO",
            "message": f"Starting workflow with task: {security_task}",
            "details": f"Scope: Domains={domains}, IP Ranges={ip_ranges}"
        }
        st.session_state.logs.append(log_entry)
        
        # Run the workflow (the run method returns a dict with keys "report", "results", etc.)
        result = st.session_state.workflow.run(
            [security_task],
            {
                "domains": domains,
                "ip_ranges": ip_ranges,
                "wildcard_domains": []  # Adjust if needed
            }
        )
        
        # Save final report from the workflow run
        st.session_state.final_report = result.get("report", {})
        
        # Add entry to scan history and mark it as completed
        history_entry = {
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "task": security_task,
            "domains": domains,
            "ip_ranges": ip_ranges,
            "status": "Completed",
            "end_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": len(st.session_state.final_report.get("vulnerabilities", []))
        }
        st.session_state.scan_history.append(history_entry)
        
        st.session_state.is_running = False
        
    except Exception as e:
        st.error(f"Error starting workflow: {str(e)}")
        st.session_state.is_running = False

def stop_workflow():
    """Stop the current workflow execution"""
    if st.session_state.is_running:
        # Update the last scan history entry
        if st.session_state.scan_history:
            st.session_state.scan_history[-1]["status"] = "Stopped"
            st.session_state.scan_history[-1]["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Log the stopping of the workflow
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": "WARNING",
            "message": "Workflow execution stopped by user",
            "details": ""
        }
        st.session_state.logs.append(log_entry)
        
        # Generate partial report
        generate_report()
        
        # Reset running state
        st.session_state.is_running = False

def generate_report():
    """Generate a final report based on task execution"""
    if st.session_state.task_manager:
        tasks = st.session_state.task_manager.get_all_tasks()
        
        # Generate report with all task information
        report = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_tasks": len(tasks),
                "completed_tasks": sum(1 for t in tasks if t.status == TaskStatus.COMPLETED),
                "failed_tasks": sum(1 for t in tasks if t.status == TaskStatus.FAILED),
                "pending_tasks": sum(1 for t in tasks if t.status == TaskStatus.PENDING),
                "running_tasks": sum(1 for t in tasks if t.status == TaskStatus.RUNNING),
            },
            "vulnerabilities": [],
            "tasks": []
        }
        
        # Add task details
        for task in tasks:
            error_str = ""
            if hasattr(task, "errors") and task.errors:
                error_str = ", ".join(task.errors)
            task_details = {
                "id": task.id,
                "description": task.description,
                "status": task.status.name,
                "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S") if task.created_at else None,
                "started_at": task.started_at.strftime("%Y-%m-%d %H:%M:%S") if task.started_at else None,
                "completed_at": task.completed_at.strftime("%Y-%m-%d %H:%M:%S") if task.completed_at else None,
                "attempts": getattr(task, "retry_count", 0),
                "result": task.result,
                "error": error_str
            }
            report["tasks"].append(task_details)
            
            # Check for vulnerabilities in task results (simple heuristic)
            if task.status == TaskStatus.COMPLETED and task.result:
                try:
                    result_str = str(task.result).lower()
                    if "vulnerability" in result_str or "open port" in result_str:
                        report["vulnerabilities"].append({
                            "task_id": task.id,
                            "description": task.description,
                            "details": str(task.result)
                        })
                except Exception:
                    pass
        
        # Update the last scan history entry
        if st.session_state.scan_history:
            st.session_state.scan_history[-1]["status"] = "Completed"
            st.session_state.scan_history[-1]["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.scan_history[-1]["vulnerabilities"] = len(report["vulnerabilities"])
        
        st.session_state.final_report = report
        return report
    return None

def add_log(level, message, details=""):
    """Add a log entry to the logs"""
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "level": level,
        "message": message,
        "details": details
    }
    st.session_state.logs.append(log_entry)

# Sidebar for configuration and controls
with st.sidebar:
    st.title("🔐 Cybersecurity Pipeline")
    
    # Configuration Section
    st.header("Scan Configuration")
    
    # Target Scope Definition
    st.subheader("Target Scope")
    domains_input = st.text_area("Domains (one per line)", 
                                 help="Enter target domains, e.g., example.com, *.example.org")
    ip_ranges_input = st.text_area("IP Ranges (one per line)", 
                                  help="Enter target IP ranges, e.g., 192.168.1.0/24")
    
    # Security Task Definition
    st.subheader("Security Task")
    security_task = st.text_area("Describe the security task", 
                                 placeholder="e.g., Scan example.com for open ports and discover directories")
    
    # Control Buttons
    st.subheader("Controls")
    col1, col2 = st.columns(2)
    
    with col1:
        if not st.session_state.is_running:
            if st.button("Start Scan", key="start_btn", use_container_width=True):
                # Parse the domains and IP ranges
                domains = [d.strip() for d in domains_input.split('\n') if d.strip()]
                ip_ranges = [ip.strip() for ip in ip_ranges_input.split('\n') if ip.strip()]
                
                # Validate inputs
                if not domains and not ip_ranges:
                    st.error("Please define at least one domain or IP range.")
                elif not security_task:
                    st.error("Please describe the security task.")
                else:
                    start_workflow(security_task, domains, ip_ranges)
    
    with col2:
        if st.session_state.is_running:
            if st.button("Stop Scan", key="stop_btn", use_container_width=True):
                stop_workflow()
    
    # History Section
    if st.session_state.scan_history:
        st.subheader("Scan History")
        for i, entry in enumerate(st.session_state.scan_history[-5:]):  # Show only the last 5 entries
            with st.expander(f"{entry['start_time']} - {entry['task'][:20]}..."):
                st.write(f"**Status:** {entry['status']}")
                st.write(f"**Start Time:** {entry['start_time']}")
                if 'end_time' in entry:
                    st.write(f"**End Time:** {entry['end_time']}")
                if 'vulnerabilities' in entry:
                    st.write(f"**Vulnerabilities Found:** {entry['vulnerabilities']}")
                st.write("**Domains:**")
                for domain in entry['domains']:
                    st.write(f"- {domain}")
                st.write("**IP Ranges:**")
                for ip_range in entry['ip_ranges']:
                    st.write(f"- {ip_range}")

# Main content area with tabs
tab1, tab2, tab3, tab4 = st.tabs(["Dashboard", "Task List", "Logs", "Report"])

# Dashboard Tab
with tab1:
    st.header("Cybersecurity Pipeline Dashboard")
    
    # Status indicators
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(label="Status", 
                  value="Running" if st.session_state.is_running else "Idle")
    
    with col2:
        if st.session_state.task_manager:
            tasks = st.session_state.task_manager.get_all_tasks()
            total_tasks = len(tasks)
            completed_tasks = sum(1 for t in tasks if t.status == TaskStatus.COMPLETED)
            st.metric(label="Task Progress", 
                      value=f"{completed_tasks}/{total_tasks}")
        else:
            st.metric(label="Task Progress", value="0/0")
    
    with col3:
        if st.session_state.final_report:
            st.metric(label="Vulnerabilities", 
                      value=len(st.session_state.final_report.get("vulnerabilities", [])))
        else:
            st.metric(label="Vulnerabilities", value="0")
    
    # Scope information
    st.subheader("Current Scope")
    if st.session_state.scope_validator:
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Domains:**")
            for domain in st.session_state.scope_validator.domains:
                st.write(f"- {domain}")
        
        with col2:
            st.write("**IP Ranges:**")
            for ip_range in st.session_state.scope_validator.ip_ranges:
                st.write(f"- {ip_range}")
    else:
        st.info("No scope defined. Configure and start a scan to define the scope.")
    
    # Live task monitoring (if available)
    if st.session_state.task_manager:
        st.subheader("Live Task Monitoring")
        
        tasks = st.session_state.task_manager.get_all_tasks()
        
        # Show current running task
        running_tasks = [t for t in tasks if t.status == TaskStatus.RUNNING]
        if running_tasks:
            with st.expander("Currently Running", expanded=True):
                for task in running_tasks:
                    st.info(f"**Task:** {task.description}")
                    st.write(f"**Started at:** {task.started_at.strftime('%Y-%m-%d %H:%M:%S') if task.started_at else 'N/A'}")
                    st.write(f"**Attempts:** {getattr(task, 'retry_count', 0)}")
        
        # Visualize task completion using a progress chart
        statuses = [t.status.name for t in tasks]
        status_counts = {
            "PENDING": statuses.count("PENDING"),
            "RUNNING": statuses.count("RUNNING"),
            "COMPLETED": statuses.count("COMPLETED"),
            "FAILED": statuses.count("FAILED")
        }
        
        df = pd.DataFrame({
            "Status": list(status_counts.keys()),
            "Count": list(status_counts.values())
        })
        
        st.bar_chart(df.set_index("Status"))

# Task List Tab
with tab2:
    st.header("Task List")
    
    if st.session_state.task_manager:
        tasks = st.session_state.task_manager.get_all_tasks()
        
        # Group tasks by status
        completed_tasks = [t for t in tasks if t.status == TaskStatus.COMPLETED]
        running_tasks = [t for t in tasks if t.status == TaskStatus.RUNNING]
        pending_tasks = [t for t in tasks if t.status == TaskStatus.PENDING]
        failed_tasks = [t for t in tasks if t.status == TaskStatus.FAILED]
        
        # Display tasks by group
        if running_tasks:
            with st.expander("Running Tasks", expanded=True):
                for task in running_tasks:
                    st.info(f"**Task {task.id}:** {task.description}")
                    st.write(f"**Started at:** {task.started_at.strftime('%Y-%m-%d %H:%M:%S') if task.started_at else 'N/A'}")
                    st.write(f"**Attempts:** {getattr(task, 'retry_count', 0)}")
        
        if pending_tasks:
            with st.expander("Pending Tasks", expanded=True):
                for task in pending_tasks:
                    st.warning(f"**Task {task.id}:** {task.description}")
                    st.write(f"**Created at:** {task.created_at.strftime('%Y-%m-%d %H:%M:%S') if task.created_at else 'N/A'}")
        
        if completed_tasks:
            with st.expander("Completed Tasks", expanded=False):
                for task in completed_tasks:
                    st.success(f"**Task {task.id}:** {task.description}")
                    st.write(f"**Completed at:** {task.completed_at.strftime('%Y-%m-%d %H:%M:%S') if task.completed_at else 'N/A'}")
                    if task.result:
                        with st.expander("Result"):
                            st.code(str(task.result))
        
        if failed_tasks:
            with st.expander("Failed Tasks", expanded=False):
                for task in failed_tasks:
                    st.error(f"**Task {task.id}:** {task.description}")
                    st.write(f"**Attempts:** {getattr(task, 'retry_count', 0)}")
                    error_msg = ", ".join(task.errors) if hasattr(task, "errors") and task.errors else ""
                    st.write(f"**Error:** {error_msg}")
    else:
        st.info("No tasks available. Start a scan to generate tasks.")

# Logs Tab
with tab3:
    st.header("Execution Logs")
    
    # Filter logs by level
    log_level_filter = st.multiselect("Filter by log level", 
                                      options=["INFO", "WARNING", "ERROR", "DEBUG"],
                                      default=["INFO", "WARNING", "ERROR"])
    
    # Display logs with filter
    if st.session_state.logs:
        filtered_logs = [log for log in reversed(st.session_state.logs) 
                         if log["level"] in log_level_filter]
        
        for log in filtered_logs:
            if log["level"] == "ERROR":
                st.error(f"**{log['timestamp']}** - {log['message']}")
            elif log["level"] == "WARNING":
                st.warning(f"**{log['timestamp']}** - {log['message']}")
            elif log["level"] == "INFO":
                st.info(f"**{log['timestamp']}** - {log['message']}")
            else:  # DEBUG
                st.text(f"**{log['timestamp']}** - {log['message']}")
            
            if log["details"]:
                with st.expander("Details"):
                    st.code(log["details"])
    else:
        st.info("No logs available. Start a scan to generate logs.")
    
    if st.button("Refresh Logs"):
        st.experimental_rerun()

# Report Tab
with tab4:
    st.header("Security Audit Report")
    
    if st.session_state.final_report:
        report = st.session_state.final_report
        
        # Report header
        st.subheader(f"Report Generated: {report['timestamp']}")
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Tasks", report["summary"]["total_tasks"])
        with col2:
            st.metric("Completed", report["summary"]["completed_tasks"])
        with col3:
            st.metric("Failed", report["summary"]["failed_tasks"])
        with col4:
            st.metric("Vulnerabilities", len(report["vulnerabilities"]))
        
        # Vulnerabilities section
        if report["vulnerabilities"]:
            st.subheader("🚨 Vulnerabilities Found")
            for i, vuln in enumerate(report["vulnerabilities"]):
                with st.expander(f"Vulnerability #{i+1}: {vuln['description'][:50]}..."):
                    st.write(f"**Task ID:** {vuln['task_id']}")
                    st.write(f"**Description:** {vuln['description']}")
                    st.code(vuln['details'])
        else:
            st.success("No vulnerabilities detected in this scan.")
        
        # Task details
        st.subheader("Task Execution Details")
        task_df = pd.DataFrame([
            {
                "ID": t["id"],
                "Description": (t["description"][:50] + "...") if len(t["description"]) > 50 else t["description"],
                "Status": t["status"],
                "Attempts": t["attempts"],
                "Completed At": t["completed_at"] if t["completed_at"] else "N/A"
            }
            for t in report["tasks"]
        ])
        
        st.dataframe(task_df, use_container_width=True)
        
        # Export options
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Export as JSON"):
                report_json = json.dumps(report, indent=2)
                st.download_button(
                    label="Download JSON",
                    data=report_json,
                    file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        
        with col2:
            if st.button("Export as Markdown"):
                markdown_report = f"""# Security Audit Report
Generated: {report['timestamp']}

## Summary
- Total Tasks: {report['summary']['total_tasks']}
- Completed Tasks: {report['summary']['completed_tasks']}
- Failed Tasks: {report['summary']['failed_tasks']}
- Pending Tasks: {report['summary']['pending_tasks']}
- Running Tasks: {report['summary']['running_tasks']}

## Vulnerabilities Found: {len(report['vulnerabilities'])}
"""
                if report["vulnerabilities"]:
                    for i, vuln in enumerate(report["vulnerabilities"]):
                        markdown_report += f"""
### Vulnerability #{i+1}: {vuln['description']}
- Task ID: {vuln['task_id']}
- Details:
{vuln['details']}
"""
                else:
                    markdown_report += "\nNo vulnerabilities detected in this scan.\n"
                
                markdown_report += "\n## Task Execution Details\n"
                for task in report["tasks"]:
                    markdown_report += f"""
### Task {task['id']}: {task['description']}
- Status: {task['status']}
- Created: {task['created_at']}
- Completed: {task['completed_at'] if task['completed_at'] else 'N/A'}
- Attempts: {task['attempts']}
"""
                    if task['result']:
                        markdown_report += f"""
- Result:
{task['result']}
"""
                    if task['error']:
                        markdown_report += f"""
- Error:
{task['error']}
"""
                st.download_button(
                    label="Download Markdown",
                    data=markdown_report,
                    file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                    mime="text/markdown"
                )
    else:
        st.info("No report available. Complete a scan to generate a report.")

# Footer
st.markdown("---")
st.caption("Agentic Cybersecurity Pipeline built with LangGraph and LangChain")
