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
            "vulnerabilities": "N/A"
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
    """Generate a final report based on task execution (fallback)"""
    if st.session_state.task_manager:
        tasks = st.session_state.task_manager.get_all_tasks()
        total = len(tasks)
        completed = sum(1 for t in tasks if t.status == TaskStatus.COMPLETED)
        failed = sum(1 for t in tasks if t.status == TaskStatus.FAILED)
        pending = sum(1 for t in tasks if t.status == TaskStatus.PENDING)
        running = sum(1 for t in tasks if t.status == TaskStatus.RUNNING)
        
        report_content = f"""# Security Assessment Report

**Total Tasks:** {total}  
**Completed Tasks:** {completed}  
**Failed Tasks:** {failed}  
**Pending Tasks:** {pending}  
**Running Tasks:** {running}
"""
        report = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "content": report_content,
            "execution_summary": {
                "total_tasks": total,
                "completed_tasks": completed,
                "failed_tasks": failed,
                "pending_tasks": pending,
                "running_tasks": running
            }
        }
        if st.session_state.scan_history:
            st.session_state.scan_history[-1]["status"] = "Completed"
            st.session_state.scan_history[-1]["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.scan_history[-1]["vulnerabilities"] = "N/A"
        
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
        # Updated: vulnerabilities metric now shows "N/A" as the new report doesn't include it.
        st.metric(label="Vulnerabilities", value="N/A")
    
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
        
        st.subheader(f"Report Generated: {report.get('timestamp', 'Unknown')}")
        
        # If an execution summary is available, display key metrics
        if 'execution_summary' in report:
            summary = report['execution_summary']
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Tasks", summary.get("total_tasks", "N/A"))
            with col2:
                st.metric("Completed", summary.get("completed_tasks", "N/A"))
            with col3:
                st.metric("Failed", summary.get("failed_tasks", "N/A"))
            with col4:
                st.metric("Pending", summary.get("pending_tasks", "N/A"))
        
        # Display the report content (Markdown)
        st.markdown(report.get("content", "No report content available."))
        
        # Export options
        col1, col2 = st.columns(2)
        with col1:
            report_json = json.dumps(report, indent=2)
            st.download_button(
                label="Download Report as JSON",
                data=report_json,
                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        with col2:
            markdown_report = report.get("content", "No report content available.")
            st.download_button(
                label="Download Report as Markdown",
                data=markdown_report,
                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )
    else:
        st.info("No report available. Complete a scan to generate a report.")

# Footer
st.markdown("---")
st.caption("Agentic Cybersecurity Pipeline built with LangGraph and LangChain")
