from typing import Dict, Any, List
import logging

from langchain.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage, HumanMessage

from agents.base_agent import BaseAgent
from utils.task_manager import TaskStatus

logger = logging.getLogger(__name__)


class ReportGenerationAgent(BaseAgent):
    
    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("Generating final security report")
        
        all_tasks = self.task_manager.get_all_tasks()
        execution_summary = {
            "total_tasks": len(all_tasks),
            "completed_tasks": len([t for t in all_tasks if t.status == TaskStatus.COMPLETED]),
            "failed_tasks": len([t for t in all_tasks if t.status == TaskStatus.FAILED]),
            "skipped_tasks": len([t for t in all_tasks if t.status == TaskStatus.SKIPPED])
        }
        
        scope_str = self.get_scope_string()
        
        state["report"] = {
            "content": "## Preliminary Security Report\n\nGenerating detailed analysis...",
            "timestamp": self.task_manager.get_current_time().isoformat(),
            "execution_summary": execution_summary
        }
        
        try:
            findings_summary = self._summarize_key_findings(state)
            
            objectives = state.get("objectives", [])
            executive_summary = self._generate_executive_summary(objectives, findings_summary, scope_str)
            
            technical_details = self._generate_technical_details(state, findings_summary)
            
            report_content = f"""# Security Assessment Report

## Executive Summary
{executive_summary}

## Methodology
The security assessment was conducted using automated scanning tools, including Nmap, Gobuster, FFUF, and SQLMap. The scope included {scope_str}.

## Key Findings
{findings_summary}

## Recommendations
{technical_details.get('recommendations', 'No specific recommendations were identified.')}

## Technical Details
{technical_details.get('details', 'No detailed technical information available.')}

## Execution Summary
- Total Tasks: {execution_summary['total_tasks']}
- Completed: {execution_summary['completed_tasks']}
- Failed: {execution_summary['failed_tasks']}
- Skipped: {execution_summary['skipped_tasks']}
"""
            
            state["report"] = {
                "content": report_content,
                "timestamp": self.task_manager.get_current_time().isoformat(),
                "execution_summary": execution_summary
            }
            
            logger.info("Report generated successfully")
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            state.setdefault("error_log", []).append(f"Error generating report: {str(e)}")
            
            fallback_report = self._generate_fallback_report(state, scope_str, execution_summary)
            state["report"] = fallback_report
            logger.info("Using fallback report due to error")
        
        return state
    
    def _summarize_key_findings(self, state: Dict[str, Any]) -> str:
        findings = []
        results = state.get("results", {})
        
        for task_id, result in results.items():
            task = self.task_manager.get_task(task_id)
            if not task or task.status != TaskStatus.COMPLETED:
                continue
            
            if isinstance(result, dict) and 'analysis' in result:
                analysis = result['analysis']
                if isinstance(analysis, dict) and 'high_level' in analysis:
                    findings.append(f"### {task.name}\n{analysis['high_level']}")
                elif isinstance(analysis, str):
                    findings.append(f"### {task.name}\n{analysis}")
            
            if isinstance(result, dict) and 'hosts' in result:
                for host in result['hosts'][:3]:
                    if 'ports' in host and host['ports']:
                        open_ports = [p for p in host['ports'] if p.get('state', {}).get('state') == 'open']
                        if open_ports:
                            findings.append(f"### Host {host.get('address', 'Unknown')}\n- Found {len(open_ports)} open ports")
        
        if not findings:
            return "No significant findings were identified."
        
        return "\n\n".join(findings)
    
    def _generate_executive_summary(self, objectives: List[str], 
                                     findings_summary: str, scope_str: str) -> str:
        try:
            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content="You are a cybersecurity report writer. Generate a concise executive summary."),
                HumanMessage(content=f"""
Write a brief executive summary (max 250 words) for a security assessment report.

Scope: {scope_str}
Objectives: {' '.join(objectives)}
Key Findings: {findings_summary}

Focus on high-level business impact and overall security posture.
                """)
            ])
            
            chain = prompt | self.llm
            summary = chain.invoke({})
            summary_text = summary.content if hasattr(summary, "content") else str(summary)
            return summary_text.strip()
            
        except Exception as e:
            logger.warning(f"Error generating executive summary: {str(e)}")
            return "This security assessment evaluated the specified targets. Several findings were identified that should be addressed according to their severity."
    
    def _generate_technical_details(self, state: Dict[str, Any], 
                                     findings_summary: str) -> Dict[str, str]:
        try:
            technical_info = []
            results = state.get("results", {})
            
            for task_id, result in results.items():
                task = self.task_manager.get_task(task_id)
                if not task or task.status != TaskStatus.COMPLETED:
                    continue
                
                task_info = f"### {task.name}\n\n"
                task_info += f"**Target:** {task.params.get('target', 'Unknown')}\n"
                task_info += f"**Tool:** {task.tool}\n\n"
                
                if isinstance(result, dict):
                    # Add key result information
                    if "hosts" in result:
                        task_info += f"**Hosts Scanned:** {len(result['hosts'])}\n"
                    if "error" in result:
                        task_info += f"**Error:** {result['error']}\n"
                    
                technical_info.append(task_info)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(findings_summary)
            
            return {
                "details": "\n\n".join(technical_info) if technical_info else "No technical details available.",
                "recommendations": recommendations
            }
            
        except Exception as e:
            logger.warning(f"Error generating technical details: {str(e)}")
            return {
                "details": "Technical details could not be generated due to an error.",
                "recommendations": "Recommendations could not be generated due to an error."
            }
    
    def _generate_recommendations(self, findings_summary: str) -> str:
        try:
            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content="You are a cybersecurity consultant providing actionable recommendations."),
                HumanMessage(content=f"""
Based on these security findings, provide 3-5 specific, actionable recommendations:

{findings_summary}

Format each recommendation as a bullet point with a brief explanation of its importance.
                """)
            ])
            
            chain = prompt | self.llm
            recommendations = chain.invoke({})
            recommendations_text = recommendations.content if hasattr(recommendations, "content") else str(recommendations)
            return recommendations_text.strip()
            
        except Exception as e:
            logger.warning(f"Error generating recommendations: {str(e)}")
            return "- Review and address all identified vulnerabilities\n- Implement security best practices\n- Conduct regular security assessments"
    
    def _generate_fallback_report(self, state: Dict[str, Any], scope_str: str,
                                   execution_summary: Dict[str, int]) -> Dict[str, Any]:
        findings = []
        results = state.get("results", {})
        
        for task_id, result in results.items():
            task = self.task_manager.get_task(task_id)
            if not task:
                continue
            
            task_result = f"### {task.name} ({task.status.value})\n"
            task_result += f"Target: {task.params.get('target', 'Unknown')}\n"
            
            if task.status == TaskStatus.COMPLETED and isinstance(result, dict):
                if 'hosts' in result:
                    task_result += f"Hosts found: {len(result['hosts'])}\n"
            
            findings.append(task_result)
        
        findings_text = "\n\n".join(findings) if findings else "No findings available."
        
        content = f"""# Security Assessment Report

## Scope
{scope_str}

## Summary
This report contains basic findings from the security assessment. A detailed analysis could not be generated.

## Findings
{findings_text}

## Execution Summary
- Total Tasks: {execution_summary['total_tasks']}
- Completed: {execution_summary['completed_tasks']}
- Failed: {execution_summary['failed_tasks']}
- Skipped: {execution_summary['skipped_tasks']}
"""
        
        return {
            "content": content,
            "timestamp": self.task_manager.get_current_time().isoformat(),
            "execution_summary": execution_summary
        }
