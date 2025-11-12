import logging
import os
from datetime import datetime
import json
from pathlib import Path

def setup_logger(log_dir="logs", log_level=logging.INFO):

    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"scan_{timestamp}.log")
    
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    file_handler = logging.FileHandler(log_file)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(log_level)
    
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(log_level)
    
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    logger = logging.getLogger("cybersec_pipeline")
    logger.info(f"Logging initialized, saving to: {log_file}")
    
    return logger

class JsonFileHandler:
    
    @staticmethod
    def save_json(data, file_path):
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logging.error(f"Error saving JSON to {file_path}: {str(e)}")
            return False
    
    @staticmethod
    def load_json(file_path):
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading JSON from {file_path}: {str(e)}")
            return None

def log_execution(func):
    def wrapper(*args, **kwargs):
        func_name = func.__name__
        logger = logging.getLogger(__name__)
        logger.info(f"Starting execution of {func_name}")
        
        try:
            result = func(*args, **kwargs)
            logger.info(f"Successfully completed execution of {func_name}")
            return result
        except Exception as e:
            logger.error(f"Error in {func_name}: {str(e)}", exc_info=True)
            raise
    
    return wrapper

class ScanLogger:
    
    def __init__(self, scan_id=None):
        self.logger = logging.getLogger("cybersec_pipeline.scan")
        self.scan_id = scan_id or datetime.now().strftime("%Y%m%d%H%M%S")
        self.report_dir = os.path.join("reports", self.scan_id)
        Path(self.report_dir).mkdir(parents=True, exist_ok=True)
    
    def log_scan_start(self, tool, target, params=None):
        params_str = json.dumps(params) if params else ""
        self.logger.info(f"SCAN_START: {tool} on {target} {params_str}")
        
    def log_scan_complete(self, tool, target, status, result_summary=None):
        self.logger.info(f"SCAN_COMPLETE: {tool} on {target} - Status: {status}")
        if result_summary:
            self.logger.info(f"RESULT: {result_summary}")
            
    def log_scan_error(self, tool, target, error):
        self.logger.error(f"SCAN_ERROR: {tool} on {target} - {error}")
        
    def save_scan_result(self, tool, target, result, format="json"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{tool}_{target.replace('.', '_')}_{timestamp}.{format}"
        file_path = os.path.join(self.report_dir, filename)
        
        try:
            if format == "json":
                with open(file_path, 'w') as f:
                    json.dump(result, f, indent=2)
            else:
                with open(file_path, 'w') as f:
                    f.write(str(result))
                    
            self.logger.info(f"Saved {tool} scan result to {file_path}")
            return file_path
        except Exception as e:
            self.logger.error(f"Error saving scan result: {str(e)}")
            return None
            
    def generate_report(self, scan_details, findings, recommendations=None):
        report = {
            "scan_id": self.scan_id,
            "timestamp": datetime.now().isoformat(),
            "scan_details": scan_details,
            "findings": findings,
            "recommendations": recommendations or []
        }
        
        report_path = os.path.join(self.report_dir, "final_report.json")
        JsonFileHandler.save_json(report, report_path)
        self.logger.info(f"Generated final report at {report_path}")
        
        return report_path