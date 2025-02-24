import logging
import time
from functools import wraps
from typing import Callable, Any, List, Dict, Optional, Union

logger = logging.getLogger(__name__)

def retry_operation(
    max_retries: int = 3,
    retry_delay: int = 2,
    backoff_factor: float = 1.5,
    exceptions_to_catch: List[Exception] = (Exception,),
    should_retry_fn: Optional[Callable[[Exception], bool]] = None
):
    """
    Decorator for retrying operations that may fail.
    
    Args:
        max_retries: Maximum number of retry attempts
        retry_delay: Initial delay between retries (in seconds)
        backoff_factor: Multiplier for the retry delay after each attempt
        exceptions_to_catch: List of exceptions that should trigger a retry
        should_retry_fn: Optional function to determine if a particular exception should trigger a retry
        
    Returns:
        The decorated function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            current_delay = retry_delay
            
            while True:
                try:
                    return func(*args, **kwargs)
                except exceptions_to_catch as e:
                    # Check if we've reached max retries
                    if retries >= max_retries:
                        logger.error(f"Max retries ({max_retries}) exceeded for {func.__name__}: {str(e)}")
                        raise
                    
                    # Check if we should retry this specific exception
                    if should_retry_fn and not should_retry_fn(e):
                        logger.info(f"Not retrying {func.__name__} based on should_retry_fn: {str(e)}")
                        raise
                    
                    # Increment retry counter
                    retries += 1
                    
                    # Log the retry
                    logger.warning(
                        f"Retry {retries}/{max_retries} for {func.__name__} after error: {str(e)}"
                    )
                    
                    # Wait before retrying
                    time.sleep(current_delay)
                    
                    # Increase delay for next retry (exponential backoff)
                    current_delay *= backoff_factor
        
        return wrapper
    
    return decorator

class RetryHandler:
    """
    Handler for executing operations with retry logic.
    """
    
    @staticmethod
    def execute_with_retry(
        func: Callable,
        args: tuple = (),
        kwargs: dict = None,
        max_retries: int = 3,
        retry_delay: int = 2,
        backoff_factor: float = 1.5,
        exceptions_to_catch: tuple = (Exception,),
    ) -> Dict[str, Any]:
        """
        Execute a function with retry logic and return a detailed result.
        
        Args:
            func: The function to execute
            args: Positional arguments for the function
            kwargs: Keyword arguments for the function
            max_retries: Maximum number of retry attempts
            retry_delay: Initial delay between retries (in seconds)
            backoff_factor: Multiplier for the retry delay after each attempt
            exceptions_to_catch: Tuple of exceptions that should trigger a retry
            
        Returns:
            dict: A dictionary containing the execution results and metadata
        """
        if kwargs is None:
            kwargs = {}
            
        retries = 0
        current_delay = retry_delay
        start_time = time.time()
        
        while True:
            try:
                # Execute the function
                result = func(*args, **kwargs)
                
                # Calculate execution time
                execution_time = time.time() - start_time
                
                # Return success result
                return {
                    "success": True,
                    "result": result,
                    "retries": retries,
                    "execution_time": execution_time,
                    "error": None
                }
                
            except exceptions_to_catch as e:
                # Check if we've reached max retries
                if retries >= max_retries:
                    # Calculate execution time
                    execution_time = time.time() - start_time
                    
                    # Return failure result
                    return {
                        "success": False,
                        "result": None,
                        "retries": retries,
                        "execution_time": execution_time,
                        "error": str(e),
                        "error_type": type(e).__name__
                    }
                
                # Increment retry counter
                retries += 1
                
                # Log the retry
                logger.warning(
                    f"Retry {retries}/{max_retries} after error: {str(e)}"
                )
                
                # Wait before retrying
                time.sleep(current_delay)
                
                # Increase delay for next retry (exponential backoff)
                current_delay *= backoff_factor