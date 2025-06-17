import yaml
import base64
import os
import re
from typing import Dict, List, Optional
from openai import OpenAI
from anthropic import Anthropic
from constants import OPENAI_API_KEY
from functools import wraps

def retry_on_yaml_error(max_retries: int = 3):
    """
    Decorator that retries a function if it raises a YAML parsing error.
    
    Args:
        max_retries (int): Maximum number of retries before giving up
        
    Returns:
        Decorated function that implements retry logic
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except yaml.YAMLError as e:
                    retries += 1
                    if retries == max_retries:
                        print(f"Failed after {max_retries} retries: {e}")
                        return []
                    print(f"YAML parsing failed, attempt {retries} of {max_retries}")
            return []
        return wrapper
    return decorator

class Planner:
    """
    A class that uses OpenAI's API to generate security testing plans.
    """
    
    def __init__(self, num_plans_target: int = 10, knowledge_summary: str = None):
        """Initialize the Planner with OpenAI client and system prompt.
        
        Args:
            num_plans_target (int): Target number of security testing plans to generate (default: 10, use -1 for unlimited)
            knowledge_summary (str): Pre-fetched security knowledge summary to include in planning
        """
        self.client = OpenAI(api_key=OPENAI_API_KEY)
        self.num_plans_target = num_plans_target
        
        # Use provided knowledge summary or fallback message
        if knowledge_summary:
            knowledge_content = knowledge_summary
        else:
            knowledge_content = """
        ## Current Security Knowledge Base
        You have access to the latest security research and proven techniques:
        - **DevSec Blog Web API Security Champion Series**: Focus on authorization bypasses, authentication flaws, object-level access control, and resource consumption attacks
        - **PortSwigger Web Security Academy Labs**: SQL injection, XSS, CSRF, authentication bypasses, access control flaws, SSRF, XXE, and business logic vulnerabilities
        - **Expert Penetration Testing Techniques**: Advanced payload crafting, polyglot attacks, chained exploits, and novel bypass methods

        When planning security tests, prioritize techniques that have proven successful in real-world penetration tests and CTF challenges. Think like a security expert who understands both classic attack vectors and modern exploitation techniques.
        """
        
        # Determine plan count instruction
        if self.num_plans_target <= 0:
            plan_instruction = "as many comprehensive security test plans as possible (aim for 15-25+ distinct plans)"
        else:
            plan_instruction = f"{self.num_plans_target} distinct security test plans"
        
        self.system_prompt = f"""
        You are an expert bug bounty hunter with years of experience finding critical vulnerabilities in web applications. Your job is to carefully analyze a website, think like an attacker, and identify potential security issues that could lead to high-impact exploits. You will be provided details about our internal company that we're testing, so think creatively about how the application could be abused.

        Based on the provided page content, generate {plan_instruction}. Each plan should focus on a specific vulnerability type or attack vector.

        Consider testing for:
        - SQL Injection (authentication bypass, data extraction, blind techniques)
        - Cross-Site Scripting (reflected, stored, DOM-based)
        - Authentication and authorization flaws
        - Directory traversal and path manipulation
        - Command injection and code execution
        - Business logic vulnerabilities
        - CSRF and state management issues
        - Information disclosure
        - Input validation bypasses
        - Session management weaknesses

        For each plan, provide:
        1. title: A clear, specific test plan name
        2. description: Detailed methodology explaining what to test and how

        Return your response as a YAML list of plans:
        ```yaml
        - title: "Plan Title 1"
          description: "Detailed description of what to test and methodology..."
        - title: "Plan Title 2"  
          description: "Detailed description of what to test and methodology..."
        ```

        Focus on plans that are most likely to yield high-impact vulnerabilities given the page content and functionality observed."""

    def plan(self, page_data: str) -> List[Dict]:
        """
        Generate a security testing plan based on provided information.
        
        Args:
            page_data (str): Input message containing page information
            
        Returns:
            List[Dict]: List of testing plan items, each containing title and description
        """
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": page_data}
        ]
        
        response = self.client.chat.completions.create(
            model="o3-mini",
            messages=messages,
        )
        
        # Parse YAML response into list of dicts
        yaml_str = response.choices[0].message.content
        
        # Strip markdown code blocks if present
        if yaml_str.strip().startswith('```'):
            # Remove opening ```yaml or ``` 
            lines = yaml_str.strip().split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]
            # Remove closing ```
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            yaml_str = '\n'.join(lines)
        
        items = yaml.safe_load(yaml_str)
        if not isinstance(items, list):
            items = [items]
        
        # Limit to target number of plans only if a limit is set
        if self.num_plans_target > 0:
            return items[:self.num_plans_target]
        else:
            return items  # Return all plans when unlimited

    @retry_on_yaml_error()
    def plan_batch(self, context_data: str, batch_size: int) -> List[Dict]:
        """
        Generate a batch of security testing plans with iterative context.
        
        Args:
            context_data (str): Input message containing page information and execution insights
            batch_size (int): Number of plans to generate in this batch
            
        Returns:
            List[Dict]: List of testing plan items, each containing title and description
        """
        # Create a modified system prompt for batch planning
        batch_prompt = self.system_prompt.replace(
            "as many comprehensive security test plans as possible (aim for 15-25+ distinct plans)",
            f"exactly {batch_size} distinct security test plans"
        ).replace(
            f"{self.num_plans_target} distinct security test plans",
            f"exactly {batch_size} distinct security test plans"
        )
        
        # Add iterative planning instruction
        batch_prompt += f"""

        IMPORTANT: Generate exactly {batch_size} new and unique security test plans. If execution insights are provided, use them to:
        1. Avoid repeating failed approaches unless you have a new angle
        2. Build upon successful techniques with variations
        3. Focus on areas that haven't been thoroughly tested yet
        4. Consider chaining attacks based on discovered vulnerabilities
        
        Ensure each plan is distinct and targets different attack vectors or methodologies."""
        
        messages = [
            {"role": "system", "content": batch_prompt},
            {"role": "user", "content": context_data}
        ]
        
        response = self.client.chat.completions.create(
            model="o3-mini",
            messages=messages,
        )
        
        # Parse YAML response into list of dicts
        yaml_str = response.choices[0].message.content
        
        # Strip markdown code blocks if present
        if yaml_str.strip().startswith('```'):
            # Remove opening ```yaml or ``` 
            lines = yaml_str.strip().split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]
            # Remove closing ```
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            yaml_str = '\n'.join(lines)
        
        items = yaml.safe_load(yaml_str)
        if not isinstance(items, list):
            items = [items]
        
        # Return exactly the requested batch size
        return items[:batch_size]
