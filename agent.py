import os
import json
import time
import base64
import logging
from logger import Logger
from proxy import WebProxy
from llm import LLM
from scanner import Scanner
from parser import HTMLParser
from planner import Planner
from tools import Tools
from summarizer import Summarizer
from utils import check_hostname, enumerate_subdomains, wait_for_network_idle, count_tokens
from reporter import Reporter

logger = Logger()

class Agent:
    """
    AI-powered security testing agent that scans web applications for vulnerabilities.
    
    The agent uses an LLM to intelligently analyze web pages, generate test plans,
    and execute security tests using various tools. It monitors network traffic,
    evaluates responses, and generates detailed vulnerability reports.
    """

    def __init__(self, starting_url: str, expand_scope: bool = False, 
                 enumerate_subdomains: bool = False, model: str = 'o3-mini',
                 output_dir: str = 'security_results', max_iterations: int = 10):
        """
        Initialize the security testing agent.

        Args:
            starting_url: Base URL to begin scanning from
            expand_scope: Whether to scan additional discovered URLs
            enumerate_subdomains: Whether to discover and scan subdomains
            model: LLM model to use for analysis
            output_dir: Directory to save scan results
            max_iterations: Maximum iterations per test plan
        """
        self.starting_url = starting_url
        self.expand_scope = expand_scope
        self.should_enumerate_subdomains = enumerate_subdomains
        self.model = model
        self.output_dir = output_dir
        self.max_iterations = max_iterations
        self.keep_messages = 15

        self.proxy = WebProxy(starting_url, logger)
        self.llm = LLM()
        self.planner = Planner()
        self.scanner = None
        self.tools = Tools()
        self.history = []
        self.reporter = Reporter(starting_url)
        
    def run(self):
        """
        Execute the security scan by:
        1. Setting up monitoring proxy
        2. Discovering target URLs
        3. Scanning each URL:
            - Analyze page content
            - Generate test plans
            - Execute security tests
            - Evaluate results
        4. Generate vulnerability reports
        """
        # Create web proxy to monitor all requests
        logger.info("Creating web proxy to monitor requests", color='yellow')
        browser, context, page, playwright = self.proxy.create_proxy()
        urls_to_parse = [self.starting_url]

        # If subdomain enumeration is enabled, add discovered subdomains
        if self.should_enumerate_subdomains:
            logger.info("Enumerating subdomains, might take a few minutes", color='yellow')
            subdomains = enumerate_subdomains(self.starting_url)
            urls_to_parse.extend(subdomains)
        
        self.reports = []
        # Initialize scanner
        logger.info("Extracting page contents", color='yellow')
        self.scanner = Scanner(page)

        total_tokens = 0
        while urls_to_parse:
            # Visit the URL and start scanning it
            url = urls_to_parse.pop(0)

            logger.info(f"Starting scan: {url}", color='cyan')
            scan_results = self.scanner.scan(url)

            # Add URLs to queue if expand_scope is enabled
            if self.expand_scope:
                more_urls = scan_results["parsed_data"]["urls"]
                new_urls = 0
                for _url in more_urls:
                    _url = _url["href"]
                    if _url not in urls_to_parse and check_hostname(self.starting_url, _url):
                        urls_to_parse.append(_url)
                        new_urls += 1
                if new_urls > 0:
                    logger.info(f"Added {new_urls} new URLs to the search queue", color='green')

            # Build a plan for what we should try for this page
            page_source = scan_results["html_content"]
            total_tokens += count_tokens(page_source)
            page_source = Summarizer().summarize_page_source(page_source, url)
            page_data = f"Page information: {page_source}\n*** URL of the page we are planning for: {url} ***"

            # Initialize history with system prompt and page data
            self.history = [
                {"role": "system", "content": self.llm.system_prompt},
                {"role": "user", "content": page_data}
            ]
            
            # Add the plan to the history
            logger.info("Generating a plan for security testing", color='cyan')
            total_tokens += count_tokens(page_data)
            plans = self.planner.plan(page_data)

            # Output the full plan first
            total_plans = len(plans)
            for index, plan in enumerate(plans):
                logger.info(f"Plan {index + 1}/{total_plans}: {plan['title']}", color='light_magenta')

            for index, plan in enumerate(plans):
                # Reset history when we are in a new plan
                self.history = self.history[:2]

                # Execute plan
                logger.info(f"{index + 1}/{total_plans}: {plan['title']}", color='cyan')
                self.history.append({"role": "assistant", "content": f"I will now start exploring the ```{plan['title']} - {plan['description']}``` and see if I can find any issues around it. Are we good to go?"})
                self.history.append({"role": "user", "content": "Sure, let us start exploring this by trying out some tools. We must stick to the plan and do not deviate from it. Once we are done, simply call the completed function."})
                
                # Execute the plan iterations
                iterations = 0
                while iterations < self.max_iterations:
                    # Manage history size - keep first 4 messages
                    if len(self.history) > self.keep_messages:
                        # First four messages are important and we need to keep them
                        keep_from_end = self.keep_messages - 4
                        self.history = self.history[:4] + Summarizer().summarize_conversation(self.history[4:-keep_from_end]) + self.history[-keep_from_end:]
                        
                    # Send the request to the LLM
                    plan_tokens = count_tokens(self.history)
                    total_tokens += plan_tokens
                    logger.info(f"Total tokens used till now: {total_tokens:,}, current query tokens: {plan_tokens:,}", color='red')

                    llm_response = self.llm.reason(self.history)
                    self.history.append({"role": "assistant", "content": llm_response})
                    logger.info(f"{llm_response}", color='light_blue')

                    # Extract and execute the tool use from the LLM response
                    tool_use = self.tools.extract_tool_use(llm_response)
                    logger.info(f"{tool_use}", color='yellow')

                    tool_output = str(self.tools.execute_tool(page, tool_use))
                    logger.info(f"{tool_output[:250]}{'...' if len(tool_output) > 250 else ''}", color='yellow')

                    total_tokens += count_tokens(tool_output)
                    
                    tool_output_summarized = Summarizer().summarize(llm_response, tool_use, tool_output)
                    self.history.append({"role": "user", "content": tool_output_summarized})
                    logger.info(f"{tool_output_summarized}", color='cyan')       

                    if tool_output == "Completed":
                        total_tokens += count_tokens(self.history[2:])
                        successful_exploit, report = self.reporter.report(self.history[2:])
                        logger.info(f"Analysis of the issue the agent has found: {report}", color='green')
                        
                        if successful_exploit:
                            logger.info("Completed, moving onto the next plan!", color='yellow')
                            break
                        else:
                            logger.info("Need to work harder on the exploit.", color='red')
                            self.history.append({"role": "user", "content": report + "\n. Lets do better, again!"})
                    
                    # Print traffic
                    wait_for_network_idle(page)
                    traffic = self.proxy.pretty_print_traffic()
                    if traffic:
                        logger.info(traffic, color='cyan')
                        self.history.append({"role": "user", "content": traffic})
                        total_tokens += count_tokens(traffic)
                    # Clear proxy
                    self.proxy.clear()

                    # Continue
                    iterations += 1
                    if iterations >= self.max_iterations:
                        logger.info("Max iterations reached, moving onto the next plan!", color='red')
                        break

        # Generate and save report
        logger.info("Generating summary report", color='yellow')
        self.reporter.generate_summary_report()