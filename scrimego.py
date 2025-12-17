#!/usr/bin/env python3

"""
Scrimego - Multi-Platform Downloader
Supports: GoFile.io, MediaFire, and Scribd
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import queue
import os
import re
from pathlib import Path
from typing import Optional, Dict, List
import sys
from datetime import datetime

# Import all required modules
import requests
from requests import Session, Response, Timeout
from requests.structures import CaseInsensitiveDict
from concurrent.futures import ThreadPoolExecutor
from threading import Event, BoundedSemaphore
from hashlib import sha256, md5
import hashlib
from shutil import move, copyfileobj
from signal import signal, SIGINT, SIG_IGN
from time import perf_counter, sleep
from itertools import count
from types import FrameType
from typing import Any, Iterator, NoReturn
import urllib.parse
import http.client
from io import BytesIO
from gzip import GzipFile
import base64

# Optional imports for additional features
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    print("Warning: BeautifulSoup4 not installed. MediaFire and Scribd may not work properly.")

try:
    from gazpacho import Soup as GazpachoSoup
    HAS_GAZPACHO = True
except ImportError:
    HAS_GAZPACHO = False

try:
    import img2pdf
    HAS_IMG2PDF = True
except ImportError:
    HAS_IMG2PDF = False
    print("Warning: img2pdf not installed. Scribd PDF conversion will not work.")

try:
    import socks
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False


# ============================================================================
# Constants and Configuration
# ============================================================================

TOR_SOCKS_PROXY = "socks5h://127.0.0.1:9050"
NON_ALPHANUM_FILE_OR_FOLDER_NAME_CHARACTERS = "-_. "
NON_ALPHANUM_FILE_OR_FOLDER_NAME_CHARACTER_REPLACEMENT = "_"

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0"
DEFAULT_MAX_WORKERS = 5
DEFAULT_RETRIES = 5
DEFAULT_TIMEOUT = 15.0
DEFAULT_CHUNK_SIZE = 2097152  # 2MB


# ============================================================================
# Utility Functions
# ============================================================================

def normalize_filename(filename: str) -> str:
    """Normalize filename to remove invalid characters."""
    return "".join(
        char if (char.isalnum() or char in NON_ALPHANUM_FILE_OR_FOLDER_NAME_CHARACTERS)
        else NON_ALPHANUM_FILE_OR_FOLDER_NAME_CHARACTER_REPLACEMENT
        for char in filename
    )


def hash_file_sha256(filename: str) -> str:
    """Calculate SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(filename, "rb") as file:
        while chunk := file.read(8192):
            h.update(chunk)
    return h.hexdigest()


def detect_platform(url: str) -> Optional[str]:
    """Detect which platform the URL belongs to."""
    url_lower = url.lower()
    
    if "gofile.io" in url_lower:
        return "gofile"
    elif "mediafire.com" in url_lower:
        return "mediafire"
    elif "scribd.com" in url_lower:
        return "scribd"
    
    return None


def get_unique_filename(filepath: str) -> str:
    """
    Generate a unique filename if file exists.
    Appends _1, _2, etc. before the extension.
    Example: file.txt -> file_1.txt -> file_2.txt
    """
    if not os.path.exists(filepath):
        return filepath
    
    directory = os.path.dirname(filepath)
    filename = os.path.basename(filepath)
    name, ext = os.path.splitext(filename)
    
    counter = 1
    while True:
        new_filename = f"{name}_{counter}{ext}"
        new_filepath = os.path.join(directory, new_filename) if directory else new_filename
        
        if not os.path.exists(new_filepath):
            return new_filepath
        
        counter += 1


def renew_tor_circuit(debug_callback=None):
    """
    Request Tor to create a new circuit.
    Requires Tor control port to be accessible.
    """
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9051))
        s.send(b"AUTHENTICATE\r\n")
        s.recv(1024)
        s.send(b"SIGNAL NEWNYM\r\n")
        response = s.recv(1024)
        s.close()
        
        if debug_callback:
            debug_callback("Tor circuit renewed")
        
        # Wait a bit for new circuit to establish
        sleep(2)
        return True
    except Exception as e:
        if debug_callback:
            debug_callback(f"Failed to renew Tor circuit: {str(e)}")
        return False


def convert_file_extension(filepath: str, target_ext: str, debug_callback=None) -> bool:
    """
    Convert file to target extension.
    Supports: txt, pdf, html, md, csv, json, xml
    """
    if not target_ext or not os.path.exists(filepath):
        return False
    
    target_ext = target_ext.lower().strip('.')
    current_ext = os.path.splitext(filepath)[1].lower().strip('.')
    
    if current_ext == target_ext:
        return True  # Already correct extension
    
    try:
        # Read original file
        with open(filepath, 'rb') as f:
            content = f.read()
        
        # Try to decode as text
        try:
            text_content = content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                text_content = content.decode('latin-1')
            except:
                if debug_callback:
                    debug_callback(f"Cannot convert binary file {filepath} to text format")
                return False
        
        # Create new filename
        new_filepath = os.path.splitext(filepath)[0] + f'.{target_ext}'
        
        # Convert based on target extension
        if target_ext == 'txt':
            # Simple text conversion
            with open(new_filepath, 'w', encoding='utf-8') as f:
                f.write(text_content)
        
        elif target_ext == 'md':
            # Convert to markdown
            with open(new_filepath, 'w', encoding='utf-8') as f:
                f.write(text_content)
        
        elif target_ext == 'html':
            # Wrap in basic HTML
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Converted Document</title>
</head>
<body>
<pre>{text_content}</pre>
</body>
</html>"""
            with open(new_filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
        
        elif target_ext == 'json':
            # Try to parse and format as JSON
            import json
            try:
                data = json.loads(text_content)
                with open(new_filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            except:
                # If not valid JSON, wrap content
                with open(new_filepath, 'w', encoding='utf-8') as f:
                    json.dump({"content": text_content}, f, indent=2)
        
        elif target_ext == 'xml':
            # Wrap in basic XML
            xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<document>
<content><![CDATA[{text_content}]]></content>
</document>"""
            with open(new_filepath, 'w', encoding='utf-8') as f:
                f.write(xml_content)
        
        elif target_ext == 'csv':
            # Convert to CSV (each line is a row)
            import csv
            with open(new_filepath, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                for line in text_content.split('\n'):
                    writer.writerow([line])
        
        else:
            # Default: just change extension
            with open(new_filepath, 'w', encoding='utf-8') as f:
                f.write(text_content)
        
        # Remove original file
        os.remove(filepath)
        
        if debug_callback:
            debug_callback(f"Converted {filepath} to {new_filepath}")
        
        return True
    
    except Exception as e:
        if debug_callback:
            debug_callback(f"Error converting {filepath}: {str(e)}")
        return False


# ============================================================================
# GoFile Downloader
# ============================================================================

class GoFileDownloader:
    """Downloader for GoFile.io links."""
    
    def __init__(self, url: str, output_dir: str, password: Optional[str] = None,
                 use_tor: bool = False, debug_callback=None, status_callback=None,
                 separate_folders: bool = False, force_extension: Optional[str] = None,
                 enable_retry: bool = True, skip_existing: bool = True):
        self.url = url
        self.base_output_dir = output_dir
        self.output_dir = os.path.join(output_dir, "gofile") if separate_folders else output_dir
        self.password = password
        self.use_tor = use_tor
        self.debug_callback = debug_callback
        self.status_callback = status_callback
        self.force_extension = force_extension
        self.enable_retry = enable_retry
        self.skip_existing = skip_existing
        self.max_retries = 3 if enable_retry else 1
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.files_info: Dict[str, Dict[str, str]] = {}
        self.max_workers = DEFAULT_MAX_WORKERS
        self.number_retries = DEFAULT_RETRIES
        self.timeout = DEFAULT_TIMEOUT
        self.chunk_size = DEFAULT_CHUNK_SIZE
        self.stop_event = Event()
        
        self.session = self._create_session()
        
    def _create_session(self) -> Session:
        """Create a requests session with appropriate settings."""
        session = Session()
        
        if self.use_tor:
            if not HAS_SOCKS:
                self._log("PySocks not installed, cannot use Tor")
            else:
                session.proxies = {
                    'http': TOR_SOCKS_PROXY,
                    'https': TOR_SOCKS_PROXY,
                }
        
        session.headers.update({
            "Accept-Encoding": "gzip",
            "User-Agent": DEFAULT_USER_AGENT,
            "Connection": "keep-alive",
            "Accept": "*/*",
        })
        
        return session
    
    def _log(self, message: str):
        """Log debug message."""
        if self.debug_callback:
            self.debug_callback(f"[GoFile] {message}")
    
    def _update_status(self, message: str):
        """Update status message."""
        if self.status_callback:
            self.status_callback(message)
    
    def _get_response(self, **kwargs) -> Optional[Response]:
        """Get response with retries."""
        for attempt in range(self.number_retries):
            try:
                return self.session.get(timeout=self.timeout, **kwargs)
            except Timeout:
                self._log(f"Timeout on attempt {attempt + 1}/{self.number_retries}")
                continue
            except Exception as e:
                self._log(f"Error on attempt {attempt + 1}: {str(e)}")
                continue
        return None
    
    def _set_account_token(self):
        """Get account token from GoFile API."""
        try:
            response = self.session.post(
                "https://api.gofile.io/accounts",
                timeout=self.timeout
            ).json()
            
            if response.get("status") == "ok":
                token = response["data"]["token"]
                self.session.cookies.set("accountToken", token)
                self.session.headers.update({"Authorization": f"Bearer {token}"})
                self._log("Account token obtained successfully")
                return True
        except Exception as e:
            self._log(f"Failed to get account token: {str(e)}")
        
        return False
    
    def _build_content_tree(self, parent_dir: str, content_id: str,
                           password: Optional[str] = None,
                           pathing_count: Optional[Dict] = None,
                           file_index: count = None):
        """Build the file tree structure from GoFile API."""
        if file_index is None:
            file_index = count(start=0, step=1)
        
        if pathing_count is None:
            pathing_count = {}
        
        url = f"https://api.gofile.io/contents/{content_id}?cache=true&wt=4fd6sg89d7s6"
        
        if password:
            url = f"{url}&password={password}"
        
        response = self._get_response(url=url)
        
        if not response:
            self._log(f"Failed to fetch content from {url}")
            return
        
        try:
            json_response = response.json()
        except Exception as e:
            self._log(f"Failed to parse JSON response: {str(e)}")
            return
        
        if json_response.get("status") != "ok":
            self._log(f"API returned non-ok status: {json_response.get('status')}")
            return
        
        data = json_response.get("data", {})
        
        if "password" in data and data.get("passwordStatus") != "passwordOk":
            self._log("Password protected link - password required or incorrect")
            return
        
        if data.get("type") != "folder":
            filepath = os.path.join(parent_dir, data.get("name", "unknown"))
            self._register_file(file_index, filepath, data.get("link", ""))
            return
        
        folder_name = data.get("name", "unnamed")
        absolute_path = os.path.join(parent_dir, folder_name)
        
        # Don't create subdirectory if parent_dir already ends with content_id
        if os.path.basename(parent_dir) == content_id or parent_dir == self.output_dir:
            absolute_path = parent_dir
        
        os.makedirs(absolute_path, exist_ok=True)
        
        for child in data.get("children", {}).values():
            if self.stop_event.is_set():
                return
            
            if child.get("type") == "folder":
                self._build_content_tree(absolute_path, child["id"], password, pathing_count, file_index)
            else:
                filepath = os.path.join(absolute_path, child.get("name", "unknown"))
                self._register_file(file_index, filepath, child.get("link", ""))
    
    def _register_file(self, file_index: count, filepath: str, file_url: str):
        """Register a file for download."""
        self.files_info[str(next(file_index))] = {
            "path": os.path.dirname(filepath),
            "filename": os.path.basename(filepath),
            "link": file_url
        }
    
    def _download_file(self, file_info: Dict[str, str]):
        """Download a single file."""
        filepath = os.path.join(file_info["path"], file_info["filename"])
        
        # Handle existing files
        if os.path.exists(filepath):
            if os.path.getsize(filepath) > 0:
                if self.skip_existing:
                    filepath = get_unique_filename(filepath)
                    file_info = file_info.copy()  # Don't modify original
                    file_info["filename"] = os.path.basename(filepath)
                    file_info["path"] = os.path.dirname(filepath)
                    self._log(f"File exists, creating new: {filepath}")
                else:
                    self._log(f"File already exists: {filepath}")
                    return
        
        tmp_file = f"{filepath}.part"
        url = file_info["link"]
        
        headers = {}
        part_size = 0
        
        if os.path.isfile(tmp_file):
            part_size = os.path.getsize(tmp_file)
            headers = {"Range": f"bytes={part_size}-"}
        
        for attempt in range(self.max_retries):
            if self.stop_event.is_set():
                return
            
            try:
                if attempt > 0:
                    self._log(f"Retry attempt {attempt + 1}/{self.max_retries} for {file_info['filename']}")
                    if self.use_tor:
                        renew_tor_circuit(self.debug_callback)
                
                response = self._get_response(url=url, headers=headers, stream=True)
                
                if not response:
                    if attempt < self.max_retries - 1:
                        continue
                    else:
                        break
                
                status_code = response.status_code
                
                if status_code not in (200, 206):
                    self._log(f"Failed to download {filepath}: status {status_code}")
                    if attempt < self.max_retries - 1:
                        continue
                    else:
                        break
                
                content_length = response.headers.get("Content-Length")
                if not content_length:
                    self._log(f"No content length for {filepath}")
                    if attempt < self.max_retries - 1:
                        continue
                    else:
                        break
                
                total_size = int(content_length) if part_size == 0 else int(response.headers.get("Content-Range", "").split("/")[-1])
                
                if self.status_callback:
                    self.status_callback(f"Downloading: {file_info['filename']}")
                
                with open(tmp_file, "ab") as f:
                    downloaded = part_size
                    for chunk in response.iter_content(chunk_size=self.chunk_size):
                        if self.stop_event.is_set():
                            return
                        
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        progress = (downloaded / total_size) * 100
                        if self.status_callback:
                            self.status_callback(f"Downloading: {file_info['filename']} ({progress:.1f}%)")
                
                if os.path.getsize(tmp_file) == total_size:
                    final_path = os.path.join(file_info["path"], file_info["filename"])
                    move(tmp_file, final_path)
                    
                    # Apply extension conversion if needed
                    if self.force_extension:
                        convert_file_extension(final_path, self.force_extension, self.debug_callback)
                    
                    self._log(f"Downloaded: {final_path}")
                    if self.status_callback:
                        self.status_callback(f"Completed: {file_info['filename']}")
                    return
                
            except Exception as e:
                self._log(f"Error downloading {filepath}: {str(e)}")
                if attempt < self.max_retries - 1:
                    continue
                else:
                    self._log(f"Failed after {self.max_retries} attempts: {filepath}")
                    break
    
    def download(self) -> bool:
        """Main download method."""
        try:
            # Extract content ID
            if "/d/" not in self.url:
                self._log("Invalid GoFile URL format")
                return False
            
            content_id = self.url.split("/")[-1].split("?")[0]  # Remove query params if any
            self._log(f"Content ID: {content_id}")
            
            # Set account token
            if not self._set_account_token():
                self._log("Failed to get account token")
                return False
            
            # Prepare password
            _password = sha256(self.password.encode()).hexdigest() if self.password else None
            
            # Build file tree
            self._update_status("Building file tree...")
            self._build_content_tree(self.output_dir, content_id, _password)
            
            if not self.files_info:
                self._log("No files found")
                return False
            
            self._log(f"Found {len(self.files_info)} files")
            
            # Download files
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for file_info in self.files_info.values():
                    if self.stop_event.is_set():
                        break
                    futures.append(executor.submit(self._download_file, file_info))
                
                for future in futures:
                    if self.stop_event.is_set():
                        break
                    future.result()
            
            self._update_status("Download completed!")
            return True
            
        except Exception as e:
            self._log(f"Error in download: {str(e)}")
            return False
    
    def stop(self):
        """Stop the download process."""
        self.stop_event.set()


# ============================================================================
# MediaFire Downloader
# ============================================================================

class MediaFireDownloader:
    """Downloader for MediaFire links with folder support."""
    
    def __init__(self, url: str, output_dir: str, password: Optional[str] = None,
                 use_tor: bool = False, debug_callback=None, status_callback=None,
                 separate_folders: bool = False, force_extension: Optional[str] = None,
                 enable_retry: bool = True, skip_existing: bool = True):
        self.url = url
        self.base_output_dir = output_dir
        self.output_dir = os.path.join(output_dir, "mediafire") if separate_folders else output_dir
        self.password = password
        self.use_tor = use_tor
        self.debug_callback = debug_callback
        self.status_callback = status_callback
        self.stop_event = Event()
        self.force_extension = force_extension
        self.max_workers = 10
        self.enable_retry = enable_retry
        self.skip_existing = skip_existing
        self.max_retries = 3 if enable_retry else 1
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.session = self._create_session()
    
    def _create_session(self) -> Session:
        """Create a requests session."""
        session = Session()
        
        if self.use_tor:
            if not HAS_SOCKS:
                self._log("PySocks not installed, cannot use Tor")
            else:
                session.proxies = {
                    'http': TOR_SOCKS_PROXY,
                    'https': TOR_SOCKS_PROXY,
                }
        
        session.headers.update({
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
        })
        
        return session
    
    def _log(self, message: str):
        """Log debug message."""
        if self.debug_callback:
            self.debug_callback(f"[MediaFire] {message}")
    
    def _get_api_endpoint(self, filefolder: str, key: str, chunk: int = 1, info: bool = False) -> str:
        """Construct MediaFire API endpoint."""
        if filefolder == "file":
            return f"https://www.mediafire.com/api/file/get_info.php?quick_key={key}&response_format=json"
        else:
            action = "get_info" if info else "get_content"
            return (f"https://www.mediafire.com/api/1.4/folder/{action}.php?r=utga&content_type={filefolder}"
                   f"&filter=all&order_by=name&order_direction=asc&chunk={chunk}"
                   f"&version=1.5&folder_key={key}&response_format=json")
    
    def _get_file_info(self, file_key: str) -> Optional[Dict]:
        """Get file info from MediaFire API."""
        try:
            response = self.session.get(self._get_api_endpoint("file", file_key), timeout=15)
            data = response.json()
            
            if "response" in data and "file_info" in data["response"]:
                return data["response"]["file_info"]
        except Exception as e:
            self._log(f"Error getting file info: {str(e)}")
        
        return None
    
    def _extract_download_link(self, url: str) -> Optional[str]:
        """Extract the actual download link from MediaFire download page."""
        try:
            response = self.session.get(url, timeout=15)
            html = response.text
            
            # Try multiple methods to extract download link
            actual_download_link = None
            
            # Method 1: Try BeautifulSoup if available
            if HAS_BS4:
                soup = BeautifulSoup(html, "html.parser")
                download_button = soup.find("a", {"id": "downloadButton"})
                
                if download_button:
                    # Check for direct href
                    if "href" in download_button.attrs:
                        href = download_button.attrs["href"]
                        # Check if it's a direct download link
                        if "download" in href:
                            actual_download_link = href
            
            # Method 2: Regex fallback for direct download links
            if not actual_download_link:
                # Look for download URLs in the HTML
                link_patterns = [
                    r'href="(https://download\d+\.mediafire\.com/[^"]+)"',
                    r"href='(https://download\d+\.mediafire\.com/[^']+)'",
                    r'<a[^>]+id="downloadButton"[^>]+href="([^"]+)"',
                ]
                
                for pattern in link_patterns:
                    match = re.search(pattern, html)
                    if match:
                        actual_download_link = match.group(1)
                        break
            
            return actual_download_link
            
        except Exception as e:
            self._log(f"Error extracting download link: {str(e)}")
            return None
    
    def _download_file_from_info(self, file_info: Dict, output_path: str):
        """Download a single MediaFire file given its info."""
        download_link = file_info["links"]["normal_download"]
        filename = normalize_filename(file_info["filename"])
        filepath = os.path.join(output_path, filename)
        
        # Handle existing files
        if os.path.exists(filepath):
            if "hash" in file_info:
                try:
                    existing_hash = hash_file_sha256(filepath)
                    if existing_hash == file_info["hash"]:
                        if self.skip_existing:
                            filepath = get_unique_filename(filepath)
                            filename = os.path.basename(filepath)
                            self._log(f"File exists, creating new: {filename}")
                        else:
                            self._log(f"File already exists: {filename}")
                            return True
                except:
                    pass
        
        for attempt in range(self.max_retries):
            if self.stop_event.is_set():
                return False
            
            try:
                if attempt > 0:
                    self._log(f"Retry attempt {attempt + 1}/{self.max_retries} for {filename}")
                    if self.use_tor:
                        renew_tor_circuit(self.debug_callback)
                
                if self.status_callback:
                    self.status_callback(f"Downloading: {filename}")
                
                self._log(f"Starting download: {filename}")
                
                # Extract actual download link
                actual_download_link = self._extract_download_link(download_link)
                
                if not actual_download_link:
                    self._log(f"Could not find download link for {filename}")
                    if attempt < self.max_retries - 1:
                        sleep(2)
                        continue
                    return False
                
                # Download the file using requests (simpler and more reliable)
                response = self.session.get(actual_download_link, stream=True, timeout=30)
                
                if response.status_code != 200:
                    self._log(f"Download failed with status: {response.status_code}")
                    if attempt < self.max_retries - 1:
                        sleep(2)
                        continue
                    return False
                
                # Download file
                with open(filepath, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if self.stop_event.is_set():
                            if os.path.exists(filepath):
                                os.remove(filepath)
                            return False
                        
                        if chunk:
                            f.write(chunk)
                
                # Apply extension conversion if needed
                if self.force_extension:
                    convert_file_extension(filepath, self.force_extension, self.debug_callback)
                
                self._log(f"Downloaded: {filename}")
                if self.status_callback:
                    self.status_callback(f"Completed: {filename}")
                return True
            
            except Exception as e:
                self._log(f"Error downloading {filename}: {str(e)}")
                if os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                    except:
                        pass
                if attempt < self.max_retries - 1:
                    sleep(2)
                    continue
                else:
                    self._log(f"Failed after {self.max_retries} attempts: {filename}")
                    return False
        
        return False
    
    def _download_folder(self, folder_key: str, folder_path: str):
        """Download all files from a MediaFire folder."""
        try:
            # Get all files in the folder (with pagination)
            files_data = []
            chunk = 1
            more_chunks = True
            
            while more_chunks:
                if self.stop_event.is_set():
                    return
                
                response = self.session.get(self._get_api_endpoint("files", folder_key, chunk=chunk), timeout=15)
                r_json = response.json()
                
                if "response" not in r_json or "folder_content" not in r_json["response"]:
                    break
                
                folder_content = r_json["response"]["folder_content"]
                more_chunks = folder_content.get("more_chunks") == "yes"
                
                if "files" in folder_content:
                    files_data.extend(folder_content["files"])
                
                chunk += 1
            
            # Download all files
            for file_info in files_data:
                if self.stop_event.is_set():
                    return
                
                self._download_file_from_info(file_info, folder_path)
            
            # Get subfolders
            response = self.session.get(self._get_api_endpoint("folders", folder_key), timeout=15)
            r_json = response.json()
            
            if "response" in r_json and "folder_content" in r_json["response"]:
                folder_content = r_json["response"]["folder_content"]
                
                if "folders" in folder_content:
                    for subfolder in folder_content["folders"]:
                        if self.stop_event.is_set():
                            return
                        
                        subfolder_name = normalize_filename(subfolder["name"])
                        subfolder_path = os.path.join(folder_path, subfolder_name)
                        os.makedirs(subfolder_path, exist_ok=True)
                        
                        self._log(f"Entering folder: {subfolder_name}")
                        self._download_folder(subfolder["folderkey"], subfolder_path)
        
        except Exception as e:
            self._log(f"Error downloading folder: {str(e)}")
    
    def download(self) -> bool:
        """Main download method."""
        try:
            # Extract file or folder key
            match = re.search(r"mediafire\.com/(folder|file|file_premium)/([a-zA-Z0-9]+)", self.url)
            
            if not match:
                self._log("Invalid MediaFire URL")
                return False
            
            content_type, key = match.groups()
            
            if content_type in ("file", "file_premium"):
                # Single file download
                file_info = self._get_file_info(key)
                if not file_info:
                    self._log("Could not get file info")
                    return False
                
                return self._download_file_from_info(file_info, self.output_dir)
            
            elif content_type == "folder":
                # Folder download
                # Get folder name first
                response = self.session.get(self._get_api_endpoint("folder", key, info=True), timeout=15)
                
                if response.status_code != 200:
                    self._log(f"Failed to get folder info: {response.status_code}")
                    return False
                
                data = response.json()
                if "response" not in data or "folder_info" not in data["response"]:
                    self._log("Invalid folder response")
                    return False
                
                folder_name = normalize_filename(data["response"]["folder_info"]["name"])
                folder_path = os.path.join(self.output_dir, folder_name)
                os.makedirs(folder_path, exist_ok=True)
                
                self._log(f"Downloading folder: {folder_name}")
                self._download_folder(key, folder_path)
                return True
            
            return False
        
        except Exception as e:
            self._log(f"Error in download: {str(e)}")
            return False
    
    def stop(self):
        """Stop the download process."""
        self.stop_event.set()


# ============================================================================
# Scribd Downloader
# ============================================================================

class ScribdDownloader:
    """Downloader for Scribd documents."""
    
    def __init__(self, url: str, output_dir: str, password: Optional[str] = None,
                 use_tor: bool = False, debug_callback=None, status_callback=None,
                 separate_folders: bool = False, force_extension: Optional[str] = None,
                 enable_retry: bool = True, skip_existing: bool = True):
        self.url = url
        self.base_output_dir = output_dir
        self.output_dir = os.path.join(output_dir, "scribd") if separate_folders else output_dir
        self.password = password
        self.use_tor = use_tor
        self.debug_callback = debug_callback
        self.status_callback = status_callback
        self.stop_event = Event()
        self.force_extension = force_extension
        self.enable_retry = enable_retry
        self.skip_existing = skip_existing
        self.max_retries = 3 if enable_retry else 1
        
        self.images: List[str] = []
        self.images_dir = os.path.join(self.output_dir, "scribd_images")
        self.total_pages: Optional[int] = None
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.session = self._create_session()
    
    def _create_session(self) -> Session:
        """Create a requests session."""
        session = Session()
        
        if self.use_tor:
            if not HAS_SOCKS:
                self._log("PySocks not installed, cannot use Tor")
            else:
                session.proxies = {
                    'http': TOR_SOCKS_PROXY,
                    'https': TOR_SOCKS_PROXY,
                }
        
        session.headers.update({
            "User-Agent": DEFAULT_USER_AGENT,
        })
        
        return session
    
    def _log(self, message: str):
        """Log debug message."""
        if self.debug_callback:
            self.debug_callback(f"[Scribd] {message}")
    
    def _update_status(self, message: str):
        """Update status message."""
        if self.status_callback:
            self.status_callback(message)
    
    def _get_total_pages(self) -> Optional[int]:
        """Get total number of pages."""
        if not HAS_BS4:
            self._log("BeautifulSoup4 not installed")
            return None
        
        try:
            response = self.session.get(self.url, timeout=15)
            soup = BeautifulSoup(response.text, "html.parser")
            span = soup.find("span", {"data-e2e": "total-pages"})
            
            if span:
                total_pages = span.get_text().replace("/", "").strip()
                return int(total_pages)
        except Exception as e:
            self._log(f"Error getting total pages: {str(e)}")
        
        return None
    
    def _sanitize_title(self, title: str) -> str:
        """Sanitize title for filename."""
        forbidden_chars = r'*\"/\\<>:|(),'
        for ch in forbidden_chars:
            title = title.replace(ch, "_")
        # Also remove leading/trailing spaces and dots
        title = title.strip('. ')
        return title
    
    def _download_image(self, url: str, page_num: int, found: bool = False):
        """Download a single image page."""
        os.makedirs(self.images_dir, exist_ok=True)
        image_path = os.path.join(self.images_dir, f"{page_num:04d}.jpg")
        
        # Skip if already exists
        if os.path.exists(image_path):
            self.images.append(image_path)
            return True
        
        # Convert JSONP URLs to image URLs
        if url.endswith(".jsonp"):
            url = url.replace("/pages/", "/images/")
            if found:
                url = url.replace(".jsonp", "/000.jpg")
            else:
                url = url.replace(".jsonp", ".jpg")
        
        for attempt in range(self.max_retries):
            if self.stop_event.is_set():
                return False
            
            try:
                if attempt > 0:
                    self._log(f"Retry attempt {attempt + 1}/{self.max_retries} for page {page_num}")
                    if self.use_tor:
                        renew_tor_circuit(self.debug_callback)
                
                response = self.session.get(url, stream=True, timeout=15)
                
                if response.status_code != 200:
                    if attempt < self.max_retries - 1:
                        sleep(1)
                        continue
                    return False
                
                with open(image_path, "wb") as f:
                    copyfileobj(response.raw, f)
                
                self.images.append(image_path)
                self._log(f"Downloaded page {page_num}" + (f"/{self.total_pages}" if self.total_pages else ""))
                return True
            
            except Exception as e:
                self._log(f"Error downloading page {page_num}: {str(e)}")
                if attempt < self.max_retries - 1:
                    sleep(1)
                    continue
                return False
        
        return False
    
    def _convert_to_pdf(self, title: str):
        """Convert downloaded images to PDF."""
        if not HAS_IMG2PDF:
            self._log("img2pdf not installed, cannot create PDF")
            return False
        
        if not self.images:
            return False
        
        try:
            sorted_images = sorted(
                self.images,
                key=lambda x: int(os.path.splitext(os.path.basename(x))[0])
            )
            
            pdf_filename = f"{title}.pdf"
            pdf_path = os.path.join(self.output_dir, pdf_filename)
            
            # Handle existing files
            if os.path.exists(pdf_path) and self.skip_existing:
                pdf_path = get_unique_filename(pdf_path)
                self._log(f"PDF exists, creating new: {pdf_path}")
            
            with open(pdf_path, "wb") as f:
                f.write(img2pdf.convert(sorted_images))
            
            # Apply extension conversion if needed and it's not PDF
            if self.force_extension and self.force_extension.lower() != 'pdf':
                convert_file_extension(pdf_path, self.force_extension, self.debug_callback)
            
            self._log(f"Created PDF: {pdf_path}")
            return True
        except Exception as e:
            self._log(f"Error creating PDF: {str(e)}")
            return False
    
    def download(self) -> bool:
        """Main download method."""
        if not HAS_BS4:
            self._log("BeautifulSoup4 required for Scribd downloads")
            return False
        
        try:
            if self.status_callback:
                self.status_callback("Fetching document info...")
            
            response = self.session.get(self.url, timeout=15)
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Get title
            title_tag = soup.find("title")
            title = self._sanitize_title(title_tag.get_text()) if title_tag else "scribd_document"
            
            self._log(f"Document title: {title}")
            
            # Get total pages
            self.total_pages = self._get_total_pages()
            if self.total_pages:
                self._log(f"Total pages: {self.total_pages}")
            
            page_num = 1
            
            # Download images with class "absimg"
            absimg = soup.find_all("img", {"class": "absimg"}, src=True)
            for img in absimg:
                if self.stop_event.is_set():
                    return False
                
                if self.status_callback:
                    self.status_callback(f"Downloading page {page_num}/{len(absimg)}")
                
                if self._download_image(img["src"], page_num):
                    page_num += 1
            
            # Find JSONP links in JavaScript
            js_text = soup.find_all("script", type="text/javascript")
            
            for script in js_text:
                if self.stop_event.is_set():
                    break
                
                script_content = script.string
                if not script_content:
                    continue
                
                # Find all JSONP URLs
                matches = re.findall(r"https://.*?\.jsonp", script_content)
                for jsonp_url in matches:
                    if self.stop_event.is_set():
                        break
                    
                    if self.status_callback:
                        self.status_callback(f"Downloading page {page_num}")
                    
                    if self._download_image(jsonp_url, page_num):
                        page_num += 1
            
            # Convert to PDF
            if self.images:
                if self.status_callback:
                    self.status_callback("Converting to PDF...")
                
                if self._convert_to_pdf(title):
                    if self.status_callback:
                        self.status_callback("PDF created successfully!")
                    return True
            
            return bool(self.images)
            
        except Exception as e:
            self._log(f"Error in download: {str(e)}")
            return False
    
    def stop(self):
        """Stop the download process."""
        self.stop_event.set()


# ============================================================================
# GUI Application
# ============================================================================

class DownloaderGUI:
    """Main GUI application."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Scrimego")
        self.root.geometry("1000x800")
        
        # Download queue and threads
        self.download_queue: queue.Queue = queue.Queue()
        self.active_downloads: Dict[str, threading.Thread] = {}
        self.download_objects: Dict[str, Any] = {}
        
        # Statistics
        self.total_downloads = 0
        self.successful_downloads = 0
        self.failed_downloads = 0
        
        # Settings
        self.use_tor = tk.BooleanVar(value=False)
        self.debug_mode = tk.BooleanVar(value=False)
        self.separate_folders = tk.BooleanVar(value=False)
        self.enable_retry = tk.BooleanVar(value=True)
        self.skip_existing = tk.BooleanVar(value=True)
        self.force_extension = tk.StringVar(value="")
        self.output_dir = tk.StringVar(value=os.getcwd())
        
        self._create_widgets()
        self._check_dependencies()
        
        # Start queue processor
        self._process_queue()
    
    def _create_widgets(self):
        """Create all GUI widgets."""
        # Configure grid weights for main window
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Main container using PanedWindow for better layout
        main_paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_paned.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)
        
        # Top Section: Input and Settings
        top_frame = ttk.Frame(main_paned)
        main_paned.add(top_frame, weight=1)
        
        top_frame.columnconfigure(0, weight=1)
        
        # Input Section
        input_frame = ttk.LabelFrame(top_frame, text="Download Links", padding="10")
        input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)
        
        # URL input mode selection
        self.input_mode = tk.StringVar(value="manual")
        
        mode_frame = ttk.Frame(input_frame)
        mode_frame.grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
        
        ttk.Radiobutton(mode_frame, text="Enter URLs manually", variable=self.input_mode,
                       value="manual", command=self._toggle_input_mode).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        ttk.Radiobutton(mode_frame, text="Load from text file", variable=self.input_mode,
                       value="file", command=self._toggle_input_mode).grid(row=0, column=1, sticky=tk.W)
        
        # Manual input frame
        self.manual_frame = ttk.Frame(input_frame)
        self.manual_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.manual_frame.columnconfigure(0, weight=1)
        
        ttk.Label(self.manual_frame, text="Enter URLs (one per line):").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        self.url_text = scrolledtext.ScrolledText(self.manual_frame, height=8)
        self.url_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 5))
        
        self.manual_frame.rowconfigure(1, weight=1)
        
        # File input frame
        self.file_frame = ttk.Frame(input_frame)
        self.file_frame.columnconfigure(0, weight=1)
        
        ttk.Label(self.file_frame, text="Text file path:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        file_path_frame = ttk.Frame(self.file_frame)
        file_path_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        file_path_frame.columnconfigure(0, weight=1)
        
        self.file_path = tk.StringVar()
        file_entry = ttk.Entry(file_path_frame, textvariable=self.file_path)
        file_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(file_path_frame, text="Browse", command=self._browse_file).grid(row=0, column=1)
        
        # Preview area for file contents
        ttk.Label(self.file_frame, text="File contents preview:").grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        self.file_preview = scrolledtext.ScrolledText(self.file_frame, height=8, state="disabled")
        self.file_preview.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Settings Section
        settings_frame = ttk.LabelFrame(top_frame, text="Settings", padding="10")
        settings_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        settings_frame.columnconfigure(1, weight=1)
        
        # Row 0: Output directory
        ttk.Label(settings_frame, text="Output Directory:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10), pady=(0, 5))
        ttk.Entry(settings_frame, textvariable=self.output_dir).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=(0, 5))
        ttk.Button(settings_frame, text="Browse", command=self._browse_output).grid(row=0, column=2, pady=(0, 5))
        
        # Row 1: Checkbuttons
        ttk.Checkbutton(settings_frame, text="Use Tor Network", variable=self.use_tor).grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        ttk.Checkbutton(settings_frame, text="Debug Mode", variable=self.debug_mode).grid(row=1, column=1, sticky=tk.W, pady=(0, 5))
        ttk.Checkbutton(settings_frame, text="Separate Folders by Platform", 
                       variable=self.separate_folders).grid(row=1, column=2, sticky=tk.W, pady=(0, 5))
        
        # Row 2: More checkbuttons
        ttk.Checkbutton(settings_frame, text="Enable Retry (3 attempts)", 
                       variable=self.enable_retry).grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        ttk.Checkbutton(settings_frame, text="Auto-rename if file exists", 
                       variable=self.skip_existing).grid(row=2, column=1, sticky=tk.W, pady=(0, 5))
        
        # Row 3: Extension forcing
        ttk.Label(settings_frame, text="Force Extension (optional):").grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=(0, 5))
        ext_entry = ttk.Entry(settings_frame, textvariable=self.force_extension, width=10)
        ext_entry.grid(row=3, column=1, sticky=tk.W, padx=(0, 10), pady=(0, 5))
        ttk.Label(settings_frame, text="e.g.: txt, pdf, html, md, csv, json, xml", 
                 foreground="gray").grid(row=3, column=2, sticky=tk.W, pady=(0, 5))
        
        # Control Buttons
        button_frame = ttk.Frame(top_frame)
        button_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        button_frame.columnconfigure(0, weight=1)
        
        btn_subframe = ttk.Frame(button_frame)
        btn_subframe.grid(row=0, column=0, sticky=tk.W)
        
        self.download_btn = ttk.Button(btn_subframe, text="Start Download", command=self._start_download)
        self.download_btn.grid(row=0, column=0, padx=(0, 5))
        
        self.stop_btn = ttk.Button(btn_subframe, text="Stop All", command=self._stop_all, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=(0, 5))
        
        ttk.Button(btn_subframe, text="Clear Downloads", command=self._clear_downloads).grid(row=0, column=2, padx=(0, 5))
        ttk.Button(btn_subframe, text="Clear Log", command=self._clear_log).grid(row=0, column=3, padx=(0, 5))
        
        # Status label
        self.status_label = ttk.Label(button_frame, text="Ready", foreground="green")
        self.status_label.grid(row=0, column=1, sticky=tk.E)
        
        # Bottom Section: Downloads and Log
        bottom_frame = ttk.Frame(main_paned)
        main_paned.add(bottom_frame, weight=2)
        
        bottom_frame.columnconfigure(0, weight=1)
        bottom_frame.rowconfigure(0, weight=1)
        
        # Create Notebook for tabs
        self.notebook = ttk.Notebook(bottom_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Download List Tab
        download_tab = ttk.Frame(self.notebook)
        self.notebook.add(download_tab, text="Active Downloads")
        download_tab.columnconfigure(0, weight=1)
        download_tab.rowconfigure(0, weight=1)
        
        # Treeview for downloads with scrollbar
        tree_frame = ttk.Frame(download_tab)
        tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        self.download_tree = ttk.Treeview(tree_frame, columns=("Platform", "Status"), show="tree headings", height=12)
        self.download_tree.heading("#0", text="URL/File")
        self.download_tree.heading("Platform", text="Platform")
        self.download_tree.heading("Status", text="Status")
        
        self.download_tree.column("#0", width=400)
        self.download_tree.column("Platform", width=100)
        self.download_tree.column("Status", width=300)
        
        tree_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.download_tree.yview)
        self.download_tree.configure(yscrollcommand=tree_scrollbar.set)
        
        self.download_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Debug Log Tab
        log_tab = ttk.Frame(self.notebook)
        self.notebook.add(log_tab, text="Debug Log")
        log_tab.columnconfigure(0, weight=1)
        log_tab.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_tab, height=20, state="disabled")
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Statistics Tab
        stats_tab = ttk.Frame(self.notebook)
        self.notebook.add(stats_tab, text="Statistics")
        stats_tab.columnconfigure(0, weight=1)
        
        # Statistics labels
        self.stats_frame = ttk.LabelFrame(stats_tab, text="Download Statistics", padding="10")
        self.stats_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=10, pady=10)
        self.stats_frame.columnconfigure(1, weight=1)
        
        ttk.Label(self.stats_frame, text="Total URLs processed:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.stats_total = ttk.Label(self.stats_frame, text="0")
        self.stats_total.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(self.stats_frame, text="Successful downloads:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.stats_success = ttk.Label(self.stats_frame, text="0", foreground="green")
        self.stats_success.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(self.stats_frame, text="Failed downloads:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.stats_failed = ttk.Label(self.stats_frame, text="0", foreground="red")
        self.stats_failed.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(self.stats_frame, text="Active downloads:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.stats_active = ttk.Label(self.stats_frame, text="0", foreground="blue")
        self.stats_active.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Initially hide file input frame
        self._toggle_input_mode()
    
    def _toggle_input_mode(self):
        """Toggle between manual and file input modes."""
        if self.input_mode.get() == "manual":
            self.file_frame.grid_forget()
            self.manual_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        else:
            self.manual_frame.grid_forget()
            self.file_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            # Load and preview file if it exists
            filepath = self.file_path.get()
            if filepath and os.path.exists(filepath):
                self._preview_file(filepath)
    
    def _preview_file(self, filepath: str):
        """Preview contents of the selected file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.file_preview.configure(state="normal")
            self.file_preview.delete(1.0, tk.END)
            self.file_preview.insert(tk.END, content)
            
            # Count lines
            lines = [line.strip() for line in content.split('\n') if line.strip()]
            self._log(f"Loaded {len(lines)} URLs from {os.path.basename(filepath)}")
            
            self.file_preview.configure(state="disabled")
        except Exception as e:
            self._log(f"Error loading file: {str(e)}")
    
    def _browse_file(self):
        """Browse for text file."""
        filename = filedialog.askopenfilename(
            title="Select URL list file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.file_path.set(filename)
            self._preview_file(filename)
    
    def _browse_output(self):
        """Browse for output directory."""
        directory = filedialog.askdirectory(title="Select output directory")
        if directory:
            self.output_dir.set(directory)
            self._log(f"Output directory set to: {directory}")
    
    def _check_dependencies(self):
        """Check for optional dependencies."""
        warnings = []
        
        if not HAS_BS4:
            warnings.append("BeautifulSoup4 not installed - MediaFire and Scribd downloads may not work")
        
        if not HAS_IMG2PDF:
            warnings.append("img2pdf not installed - Scribd PDF conversion will not work")
        
        if not HAS_SOCKS:
            warnings.append("PySocks not installed - Tor support unavailable")
        
        if warnings:
            self._log("⚠️ Missing dependencies:")
            for warning in warnings:
                self._log(f"  - {warning}")
            self._log("Install with: pip install beautifulsoup4 img2pdf PySocks")
    
    def _log(self, message: str):
        """Add message to log."""
        if self.debug_mode.get() or message.startswith("⚠️") or message.startswith("✓") or message.startswith("✗"):
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.log_text.configure(state="normal")
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.log_text.see(tk.END)
            self.log_text.configure(state="disabled")
    
    def _clear_log(self):
        """Clear the log."""
        self.log_text.configure(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state="disabled")
    
    def _clear_downloads(self):
        """Clear completed downloads from the list."""
        items = self.download_tree.get_children()
        
        for item in items:
            status = self.download_tree.set(item, "Status")
            if "Completed" in status or "Failed" in status or "Error" in status:
                self.download_tree.delete(item)
        
        self._log("✓ Cleared completed downloads from list")
    
    def _get_urls(self) -> List[str]:
        """Get URLs from input."""
        if self.input_mode.get() == "manual":
            text = self.url_text.get(1.0, tk.END).strip()
            return [url.strip() for url in text.split("\n") if url.strip()]
        else:
            filepath = self.file_path.get()
            if not filepath or not os.path.exists(filepath):
                return []
            
            try:
                with open(filepath, "r", encoding='utf-8') as f:
                    return [url.strip() for url in f.readlines() if url.strip()]
            except Exception as e:
                self._log(f"Error reading file: {str(e)}")
                return []
    
    def _update_stats(self):
        """Update statistics display."""
        self.stats_total.config(text=str(self.total_downloads))
        self.stats_success.config(text=str(self.successful_downloads))
        self.stats_failed.config(text=str(self.failed_downloads))
        self.stats_active.config(text=str(len(self.active_downloads)))
    
    def _start_download(self):
        """Start download process."""
        urls = self._get_urls()
        
        if not urls:
            messagebox.showwarning("No URLs", "Please enter at least one URL")
            return
        
        output_dir = self.output_dir.get()
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except Exception as e:
                messagebox.showerror("Error", f"Could not create output directory: {str(e)}")
                return
        
        self.download_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        
        # Add URLs to queue
        for url in urls:
            self.download_queue.put(url)
            self.total_downloads += 1
        
        self._update_stats()
        self._log(f"✓ Added {len(urls)} URLs to download queue")
    
    def _process_queue(self):
        """Process download queue."""
        try:
            while not self.download_queue.empty() and len(self.active_downloads) < 3:
                url = self.download_queue.get_nowait()
                self._start_single_download(url)
        except queue.Empty:
            pass
        
        # Update stats
        self._update_stats()
        
        # Check again after 500ms
        self.root.after(500, self._process_queue)
    
    def _start_single_download(self, url: str):
        """Start a single download."""
        platform = detect_platform(url)
        
        if not platform:
            self._log(f"✗ Unknown platform for URL: {url}")
            self.failed_downloads += 1
            return
        
        # Add to tree
        item_id = self.download_tree.insert("", tk.END, text=url[:80] + "..." if len(url) > 80 else url, 
                                           values=(platform.title(), "Starting..."))
        
        def download_thread():
            try:
                output_dir = self.output_dir.get()
                use_tor = self.use_tor.get()
                separate_folders = self.separate_folders.get()
                force_ext = self.force_extension.get().strip() or None
                enable_retry = self.enable_retry.get()
                skip_existing = self.skip_existing.get()
                
                def debug_callback(msg):
                    self._log(msg)
                
                def status_callback(msg):
                    try:
                        self.download_tree.set(item_id, "Status", msg)
                    except:
                        pass
                
                # Create appropriate downloader
                if platform == "gofile":
                    downloader = GoFileDownloader(url, output_dir, use_tor=use_tor,
                                                 debug_callback=debug_callback,
                                                 status_callback=status_callback,
                                                 separate_folders=separate_folders,
                                                 force_extension=force_ext,
                                                 enable_retry=enable_retry,
                                                 skip_existing=skip_existing)
                elif platform == "mediafire":
                    downloader = MediaFireDownloader(url, output_dir, use_tor=use_tor,
                                                    debug_callback=debug_callback,
                                                    status_callback=status_callback,
                                                    separate_folders=separate_folders,
                                                    force_extension=force_ext,
                                                    enable_retry=enable_retry,
                                                    skip_existing=skip_existing)
                elif platform == "scribd":
                    downloader = ScribdDownloader(url, output_dir, use_tor=use_tor,
                                                 debug_callback=debug_callback,
                                                 status_callback=status_callback,
                                                 separate_folders=separate_folders,
                                                 force_extension=force_ext,
                                                 enable_retry=enable_retry,
                                                 skip_existing=skip_existing)
                else:
                    self._log(f"✗ Unsupported platform: {platform}")
                    self.download_tree.set(item_id, "Status", "Unsupported")
                    self.failed_downloads += 1
                    return
                
                self.download_objects[item_id] = downloader
                
                # Start download
                success = downloader.download()
                
                if success:
                    self.download_tree.set(item_id, "Status", "✓ Completed")
                    self._log(f"✓ Completed: {url}")
                    self.successful_downloads += 1
                else:
                    self.download_tree.set(item_id, "Status", "✗ Failed")
                    self._log(f"✗ Failed: {url}")
                    self.failed_downloads += 1
                
            except Exception as e:
                self.download_tree.set(item_id, "Status", f"✗ Error: {str(e)}")
                self._log(f"✗ Error downloading {url}: {str(e)}")
                self.failed_downloads += 1
            
            finally:
                if item_id in self.download_objects:
                    del self.download_objects[item_id]
                if item_id in self.active_downloads:
                    del self.active_downloads[item_id]
                
                # Update stats
                self._update_stats()
                
                # Re-enable download button if no active downloads
                if not self.active_downloads:
                    self.download_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
        
        # Start thread
        thread = threading.Thread(target=download_thread, daemon=True)
        self.active_downloads[item_id] = thread
        thread.start()
    
    def _stop_all(self):
        """Stop all active downloads."""
        for downloader in self.download_objects.values():
            downloader.stop()
        
        self._log("⚠️ Stopping all downloads...")
        
        # Clear queue
        while not self.download_queue.empty():
            try:
                self.download_queue.get_nowait()
            except queue.Empty:
                break
        
        self.download_btn.config(state="normal")
        self.stop_btn.config(state="disabled")


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point."""
    root = tk.Tk()
    app = DownloaderGUI(root)
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")
    
    root.mainloop()


if __name__ == "__main__":
    main()
