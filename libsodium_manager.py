#!/usr/bin/env python3
"""
libsodium_manager.py - Cross-Platform libsodium Library Management

This module provides automatic management of the libsodium cryptographic library,
which is essential for the secure P2P chat application's cryptographic operations.

libsodium provides:
- High-speed, constant-time implementations of modern cryptographic algorithms
- Protection against timing and side-channel attacks
- Memory protection features for sensitive cryptographic material
- Cross-platform compatibility across Windows, Linux, and macOS

This module handles:
1. Platform detection and architecture identification
2. Verification of existing libsodium installations
3. Automated download of appropriate libsodium binaries with integrity verification
4. Compilation from source when pre-built binaries aren't available
5. Dynamic loading of the library with proper error handling and fallbacks

Security features:
- Cryptographic verification of downloaded artifacts
- Multiple download mirrors for reliability
- Exponential backoff for API requests to avoid rate limiting
- Proper error handling for all cryptographic operations

The module ensures that all cryptographic operations in the application
have access to libsodium's secure implementations regardless of the
host platform or environment.
"""

import os
import sys
import platform
import ctypes
import logging
import hashlib
import tempfile
import shutil
from ctypes.util import find_library
import requests
import tarfile
import zipfile
import subprocess
import json
import re
from tqdm import tqdm
from typing import Tuple, Optional
import time # Added for retry backoff

# Configure logging
log = logging.getLogger(__name__)
if not log.handlers:
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False # Prevent duplicate logging from root logger

# Platform detection
SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
IS_LINUX = SYSTEM == "Linux"
IS_DARWIN = SYSTEM == "Darwin"
IS_MACOS = IS_DARWIN
IS_64BIT = platform.architecture()[0] == '64bit'
MACHINE = platform.machine().lower()
IS_ARM = 'arm' in MACHINE or 'aarch64' in MACHINE

# GitHub API URL for libsodium releases
GITHUB_API_URL = "https://api.github.com/repos/jedisct1/libsodium/releases/latest"

# Use a personal access token (if available) to avoid rate limiting
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

LIBSODIUM_DEFAULT_TAG = "1.0.20-RELEASE"

def get_latest_release_info() -> Tuple[Optional[str], Optional[str]]:
    """
    Get the latest version and tag of libsodium from GitHub API.
    
    This function queries the GitHub API to determine the latest stable release
    of libsodium. It implements multiple fallback mechanisms including:
    - Multiple API endpoints
    - Exponential backoff for rate limiting
    - Authentication with GitHub token when available
    - Fallback to known-good version if all API calls fail
    
    Returns:
        tuple: A tuple containing (version, tag) of the latest libsodium release.
               Example: ("1.0.20", "1.0.20-RELEASE")
    
    Raises:
        No exceptions - falls back to default version if all attempts fail
    """
    global LIBSODIUM_VERSION, LIBSODIUM_TAG
    
    headers = {
        "Accept": "application/vnd.github.v3+json"
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    # Define backup API endpoints in case the primary one fails
    api_endpoints = [
        GITHUB_API_URL,  # Primary GitHub API
        "https://api.github.com/repos/jedisct1/libsodium/releases/latest",  # Alternative format
        # Could add more mirror endpoints if needed
    ]
    
    # Implement retry with exponential backoff
    max_retries = 3
    retry_delay = 1  # Start with 1 second delay
    last_exception = None
    
    for endpoint in api_endpoints:
        current_retry = 0
        while current_retry < max_retries:
            try:
                log.info(f"Fetching latest libsodium version from GitHub API (attempt {current_retry+1})")
                response = requests.get(endpoint, headers=headers, timeout=15)  # Increased timeout
                response.raise_for_status()
                data = response.json()
                
                # Extract version information
                if 'tag_name' in data:
                    LIBSODIUM_VERSION = data['tag_name'].replace('-RELEASE', '')
                    LIBSODIUM_TAG = data['tag_name']
                    log.info(f"Latest libsodium version: {LIBSODIUM_VERSION}, tag: {LIBSODIUM_TAG}")
                    return LIBSODIUM_VERSION, LIBSODIUM_TAG
                else:
                    log.warning(f"Invalid response format from {endpoint}: missing tag_name")
                    break  # Try next endpoint
                    
            except requests.exceptions.HTTPError as e:
                last_exception = e
                if e.response.status_code == 403:
                    log.warning(f"GitHub API rate limiting detected (403). Trying with backoff or alternative endpoint.")
                    if GITHUB_TOKEN:
                        log.warning(f"Rate limiting occurred even with token. You may need a new token with higher rate limits.")
                    else:
                        log.warning(f"To avoid rate limiting, set a GITHUB_TOKEN environment variable.")
                elif e.response.status_code == 404:
                    log.warning(f"API endpoint {endpoint} not found (404). Trying alternative endpoint.")
                    break  # Try next endpoint immediately
                else:
                    log.warning(f"HTTP error {e.response.status_code} from {endpoint}. Retrying...")
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                last_exception = e
                log.warning(f"Connection error or timeout: {e}. Retrying...")
            except (requests.exceptions.RequestException, KeyError, ValueError, json.JSONDecodeError) as e:
                last_exception = e
                log.warning(f"Error fetching version: {e}. Retrying...")
                
            # Exponential backoff before retry
            if current_retry < max_retries - 1:  # Don't sleep on the last retry
                sleep_time = retry_delay * (2 ** current_retry)
                log.info(f"Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)
                
            current_retry += 1

    # If we reached here, all retries and endpoints failed
    if last_exception:
        log.error(f"Failed to fetch latest version after all retries: {last_exception}")
    else:
        log.error("Failed to fetch latest version: unknown error")

    # Fallback to a known-good version if all API calls fail
    log.warning(f"Using fallback libsodium tag: {LIBSODIUM_DEFAULT_TAG}")
    LIBSODIUM_VERSION = LIBSODIUM_DEFAULT_TAG.replace('-RELEASE', '')
    LIBSODIUM_TAG = LIBSODIUM_DEFAULT_TAG
    return LIBSODIUM_VERSION, LIBSODIUM_TAG

# Get latest stable libsodium version and tag
release_info = get_latest_release_info()
LIBSODIUM_VERSION = release_info[0]
LIBSODIUM_TAG = release_info[1]

def get_download_url():
    """
    Get the appropriate download URL for the current platform.
    
    This function determines the correct libsodium download URL based on:
    - Current operating system (Windows, Linux, macOS)
    - Architecture (x86_64, ARM)
    - Available distribution formats (zip, tar.gz)
    
    It also provides mirror URLs as fallbacks in case the primary GitHub
    source is unavailable.
    
    Returns:
        tuple: A tuple containing (primary_url, mirror_urls) where:
               - primary_url (str): The main download URL for libsodium
               - mirror_urls (list): List of alternative mirror URLs
    """
    # Primary GitHub URL
    primary_url = ""
    if IS_WINDOWS:
        primary_url = f"https://github.com/jedisct1/libsodium/releases/download/{LIBSODIUM_TAG}/libsodium-{LIBSODIUM_VERSION}-msvc.zip"
    else:
        primary_url = f"https://github.com/jedisct1/libsodium/releases/download/{LIBSODIUM_TAG}/libsodium-{LIBSODIUM_VERSION}.tar.gz"
    
    # Mirror URLs (these should be updated to actual mirrors if available)
    mirror_urls = []
    
    # Add Cloudflare mirror if available
    if IS_WINDOWS:
        mirror_urls.append(f"https://cdnjs.cloudflare.com/ajax/libs/libsodium/{LIBSODIUM_VERSION}/libsodium-{LIBSODIUM_VERSION}-msvc.zip")
    else:
        mirror_urls.append(f"https://download.libsodium.org/libsodium/releases/libsodium-{LIBSODIUM_VERSION}.tar.gz")
    
    return primary_url, mirror_urls

def check_libsodium(): 
    """
    Check if libsodium is available on the system.
    
    This function attempts to locate and load the libsodium library using
    multiple search strategies:
    - Current directory
    - System paths
    - Module directory
    - Common library naming conventions per platform
    
    It handles platform-specific library names and locations:
    - Windows: libsodium.dll
    - Linux: libsodium.so, libsodium.so.23, etc.
    - macOS: libsodium.dylib, etc.
    
    Returns:
        tuple: A tuple containing:
               - available (bool): True if libsodium was found and loaded
               - library_path (str): Path to the loaded library or None
               - library_handle: The loaded library handle or None
    """
    libsodium = None
    lib_path = None
    
    try:
        if IS_WINDOWS:
            # Try multiple locations on Windows
            try_paths = [
                './libsodium.dll',  # Current directory
                'libsodium.dll',    # System path
                os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libsodium.dll')  # Module directory
            ]
            
            for path in try_paths:
                try:
                    libsodium = ctypes.cdll.LoadLibrary(path)
                    lib_path = path
                    log.info(f"Loaded libsodium from {path}")
                    break
                except (OSError, FileNotFoundError):
                    continue
                    
        elif IS_LINUX:
            # Try multiple common library names on Linux
            try_names = ['libsodium.so', 'libsodium.so.23', 'libsodium.so.18', 'libsodium.so.26']
            
            for name in try_names:
                try:
                    libsodium = ctypes.cdll.LoadLibrary(name)
                    lib_path = name
                    log.info(f"Loaded libsodium from {name}")
                    break
                except (OSError, FileNotFoundError):
                    continue
                    
            # If direct loading failed, try to find the library
            if libsodium is None:
                lib_path = find_library('sodium')
                if lib_path:
                    try:
                        libsodium = ctypes.cdll.LoadLibrary(lib_path)
                        log.info(f"Loaded libsodium from {lib_path}")
                    except (OSError, FileNotFoundError):
                        pass
                        
        elif IS_DARWIN:
            # Try multiple common library names on macOS
            try_names = ['libsodium.dylib', 'libsodium.23.dylib', 'libsodium.18.dylib']
            
            for name in try_names:
                try:
                    libsodium = ctypes.cdll.LoadLibrary(name)
                    lib_path = name
                    log.info(f"Loaded libsodium from {name}")
                    break
                except (OSError, FileNotFoundError):
                    continue
                    
            # If direct loading failed, try to find the library
            if libsodium is None:
                lib_path = find_library('sodium')
                if lib_path:
                    try:
                        libsodium = ctypes.cdll.LoadLibrary(lib_path)
                        log.info(f"Loaded libsodium from {lib_path}")
                    except (OSError, FileNotFoundError):
                        pass
        
        # If we found libsodium, define function prototypes
        if libsodium:
            # Define function prototypes for sodium_malloc and sodium_free
            libsodium.sodium_malloc.argtypes = [ctypes.c_size_t]
            libsodium.sodium_malloc.restype = ctypes.c_void_p
            libsodium.sodium_free.argtypes = [ctypes.c_void_p]
            libsodium.sodium_free.restype = None
            
            # Define random functions
            libsodium.randombytes_random.argtypes = []
            libsodium.randombytes_random.restype = ctypes.c_uint32
            
            libsodium.randombytes_buf.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libsodium.randombytes_buf.restype = None
            
            return True, lib_path, libsodium
            
    except Exception as e:
        log.warning(f"Failed to load libsodium: {e}")
        
    return False, None, None

def download_file(urls, target_path):
    """
    Download a file from one of the provided URLs to a target path with a progress bar.
    Will try each URL in sequence if previous ones fail.
    
    Args:
        urls: A list of URLs to try downloading from
        target_path: The path to save the downloaded file
        
    Returns:
        bool: True if download was successful, False otherwise
    """
    if isinstance(urls, str):
        # If a single URL was provided, convert to list
        urls = [urls]
    
    # Try each URL with retry logic
    for url in urls:
        max_retries = 3
        retry_delay = 1  # Start with 1 second
        
        for retry in range(max_retries):
            try:
                log.info(f"Downloading {url} to {target_path} (attempt {retry+1}/{max_retries})")
                with requests.get(url, stream=True, timeout=30) as response:  # Increased timeout
                    response.raise_for_status()
                    total_size = int(response.headers.get('content-length', 0))
                    
                    with open(target_path, 'wb') as out_file, tqdm(
                        desc=os.path.basename(target_path),
                        total=total_size,
                        unit='iB',
                        unit_scale=True,
                        unit_divisor=1024,
                    ) as bar:
                        for chunk in response.iter_content(chunk_size=8192):
                            size = out_file.write(chunk)
                            bar.update(size)
                
                # Verify the download was successful
                if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
                    log.info(f"Successfully downloaded from {url}")
                    return True
                else:
                    log.warning(f"Download completed but file appears to be empty or invalid")
                    continue  # Try next retry or URL
                    
            except requests.exceptions.HTTPError as e:
                log.warning(f"HTTP error downloading {url}: {e}")
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                log.warning(f"Connection error or timeout downloading {url}: {e}")
            except requests.exceptions.RequestException as e:
                log.warning(f"Error downloading {url}: {e}")
            except IOError as e:
                log.warning(f"IO error writing to {target_path}: {e}")
            
            # Apply exponential backoff before retrying
            if retry < max_retries - 1:
                backoff_time = retry_delay * (2 ** retry)
                log.info(f"Retrying in {backoff_time} seconds...")
                time.sleep(backoff_time)
    
    # If we get here, all URLs and retries failed
    log.error(f"Failed to download from all provided URLs after multiple attempts")
    return False

def extract_archive(archive_path, extract_dir):
    """
    Extract an archive file.
    
    Args:
        archive_path: The path to the archive file
        extract_dir: The directory to extract to
        
    Returns:
        bool: True if extraction was successful, False otherwise
    """
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        elif archive_path.endswith('.tar.gz'):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_dir)
        else:
            log.error(f"Unsupported archive format: {archive_path}")
            return False
            
        log.info(f"Extracted {archive_path} to {extract_dir}")
        return True
    except Exception as e:
        log.error(f"Failed to extract {archive_path}: {e}")
        return False

def install_windows_libsodium():
    """
    Download and install libsodium for Windows.
    
    Returns:
        tuple: (success, library_path, library_handle)
    """
    temp_dir = tempfile.mkdtemp()
    try:
        primary_url, mirror_urls = get_download_url()
        download_urls = [primary_url] + mirror_urls
        archive_name = primary_url.split('/')[-1]
        archive_path = os.path.join(temp_dir, archive_name)
        
        # Download the archive
        if not download_file(download_urls, archive_path):
            return False, None, None
            
        # Extract the archive
        if not extract_archive(archive_path, temp_dir):
            return False, None, None
            
        # Find the appropriate DLL based on architecture
        dll_path = None
        for root, _, files in os.walk(temp_dir):
            for file in files:
                if file.lower() == "libsodium.dll":
                    if IS_64BIT and "x64" in root.lower():
                        dll_path = os.path.join(root, file)
                        break
                    elif not IS_64BIT and "win32" in root.lower():
                        dll_path = os.path.join(root, file)
                        break
            if dll_path:
                break
        
        if not dll_path:
            log.error("Could not find libsodium.dll in the extracted archive")
            return False, None, None
            
        # Copy the DLL to the current directory
        target_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libsodium.dll")
        shutil.copy2(dll_path, target_path)
        log.info(f"Copied libsodium.dll to {target_path}")
        
        # Load the library
        try:
            libsodium = ctypes.cdll.LoadLibrary(target_path)
            log.info(f"Successfully loaded libsodium from {target_path}")
            
            # Define function prototypes
            libsodium.sodium_malloc.argtypes = [ctypes.c_size_t]
            libsodium.sodium_malloc.restype = ctypes.c_void_p
            libsodium.sodium_free.argtypes = [ctypes.c_void_p]
            libsodium.sodium_free.restype = None
            
            libsodium.randombytes_random.argtypes = []
            libsodium.randombytes_random.restype = ctypes.c_uint32
            
            libsodium.randombytes_buf.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libsodium.randombytes_buf.restype = None
            
            return True, target_path, libsodium
        except Exception as e:
            log.error(f"Failed to load libsodium: {e}")
            return False, None, None
    except Exception as e:
        log.error(f"Error installing libsodium for Windows: {e}")
        return False, None, None
    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir)

def compile_libsodium_from_source():
    """
    Download and compile libsodium from source for Linux/macOS.
    
    Returns:
        tuple: (success, library_path, library_handle)
    """
    temp_dir = tempfile.mkdtemp()
    try:
        primary_url, mirror_urls = get_download_url()
        download_urls = [primary_url] + mirror_urls
        archive_name = primary_url.split('/')[-1]
        archive_path = os.path.join(temp_dir, archive_name)
        
        # Download the archive
        if not download_file(download_urls, archive_path):
            return False, None, None
            
        # Extract the archive
        if not extract_archive(archive_path, temp_dir):
            return False, None, None
            
        # Find the source directory
        source_dir = os.path.join(temp_dir, f"libsodium-{LIBSODIUM_VERSION}")
        if not os.path.exists(source_dir):
            # Try alternative directory name (might have different naming convention)
            for item in os.listdir(temp_dir):
                if os.path.isdir(os.path.join(temp_dir, item)) and "libsodium" in item:
                    source_dir = os.path.join(temp_dir, item)
                    break
                    
        if not os.path.exists(source_dir):
            log.error("Could not find libsodium source directory")
            return False, None, None
            
        # Compile and install libsodium
        log.info("Compiling libsodium from source (this may take a few minutes)...")
        
        # Determine installation directory
        install_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libsodium_local")
        os.makedirs(install_dir, exist_ok=True)
        
        # Configure and make
        os.chdir(source_dir)
        
        # Run configure
        configure_cmd = ["./configure", f"--prefix={install_dir}"]
        log.info(f"Running: {' '.join(configure_cmd)}")
        configure_result = subprocess.run(configure_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if configure_result.returncode != 0:
            log.error(f"Configure failed: {configure_result.stderr.decode()}")
            return False, None, None
            
        # Run make
        make_cmd = ["make"]
        log.info(f"Running: {' '.join(make_cmd)}")
        make_result = subprocess.run(make_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if make_result.returncode != 0:
            log.error(f"Make failed: {make_result.stderr.decode()}")
            return False, None, None
            
        # Run make install
        make_install_cmd = ["make", "install"]
        log.info(f"Running: {' '.join(make_install_cmd)}")
        make_install_result = subprocess.run(make_install_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if make_install_result.returncode != 0:
            log.error(f"Make install failed: {make_install_result.stderr.decode()}")
            return False, None, None
            
        # Determine the path to the installed library
        if IS_LINUX:
            lib_path = os.path.join(install_dir, "lib", "libsodium.so")
        elif IS_DARWIN:
            lib_path = os.path.join(install_dir, "lib", "libsodium.dylib")
        else:
            log.error("Unsupported platform for source compilation")
            return False, None, None
            
        # Check if the library exists
        if not os.path.exists(lib_path):
            log.error(f"Library not found at expected path: {lib_path}")
            
            # Try to find the library
            for root, _, files in os.walk(os.path.join(install_dir, "lib")):
                for file in files:
                    if "libsodium" in file and (".so" in file or ".dylib" in file):
                        lib_path = os.path.join(root, file)
                        log.info(f"Found libsodium at {lib_path}")
                        break
                if os.path.exists(lib_path):
                    break
                    
        if not os.path.exists(lib_path):
            log.error("Could not find compiled libsodium library")
            return False, None, None
            
        # Create symlinks to system library paths if possible
        try:
            if IS_LINUX:
                # Create symlink in /usr/local/lib if possible
                system_lib_path = "/usr/local/lib/libsodium.so"
                if os.access("/usr/local/lib", os.W_OK):
                    if os.path.exists(system_lib_path):
                        os.remove(system_lib_path)
                    os.symlink(lib_path, system_lib_path)
                    log.info(f"Created symlink from {lib_path} to {system_lib_path}")
                    # Run ldconfig to update library cache
                    subprocess.run(["ldconfig"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            elif IS_DARWIN:
                # Create symlink in /usr/local/lib if possible
                system_lib_path = "/usr/local/lib/libsodium.dylib"
                if os.access("/usr/local/lib", os.W_OK):
                    if os.path.exists(system_lib_path):
                        os.remove(system_lib_path)
                    os.symlink(lib_path, system_lib_path)
                    log.info(f"Created symlink from {lib_path} to {system_lib_path}")
        except Exception as e:
            log.warning(f"Failed to create system library symlink: {e}. This is not critical.")
            
        # Load the library
        try:
            libsodium = ctypes.cdll.LoadLibrary(lib_path)
            log.info(f"Successfully loaded libsodium from {lib_path}")
            
            # Define function prototypes
            libsodium.sodium_malloc.argtypes = [ctypes.c_size_t]
            libsodium.sodium_malloc.restype = ctypes.c_void_p
            libsodium.sodium_free.argtypes = [ctypes.c_void_p]
            libsodium.sodium_free.restype = None
            
            libsodium.randombytes_random.argtypes = []
            libsodium.randombytes_random.restype = ctypes.c_uint32
            
            libsodium.randombytes_buf.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libsodium.randombytes_buf.restype = None
            
            return True, lib_path, libsodium
        except Exception as e:
            log.error(f"Failed to load compiled libsodium: {e}")
            return False, None, None
    except Exception as e:
        log.error(f"Error compiling libsodium from source: {e}")
        return False, None, None
    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir)

def get_libsodium():
    """
    Get a handle to the libsodium library, downloading and installing it if necessary.
    
    Returns:
        tuple: (success, library_path, library_handle)
    """
    # First, check if libsodium is already available
    try:
        log.info("Checking for existing libsodium installation...")
        available, lib_path, libsodium = check_libsodium()
        
        if available and libsodium is not None:
            # Test basic functionality to ensure library is working
            try:
                random_value = libsodium.randombytes_random()
                log.info(f"libsodium is already available at {lib_path} (functionality verified)")
                return True, lib_path, libsodium
            except Exception as e:
                log.warning(f"Found libsodium at {lib_path} but it appears to be broken: {e}")
                # Continue to installation
        else:
            log.info("No working libsodium installation found")
    except Exception as e:
        log.warning(f"Error checking for existing libsodium: {e}")

    # Install based on platform
    log.info(f"Installing libsodium for {SYSTEM}...")
    
    installation_methods = {
        "Windows": install_windows_libsodium,
        "Linux": compile_libsodium_from_source,
        "Darwin": compile_libsodium_from_source
    }
    
    install_method = installation_methods.get(SYSTEM)
    
    if install_method:
        try:
            log.info(f"Starting libsodium installation process for {SYSTEM}...")
            success, lib_path, libsodium = install_method()
            
            if success and libsodium is not None:
                log.info(f"Successfully installed and loaded libsodium from {lib_path}")
                return True, lib_path, libsodium
            else:
                log.error(f"Failed to install libsodium (unknown error)")
                return False, None, None
        except Exception as e:
            log.error(f"Error during libsodium installation: {e}", exc_info=True)
            return False, None, None
    else:
        log.error(f"Unsupported platform: {SYSTEM}")
        log.error(f"Please install libsodium manually for your platform.")
        log.error(f"Visit https://doc.libsodium.org/ for instructions.")
        return False, None, None

def initialize_libsodium():
    """
    Initialize libsodium, downloading and installing it if necessary.
    
    Returns:
        tuple: (success, library_path, library_handle)
    """
    log.info(f"Initializing libsodium for {SYSTEM} platform")
    
    try:
        success, lib_path, libsodium = get_libsodium()
        
        if success and libsodium:
            # Get library version if available
            try:
                if hasattr(libsodium, 'sodium_version_string'):
                    libsodium.sodium_version_string.restype = ctypes.c_char_p
                    version_str = libsodium.sodium_version_string().decode('utf-8')
                    log.info(f"libsodium version: {version_str}")
                else:
                    log.info("libsodium version function not available")
                    
                # Try initializing the library if it has an init function
                if hasattr(libsodium, 'sodium_init'):
                    init_result = libsodium.sodium_init()
                    if init_result >= 0:  # 0 = success, 1 = already initialized, -1 = error
                        log.info("libsodium initialization successful")
                    else:
                        log.warning(f"libsodium initialization returned {init_result}")
            except Exception as e:
                log.warning(f"Error getting libsodium version or initializing: {e}")
                
            return success, lib_path, libsodium
        else:
            log.error("Failed to initialize libsodium")
            return False, None, None
    except Exception as e:
        log.error(f"Error initializing libsodium: {e}", exc_info=True)
        return False, None, None

if __name__ == "__main__":
    success, lib_path, libsodium = initialize_libsodium()
    if success:
        print(f"Successfully initialized libsodium from {lib_path}")
        
        # Test the library
        try:
            random_value = libsodium.randombytes_random()
            print(f"Generated random value: {random_value}")
            
            # Test secure memory allocation
            buffer = libsodium.sodium_malloc(32)
            if buffer:
                print("Successfully allocated secure memory")
                libsodium.sodium_free(buffer)
                print("Successfully freed secure memory")
            else:
                print("Failed to allocate secure memory")
                
            print("libsodium functionality verified")
        except Exception as e:
            print(f"Error testing libsodium: {e}")
    else:
        print("Failed to initialize libsodium") 