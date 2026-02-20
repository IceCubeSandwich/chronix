#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Tyrrell Brewster

"""Chronix CLI"""

import argparse
import os
import sys
import socket
import webbrowser
import secrets
import string
from pathlib import Path
from datetime import datetime


def get_version():
    return "1.0.0"


# =============================================================================
# Configuration Management
# =============================================================================

CONFIG_DIR = Path.home() / ".config" / "chronix"
CONFIG_FILE = CONFIG_DIR / "chronix.env"


def load_config():
    """Load configuration from ~/.config/chronix/chronix.env if it exists"""
    if not CONFIG_FILE.exists():
        return False
    
    try:
        with open(CONFIG_FILE) as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Parse KEY=value
                if '=' in line:
                    key, _, value = line.partition('=')
                    key = key.strip()
                    value = value.strip()
                    # Don't override existing environment variables
                    if key and key not in os.environ:
                        os.environ[key] = value
        return True
    except Exception as e:
        print(f"[Warning] Failed to load config from {CONFIG_FILE}: {e}")
        return False


def config_has_secret() -> bool:
    """Check if config file exists and contains a session secret"""
    if not CONFIG_FILE.exists():
        return False
    
    try:
        with open(CONFIG_FILE) as f:
            for line in f:
                line = line.strip()
                if line.startswith('CHRONIX_SESSION_SECRET=') and len(line) > 25:
                    # Has a non-empty secret
                    return True
    except Exception:
        pass
    
    return False


# =============================================================================
# Secure Random Generation
# =============================================================================

def generate_secure_password(length: int = 24) -> str:
    """
    Generate a cryptographically secure random password.
    
    Uses secrets module (CSPRNG) for generation.
    Character set: uppercase, lowercase, digits, and safe punctuation.
    Ensures at least one of each character type for complexity requirements.
    """
    # Character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    # Safe punctuation (avoiding shell-problematic characters)
    punctuation = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    all_chars = uppercase + lowercase + digits + punctuation
    
    # Ensure at least one of each type
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(punctuation),
    ]
    
    # Fill the rest randomly
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))
    
    # Shuffle to avoid predictable positions
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    
    return ''.join(password_list)


def generate_session_secret(bytes_length: int = 32) -> str:
    """
    Generate a cryptographically secure session secret.
    
    Returns a 64-character hex string (32 bytes of entropy).
    Suitable for HMAC signing of session cookies.
    """
    return secrets.token_hex(bytes_length)


# =============================================================================
# Init Command Implementation
# =============================================================================

def cmd_init(args):
    """
    Initialize Chronix.
    
    Creates:
    1. Configuration file with session secret
    2. Admin user in database
    
    Safe to run once. Refuses to overwrite existing config/admin.
    """
    # Colors for output
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    
    print(f"""
{CYAN}╔═══════════════════════════════════════════════════════════════╗
║                    CHRONIX INITIALIZATION                     ║
╚═══════════════════════════════════════════════════════════════╝{RESET}
""")
    
    # Track what we need to do
    create_config = False
    create_admin = False
    session_secret = None
    
    # -------------------------------------------------------------------------
    # Step 1: Check/Create Configuration
    # -------------------------------------------------------------------------
    print(f"{BOLD}[1/2] Checking configuration...{RESET}")
    
    if config_has_secret():
        if args.force:
            print(f"  {YELLOW}!{RESET} Config exists but --force specified, will regenerate secret")
            create_config = True
        else:
            print(f"  {GREEN}✓{RESET} Session secret already configured: {CONFIG_FILE}")
            print(f"    {CYAN}(use --force to regenerate){RESET}")
    else:
        create_config = True
        if CONFIG_FILE.exists():
            print(f"  {YELLOW}!{RESET} Config file exists but missing session secret")
        else:
            print(f"  {CYAN}→{RESET} Will create new configuration")
    
    # -------------------------------------------------------------------------
    # Step 2: Check/Create Admin User
    # -------------------------------------------------------------------------
    print(f"\n{BOLD}[2/2] Checking admin user...{RESET}")
    
    # We need to initialize the database to check for admin
    db_path = args.db if args.db else os.environ.get("CHRONIX_DB_PATH", "./chronix.db")
    db_path = str(Path(db_path).resolve())
    os.environ["CHRONIX_DB_PATH"] = db_path
    
    # Import here to avoid circular imports and allow env to be set first
    try:
        from chronix.models import init_db, User, UserRole as DBUserRole
        from chronix.security import hash_password
        from sqlalchemy.orm import sessionmaker
    except ImportError as e:
        print(f"  {RED}✗{RESET} Failed to import Chronix modules: {e}")
        print(f"    Make sure Chronix is properly installed.")
        return 1
    
    # Initialize database (creates tables if needed)
    engine = init_db(db_path)
    Session = sessionmaker(bind=engine)
    db = Session()
    
    try:
        # Check for existing admin
        existing_admin = db.query(User).filter(
            User.role == DBUserRole.ADMIN,
            User.is_active == True
        ).first()
        
        if existing_admin:
            if args.force:
                print(f"  {YELLOW}!{RESET} Admin exists but --force specified")
                print(f"  {RED}✗{RESET} Refusing to overwrite existing admin user for safety")
                print(f"    Existing admin: {existing_admin.username}")
                print(f"    {CYAN}To reset: manually delete the user from the database{RESET}")
                # Don't create admin, but continue with config if needed
            else:
                print(f"  {GREEN}✓{RESET} Admin user already exists: {existing_admin.username}")
        else:
            create_admin = True
            print(f"  {CYAN}→{RESET} Will create admin user")
        
        # -------------------------------------------------------------------------
        # Execute Changes
        # -------------------------------------------------------------------------
        
        admin_password = None
        
        if not create_config and not create_admin:
            print(f"\n{GREEN}Chronix is already initialized. No changes needed.{RESET}")
            return 0
        
        print(f"\n{BOLD}Applying changes...{RESET}\n")
        
        # Create/update config file
        if create_config:
            session_secret = generate_session_secret(32)
            
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            
            # Read existing config if present (to preserve other settings)
            existing_lines = []
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE) as f:
                    existing_lines = [
                        line for line in f.readlines()
                        if not line.strip().startswith('CHRONIX_SESSION_SECRET=')
                    ]
            
            with open(CONFIG_FILE, 'w') as f:
                if existing_lines:
                    f.writelines(existing_lines)
                    if not existing_lines[-1].endswith('\n'):
                        f.write('\n')
                else:
                    f.write(f"# Chronix Configuration\n")
                    f.write(f"# Generated by 'chronix init' on {datetime.now().isoformat()}\n")
                    f.write(f"#\n")
                    f.write(f"# This file is loaded automatically by the chronix command.\n")
                    f.write(f"# Keep this file secure - it contains your session signing secret.\n\n")
                
                f.write(f"CHRONIX_SESSION_SECRET={session_secret}\n")
            
            # Secure the config file (owner read/write only)
            CONFIG_FILE.chmod(0o600)
            
            print(f"  {GREEN}✓{RESET} Session secret generated and saved")
            print(f"    Location: {CONFIG_FILE}")
            print(f"    Permissions: 600 (owner read/write only)")
        
        # Create admin user
        if create_admin:
            admin_password = generate_secure_password(24)
            admin_username = args.username if args.username else "admin"
            
            admin_user = User(
                username=admin_username,
                password_hash=hash_password(admin_password),
                display_name="Administrator",
                role=DBUserRole.ADMIN,
            )
            db.add(admin_user)
            db.commit()
            
            print(f"  {GREEN}✓{RESET} Admin user created")
            print(f"    Username: {admin_username}")
            print(f"    Role: Admin")
        
        # -------------------------------------------------------------------------
        # Output Credentials (ONE TIME ONLY)
        # -------------------------------------------------------------------------
        
        if admin_password:
            print(f"""
{YELLOW}{'═' * 66}
 ⚠️  SAVE THESE CREDENTIALS - SHOWN ONCE ONLY
{'═' * 66}{RESET}

  {BOLD}Username:{RESET}  {admin_username}
  {BOLD}Password:{RESET}  {admin_password}

{YELLOW}{'═' * 66}{RESET}
""")
        
        # -------------------------------------------------------------------------
        # Final Instructions
        # -------------------------------------------------------------------------
        
        print(f"""{GREEN}
Initialization complete.{RESET}

Run: {CYAN}chronix{RESET}
""")
        
        return 0
        
    except Exception as e:
        print(f"\n{RED}✗ Error during initialization:{RESET} {e}")
        db.rollback()
        return 1
    finally:
        db.close()


# =============================================================================
# Server Command (default)
# =============================================================================

def get_local_ips():
    """Get all local IP addresses for network interfaces"""
    ips = []
    try:
        # Get hostname
        hostname = socket.gethostname()
        # Get all IPs for this host
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith('127.'):
                ips.append(ip)
    except Exception:
        pass
    
    # Also try to get IP by connecting to external address (doesn't actually connect)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        if ip not in ips:
            ips.append(ip)
        s.close()
    except Exception:
        pass
    
    return ips


def print_initialization_required():
    """Print clean initialization required message and exit instructions"""
    ORANGE = "\033[38;5;208m"
    CYAN = "\033[36m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    
    print(f"""
{ORANGE}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗██╗██╗  ██╗    ║
║    ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██║╚██╗██╔╝    ║
║    ██║     ███████║██████╔╝██║   ██║██╔██╗ ██║██║ ╚███╔╝     ║
║    ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██║ ██╔██╗     ║
║    ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║██║██╔╝ ██╗    ║
║     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝    ║
║                                                               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{RESET}

{"="*70}
{ORANGE}INITIALIZATION REQUIRED{RESET}
{"="*70}

Run:

    {CYAN}chronix init{RESET}

{"="*70}
""")


def cmd_serve(args):
    """Run the Chronix server"""
    # Load config file first
    config_loaded = load_config()
    
    # Feature #3: If --local flag is set, override host to 127.0.0.1
    host = args.host
    if args.local:
        host = "127.0.0.1"
    
    # Set environment variables for the server
    os.environ["CHRONIX_DB_PATH"] = str(Path(args.db).resolve())
    
    # Handle --debug flag
    if args.debug:
        os.environ["CHRONIX_DEBUG"] = "true"
    
    # Check initialization state BEFORE starting ASGI (unless debug mode)
    if not args.debug and not config_has_secret():
        print_initialization_required()
        sys.exit(1)
    
    # Print banner
    print_banner(host, args.port, args.db, config_loaded)
    
    # Feature #3: Show network warning when binding to 0.0.0.0
    if host == "0.0.0.0":
        print_network_warning(args.port)
    
    # Open browser unless disabled
    if not args.no_browser:
        import threading
        def open_browser():
            import time
            time.sleep(1.5)  # Wait for server to start
            # Use localhost for browser even if binding to 0.0.0.0
            browser_host = "127.0.0.1" if host == "0.0.0.0" else host
            webbrowser.open(f"http://{browser_host}:{args.port}")
        threading.Thread(target=open_browser, daemon=True).start()
    
    # Start the server
    try:
        import uvicorn
        from chronix.server import app
        
        # Log level: "warning" by default (suppresses connection spam)
        # "debug" when --debug is set (shows all connection details)
        log_level = "debug" if args.debug else "warning"
        
        uvicorn.run(
            "chronix.server:app" if args.reload else app,
            host=host,
            port=args.port,
            reload=args.reload,
            log_level=log_level,
        )
    except KeyboardInterrupt:
        print("\n\nShutting down Chronix...")
        sys.exit(0)
    except Exception as e:
        print(f"\nError starting server: {e}", file=sys.stderr)
        sys.exit(1)


def print_banner(host: str, port: int, db_path: str, config_loaded: bool):
    """Print the Chronix startup banner"""
    ORANGE = "\033[38;5;208m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    
    config_status = f"{GREEN}✓ Config loaded{RESET}" if config_loaded else f"{DIM}No config file{RESET}"
    
    print(f"""
{ORANGE}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗██╗██╗  ██╗    ║
║    ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██║╚██╗██╔╝    ║
║    ██║     ███████║██████╔╝██║   ██║██╔██╗ ██║██║ ╚███╔╝     ║
║    ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██║ ██╔██╗     ║
║    ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║██║██╔╝ ██╗    ║
║     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝    ║
║                                                               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{RESET}

{GREEN}▶{RESET} Server:   {CYAN}http://{host}:{port}{RESET}
{GREEN}▶{RESET} Database: {DIM}{db_path}{RESET}
{GREEN}▶{RESET} Config:   {config_status}

{DIM}Press Ctrl+C to stop{RESET}
""")


def print_network_warning(port: int):
    """Print network accessibility warning when binding to 0.0.0.0"""
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    
    local_ips = get_local_ips()
    
    print(f"{YELLOW}⚠️  Chronix is accessible on your network at:{RESET}")
    
    # Always show localhost
    print(f"    {CYAN}http://127.0.0.1:{port}{RESET}")
    
    # Show all detected network IPs
    for ip in local_ips:
        print(f"    {CYAN}http://{ip}:{port}{RESET}")
    
    print(f"\n    {DIM}Use --local flag to restrict to localhost only{RESET}")
    print()


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="chronix",
        description="Chronix",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"chronix {get_version()}"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # -------------------------------------------------------------------------
    # init subcommand
    # -------------------------------------------------------------------------
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize Chronix",
        description="Initialize Chronix.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    init_parser.add_argument(
        "--db", "-d",
        default=os.environ.get("CHRONIX_DB_PATH", "./chronix.db"),
        help="Database path (default: ./chronix.db)"
    )
    init_parser.add_argument(
        "--username", "-u",
        default="admin",
        help="Admin username (default: admin)"
    )
    init_parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Regenerate session secret"
    )
    
    # -------------------------------------------------------------------------
    # serve subcommand (also default when no command given)
    # -------------------------------------------------------------------------
    serve_parser = subparsers.add_parser(
        "serve",
        help="Start server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_serve_arguments(serve_parser)
    
    # Also add serve arguments to main parser for default behavior
    add_serve_arguments(parser)
    
    args = parser.parse_args()
    
    # Route to appropriate command
    if args.command == "init":
        sys.exit(cmd_init(args))
    elif args.command == "serve":
        cmd_serve(args)
    else:
        # Default: run server (no subcommand given)
        # Need to load config first for default behavior
        load_config()
        cmd_serve(args)


def add_serve_arguments(parser):
    """Add server-related arguments to a parser"""
    parser.add_argument(
        "--host", "-H",
        default=os.environ.get("CHRONIX_HOST", "0.0.0.0"),
        help="Bind address (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Bind to localhost only"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=int(os.environ.get("CHRONIX_PORT", "8000")),
        help="Port (default: 8000)"
    )
    parser.add_argument(
        "--db", "-d",
        default=os.environ.get("CHRONIX_DB_PATH", "./chronix.db"),
        help="Database path (default: ./chronix.db)"
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Skip browser launch"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode"
    )


if __name__ == "__main__":
    main()
