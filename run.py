#!/usr/bin/env python3
"""
DDoS Detection System Runner
Alternative implementation with enhanced features
"""

import uvicorn
import logging
import os
import sys
import argparse
from pathlib import Path
from config.settings import settings

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/server.log', mode='a') if os.path.exists('logs') else logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='DDoS Detection API Server')
    parser.add_argument('--host', default=None, help='Server host (default: from settings)')
    parser.add_argument('--port', type=int, default=None, help='Server port (default: from settings)')
    parser.add_argument('--workers', type=int, default=None, help='Number of workers (default: from settings)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--no-reload', action='store_true', help='Disable auto-reload')
    parser.add_argument('--log-level', choices=['debug', 'info', 'warning', 'error'], default='info',
                       help='Logging level')
    return parser.parse_args()

def validate_environment():
    """Validate environment and dependencies"""
    logger.info("Validating environment...")

    # Check if required directories exist
    required_dirs = ['config', 'core', 'api', 'models', 'data']
    for dir_name in required_dirs:
        if not os.path.exists(dir_name):
            logger.warning(f"Directory '{dir_name}' not found")

    # Check if required files exist
    required_files = ['config/settings.py', 'api/main.py']
    for file_name in required_files:
        if not os.path.exists(file_name):
            logger.error(f"Required file '{file_name}' not found")
            return False

    logger.info("Environment validation completed")
    return True

def setup_server_config(args):
    """Setup server configuration from arguments and environment"""
    config = {}

    # Host configuration
    config['host'] = args.host or os.getenv("API_HOST", settings.API_HOST)

    # Port configuration
    config['port'] = args.port or int(os.getenv("API_PORT", settings.API_PORT))

    # Workers configuration
    config['workers'] = args.workers or int(os.getenv("API_WORKERS", settings.API_WORKERS))

    # Debug mode
    config['debug'] = args.debug or os.getenv("DEBUG", str(settings.DEBUG)).lower() == "true"

    # Reload configuration
    config['reload'] = not args.no_reload and config['debug']

    # Log level
    config['log_level'] = args.log_level

    return config

def print_startup_banner(config):
    """Print startup banner"""
    print("=" * 60)
    print("🚀 DDoS Detection API Server")
    print("=" * 60)
    print(f"Host: {config['host']}")
    print(f"Port: {config['port']}")
    print(f"Workers: {config['workers']}")
    print(f"Debug Mode: {config['debug']}")
    print(f"Auto Reload: {config['reload']}")
    print(f"Log Level: {config['log_level']}")
    print(f"API Docs: http://{config['host']}:{config['port']}/docs")
    print(f"API Redoc: http://{config['host']}:{config['port']}/redoc")
    print("=" * 60)

def main():
    """Main entry point"""
    try:
        # Parse arguments
        args = parse_arguments()

        # Validate environment
        if not validate_environment():
            logger.error("Environment validation failed")
            sys.exit(1)

        # Setup configuration
        config = setup_server_config(args)

        # Set logging level
        numeric_level = getattr(logging, config['log_level'].upper(), logging.INFO)
        logging.getLogger().setLevel(numeric_level)

        # Print startup banner
        print_startup_banner(config)

        logger.info("Starting DDoS Detection API Server...")

        # Start server
        uvicorn.run(
            "api.main:app",
            host=config['host'],
            port=config['port'],
            reload=config['reload'],
            workers=config['workers'] if not config['debug'] else 1,
            log_level=config['log_level'],
            access_log=True,
            server_header=False,  # Hide server info for security
            date_header=False     # Hide date for security
        )

    except KeyboardInterrupt:
        logger.info("Server shutdown requested by user")
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
