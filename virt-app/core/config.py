import os
import yaml
import logging

# --- Base app settings ---
CONFIG_FILE = os.getenv("CONFIG_FILE", "config.yaml")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
APP_NAME = os.getenv("APP_NAME", "Libvirt Cluster API")
APP_VERSION = os.getenv("APP_VERSION", "0.1.0")

# Initialize logger early (before setup_logging is called)
logger = logging.getLogger(APP_NAME)
if not logger.handlers:
    logging.basicConfig(level=LOG_LEVEL, format="%(levelname)s: %(message)s")


def load_yaml_config() -> dict:
    """Load global YAML configuration (app + cluster)."""
    try:
        with open(CONFIG_FILE, "r") as f:
            data = yaml.safe_load(f) or {}
            logger.info("Loaded configuration from %s", CONFIG_FILE)
            return data
    except FileNotFoundError:
        logger.warning("Configuration file not found: %s", CONFIG_FILE)
        return {}
    except yaml.YAMLError as e:
        logger.error("Error parsing YAML config (%s): %s", CONFIG_FILE, e)
        return {}


# --- Load YAML and derive app settings ---
CONFIG_YAML = load_yaml_config()

# --- Extract CORS settings ---
CORS_CONFIG = CONFIG_YAML.get("cors", {})
CORS_ORIGINS = CORS_CONFIG.get("allow_origins", [])
CORS_ALLOW_CREDENTIALS = CORS_CONFIG.get("allow_credentials", True)
CORS_ALLOW_METHODS = CORS_CONFIG.get("allow_methods", ["*"])
CORS_ALLOW_HEADERS = CORS_CONFIG.get("allow_headers", ["*"])

# Optional: expose libvirt hosts list here if needed globally
LIBVIRT_HOSTS = CONFIG_YAML.get("hosts", [])

# Confirm loaded config summary
logger.debug(
    "CORS_ORIGINS=%s, allow_credentials=%s, allow_methods=%s",
    CORS_ORIGINS,
    CORS_ALLOW_CREDENTIALS,
    CORS_ALLOW_METHODS,
)

