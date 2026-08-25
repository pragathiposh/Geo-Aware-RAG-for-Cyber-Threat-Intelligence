from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import logging
import os
from dotenv import load_dotenv

load_dotenv()

# Import collector functions
from app.collectors.nvd import fetch_nvd
from app.collectors.cisa import fetch_cisa_kev
from app.collectors.otx import fetch_otx

try:
    from app.collectors.mitre_attack import load_attack
except ImportError:
    load_attack = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)


def update_nvd():
    """Fetch latest CVEs from NVD."""
    try:
        logger.info("Updating NVD CVEs...")
        api_key = os.getenv("NVD_API_KEY", "")
        data = fetch_nvd(api_key)
        logger.info(f"NVD Update Complete: {len(data)} CVEs fetched.")
    except Exception as e:
        logger.error(f"NVD Update Failed: {e}")


def update_cisa():
    """Fetch latest CISA KEV."""
    try:
        logger.info("Updating CISA KEV...")
        data = fetch_cisa_kev()
        logger.info(f"CISA Update Complete: {len(data)} vulnerabilities fetched.")
    except Exception as e:
        logger.error(f"CISA Update Failed: {e}")


def update_otx():
    """Fetch latest AlienVault OTX Pulses."""
    try:
        logger.info("Updating OTX Threat Intelligence...")
        api_key = os.getenv("OTX_API_KEY", "")
        data = fetch_otx(api_key)
        logger.info(f"OTX Update Complete: {len(data)} pulses fetched.")
    except Exception as e:
        logger.error(f"OTX Update Failed: {e}")


def update_attack():
    if load_attack is None:
        logger.warning("MITRE ATT&CK module not available. Skipping update.")
        return

    try:
        logger.info("Loading MITRE ATT&CK...")
        data = load_attack()
        logger.info(f"MITRE ATT&CK Loaded: {len(data)} techniques.")
    except Exception as e:
        logger.error(f"MITRE ATT&CK Update Failed: {e}")


def update_all():
    logger.info("=" * 60)
    logger.info("Starting Threat Intelligence Update")
    logger.info("=" * 60)

    update_nvd()
    update_cisa()
    update_otx()
    update_attack()

    logger.info("=" * 60)
    logger.info("Threat Intelligence Update Finished")
    logger.info("=" * 60)


def start_scheduler():
    scheduler = BackgroundScheduler()

    # Daily at 01:00 AM
    scheduler.add_job(
        update_all,
        trigger="cron",
        hour=1,
        minute=0,
        id="daily_update",
        replace_existing=True
    )

    scheduler.start()

    logger.info("Scheduler Started")
    logger.info("Daily Update Time: 01:00 AM")

    return scheduler


if __name__ == "__main__":
    print("Running update manually...")
    update_all()
