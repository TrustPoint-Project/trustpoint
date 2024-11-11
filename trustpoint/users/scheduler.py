import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger('tp.users')

class TaskScheduler:
    """
    Class responsible for setting up and manually triggering periodic tasks
    using Python's threading.
    """

    def __init__(self):

        from users.tasks import (setup_trustpoint_notifications, check_system_health,
                                 check_for_security_vulnerabilities,
                                 check_certificate_validity, check_issuing_ca_validity, check_domain_issuing_ca,
                                 check_non_onboarded_devices, check_devices_with_failed_onboarding,
                                 check_devices_with_revoked_certificates, check_for_weak_signature_algorithms,
                                 check_for_insufficient_key_length, check_for_weak_ecc_curves)

        self.periodic_tasks = {
            'setup_trustpoint_notifications': setup_trustpoint_notifications,
            'check_system_health': check_system_health,
            'check_for_security_vulnerabilities': check_for_security_vulnerabilities,
            'check_certificate_validity': check_certificate_validity,
            'check_issuing_ca_validity': check_issuing_ca_validity,
            'check_domain_issuing_ca': check_domain_issuing_ca,
            'check_non_onboarded_devices': check_non_onboarded_devices,
            'check_devices_with_failed_onboarding': check_devices_with_failed_onboarding,
            'check_devices_with_revoked_certificates': check_devices_with_revoked_certificates,
            'check_for_weak_signature_algorithms': check_for_weak_signature_algorithms,
            'check_for_insufficient_key_length': check_for_insufficient_key_length,
            'check_for_weak_ecc_curves': check_for_weak_ecc_curves,
        }

    def run_task(self, task_func):
        """
        Submit a task to the thread pool for execution.
        """
        try:
            logger.debug(f"Submitting '{task_func.__name__}' to the thread pool.")
            future = self.executor.submit(task_func)
            return future
        except Exception as e:
            logger.error(f"Failed to submit task '{task_func.__name__}': {e}")

    def setup_periodic_tasks(self, interval_minutes=10):
        """
        Schedule periodic tasks using a thread pool and sleep for the given interval.
        """
        logger.info("Setting up periodic tasks...")
        with ThreadPoolExecutor(max_workers=len(self.periodic_tasks)) as self.executor:
            while True:
                logger.info("Triggering periodic tasks.")
                futures = [self.run_task(task_func) for task_func in self.periodic_tasks.values()]

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Task execution resulted in an error: {e}")

                logger.info("All periodic tasks completed.")
                logger.info(f"Sleeping for {interval_minutes} minutes before the next run.")
                time.sleep(interval_minutes * 60)  # Convert minutes to seconds

    def trigger_all_tasks_once(self):
        """
        Manually trigger all periodic tasks once, using a thread pool.
        """
        logger.info("Manually triggering all periodic tasks.")
        with ThreadPoolExecutor(max_workers=len(self.periodic_tasks)) as self.executor:
            futures = [self.run_task(task_func) for task_func in self.periodic_tasks.values()]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Task execution resulted in an error: {e}")

            logger.info("All periodic tasks triggered successfully.")
