import os
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from typing import Optional
from datetime import datetime
from flask import current_app


class BackupScheduler:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.scheduler = BackgroundScheduler(daemon=True)
        self.logger = logging.getLogger(__name__)
        self._jobs = {
            'daily_backup': {
                'trigger': CronTrigger(hour=2, minute=0),
                'func': self.run_backup,
                'kwargs': {'description': 'Daily automatic backup'}
            },
            'weekly_metrics': {
                'trigger': CronTrigger(day_of_week='sun', hour=3),
                'func': self.record_metrics,
                'kwargs': {'detailed': True}
            },
            'cloud_sync': {
                'trigger': CronTrigger(hour=4, minute=30),
                'func': self.cloud_sync_latest,
                'kwargs': {'provider': 's3'}
            }
        }

    def start(self) -> bool:
        """Start all scheduled jobs with error handling"""
        try:
            for job_id, config in self._jobs.items():
                self.scheduler.add_job(
                    id=job_id,
                    func=config['func'],
                    trigger=config['trigger'],
                    kwargs=config.get('kwargs', {}),
                    misfire_grace_time=3600,
                    coalesce=True
                )

            self.scheduler.start()
            self.logger.info("Backup scheduler started with %d jobs", len(self._jobs))
            return True

        except Exception as e:
            self.logger.critical(f"Scheduler failed to start: {str(e)}")
            raise

    def run_backup(self, description: Optional[str] = None) -> Optional[str]:
        """Execute backup with enhanced logging"""
        try:
            self.logger.info("Starting scheduled backup: %s", description or 'No description')

            backup_name = f"auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            backup_path = self.db_manager.create_backup(backup_name)

            self.logger.info("Backup completed: %s", backup_path)
            return backup_path

        except Exception as e:
            self.logger.error("Backup job failed: %s", str(e))
            return None

    def record_metrics(self, detailed: bool = False) -> None:
        """Record system metrics with optional detailed stats"""
        try:
            with self.db_manager.get_db('app') as conn:
                stats = self.db_manager.get_system_stats()

                conn.execute('''
                INSERT INTO system_metrics (
                    timestamp, 
                    total_users, 
                    active_users, 
                    total_uploads, 
                    total_storage
                ) VALUES (datetime('now'), ?, ?, ?, ?)
                ''', (
                    stats['total_users'],
                    stats['active_users'],
                    stats['total_uploads'],
                    stats['total_storage']
                ))

                if detailed:
                    conn.execute('''
                    INSERT INTO detailed_metrics (
                        timestamp,
                        locked_accounts,
                        active_sessions,
                        avg_upload_size
                    ) VALUES (datetime('now'), ?, ?, ?)
                    ''', (
                        stats.get('locked_accounts', 0),
                        stats.get('active_sessions', 0),
                        stats.get('total_storage', 0) / max(1, stats.get('total_uploads', 1))
                    ))

                conn.commit()

            self.logger.info("Recorded %smetrics", 'detailed ' if detailed else '')

        except Exception as e:
            self.logger.error("Metrics recording failed: %s", str(e))

    def cloud_sync_latest(self, provider: str = 's3') -> bool:
        """Sync latest backup to cloud storage"""
        try:
            backups = sorted(
                [d for d in os.scandir(current_app.config['BACKUP_DIR']) if d.is_dir()],
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )

            if backups:
                latest = backups[0].name
                self.logger.info("Initiating cloud sync for: %s", latest)
                return self.db_manager.cloud_sync(latest, provider)
            return False

        except Exception as e:
            self.logger.error("Cloud sync failed: %s", str(e))
            return False

    def shutdown(self) -> None:
        """Graceful scheduler shutdown"""
        try:
            if self.scheduler.running:
                self.scheduler.shutdown(wait=True)
                self.logger.info("Backup scheduler stopped")
        except Exception as e:
            self.logger.warning("Error during shutdown: %s", str(e))
