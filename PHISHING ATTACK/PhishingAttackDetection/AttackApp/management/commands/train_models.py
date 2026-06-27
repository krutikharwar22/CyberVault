from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Train and save ML models for URL threat detection."

    def handle(self, *args, **options):
        from AttackApp.trianer import train_all

        out_dir = Path(settings.BASE_DIR) / "AttackApp" / "ml_models"
        train_all(out_dir)
        self.stdout.write(self.style.SUCCESS(f"Models saved to {out_dir}"))

