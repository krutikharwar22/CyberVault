from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("AttackApp", "0004_usersettings"),
    ]

    operations = [
        migrations.AddField(
            model_name="usersettings",
            name="history_page_size",
            field=models.PositiveIntegerField(default=200),
        ),
        migrations.AddField(
            model_name="usersettings",
            name="truncate_urls_in_tables",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="usersettings",
            name="log_scan_to_recent_activity",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="usersettings",
            name="email_alerts_on_threat",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="usersettings",
            name="alert_email",
            field=models.EmailField(blank=True, default="", max_length=254),
        ),
    ]

