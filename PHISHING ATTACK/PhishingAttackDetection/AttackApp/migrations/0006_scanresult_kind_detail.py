# Generated manually for expanded scan history (URL / email / payload).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("AttackApp", "0005_usersettings_more_fields"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scanresult",
            name="url",
            field=models.CharField(max_length=2048),
        ),
        migrations.AlterField(
            model_name="scanresult",
            name="result",
            field=models.CharField(max_length=100),
        ),
        migrations.AddField(
            model_name="scanresult",
            name="detail",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="scanresult",
            name="scan_kind",
            field=models.CharField(default="url", max_length=16),
        ),
    ]
