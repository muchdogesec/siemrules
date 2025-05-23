# Generated by Django 5.1.4 on 2025-05-14 06:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('siemrules', '0016_alter_job_state'),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='name',
            field=models.CharField(help_text='This will be assigned to the File and Report object created. Note, the names of each detection rule generated will be automatically. Max 256 characters. This is a txt2detection setting.', max_length=256),
        ),
    ]
