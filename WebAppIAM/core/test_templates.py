import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'WebAppIAM.settings')
django.setup()

from django.template.loader import get_template


def test_all_core_templates_load():
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    for root, _, files in os.walk(template_dir):
        for f in files:
            if f.endswith('.html'):
                rel_path = os.path.relpath(os.path.join(root, f), template_dir)
                get_template(rel_path)
