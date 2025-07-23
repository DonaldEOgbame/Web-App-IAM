from django import template

register = template.Library()

@register.filter(name='addattr')
def addattr(field, attr):
    """Add an attribute to a form field widget."""
    if not hasattr(field, 'field'):
        return field
    attr_name, _, attr_value = attr.partition(':') if ':' in attr else (attr, '', '')
    # If attr like 'autofocus' without value
    if not attr_value:
        attr_name, _, attr_value = attr.partition('=') if '=' in attr else (attr, '', '')
    existing_attrs = field.field.widget.attrs.copy()
    existing_attrs.update({attr_name: attr_value or None})
    return field.as_widget(attrs=existing_attrs)
