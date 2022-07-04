from django import template
register = template.Library()

@register.filter
def index(indexable, i):
    i=int(i)
    return indexable[i]