from app import app as handler
def handler(event, context):
    return app(event, +context)
