"""Storage for question images after the application authorizes the request."""

from contextlib import closing
from functools import lru_cache

from flask import current_app


@lru_cache(maxsize=1)
def _client():
    import boto3
    from botocore.config import Config

    return boto3.client(
        's3', endpoint_url=current_app.config.get('QUZO_S3_ENDPOINT'),
        config=Config(connect_timeout=3, read_timeout=8, retries={'total_max_attempts': 2}),
    )


def store_image(name, data, content_type):
    bucket = current_app.config.get('QUZO_S3_BUCKET')
    if not bucket:
        return False
    _client().put_object(Bucket=bucket, Key=f'questions/{name}', Body=data, ContentType=content_type)
    return True


def read_image(name):
    bucket = current_app.config.get('QUZO_S3_BUCKET')
    if not bucket:
        return None
    from botocore.exceptions import ClientError

    try:
        response = _client().get_object(Bucket=bucket, Key=f'questions/{name}')
    except ClientError as error:
        if error.response['Error']['Code'] in ('NoSuchKey', 'NotFound', '404'):
            return None
        raise
    maximum = current_app.config['MAX_CONTENT_LENGTH']
    with closing(response['Body']) as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('Stored question image exceeds the size limit.')
    return data
