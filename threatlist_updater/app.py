import json
import requests
import boto3
import os
import tempfile
import logging

# Init Logging
logging.basicConfig(
        level=logging.INFO,
        format=f'%(asctime)s %(levelname)s %(message)s'
    )
logger = logging.getLogger()

# Init Clients
s3 = boto3.client('s3')
guardduty = boto3.client('guardduty')

# Get Lambda Inputs
bucket = os.environ.get('S3_BUCKET')
dest_key = os.environ.get('S3_KEY')
location = f"s3://{bucket}/{dest_key}"
detector = threat_intel_set = os.environ.get('GD_DETECTOR_ID')
threat_intel_set = os.environ.get('GD_THREAT_INTEL_SET')
threatlist_url = os.environ.get('THREATLIST_URL')
threatlist_format = os.environ.get('THREATLIST_FORMAT', 'TXT')

logger.info(f"Config:")
logger.info(f"  S3_BUCKET: {bucket}")
logger.info(f"  S3_KEY: {dest_key}")
logger.info(f"  GD_DETECTOR_ID: {detector}")
logger.info(f"  GD_THREAT_INTEL_SET: {threat_intel_set}")
logger.info(f"  THREATLIST_URL: {threatlist_url}")
logger.info(f"  THREATLIST_FORMAT: {threatlist_format}")


def lambda_handler(event, context):

    logger.info("Starting update")

    logger.info("Fetching threatlist")
    resp = requests.get(threatlist_url, allow_redirects=True)
    logger.info(f"Recieved response: {resp.status_code}")

    if resp.status_code == 200:
        temp_file = tempfile.TemporaryFile()
        try:
            temp_file.write(resp.content)
            temp_file.seek(0)
            logger.info(f"Uploading threatlist to s3")
            s3_resp = s3.upload_fileobj(temp_file, bucket, dest_key)
        except Exception as e:
            logger.exception(e)
            raise e
        finally:
            temp_file.close()

        try:
            logger.info("Attempting to create threat intel set")
            response = guardduty.create_threat_intel_set(
                Activate=True,
                DetectorId=detector,
                Format=threatlist_format,
                Location=f"s3://{bucket}/{dest_key}",
                Name=threat_intel_set
            )
        except Exception as error:
            error_message = error.response.get('Message')
            if "name already exists" in error_message:
                logger.info("Threat intel set already exists. Attempting to update")
                found = False
                response = guardduty.list_threat_intel_sets(DetectorId=detector)
                for setId in response['ThreatIntelSetIds']:
                    response = guardduty.get_threat_intel_set(DetectorId=detector, ThreatIntelSetId=setId)
                    if (threat_intel_set == response['Name']):
                        found = True
                        logger.info(f"Found existing threat intel set {threat_intel_set}. Updating...")
                        response = guardduty.update_threat_intel_set(
                            Activate=True,
                            DetectorId=detector,
                            Location=location,
                            Name=threat_intel_set,
                            ThreatIntelSetId=setId
                        )
                        logger.info(f"Update complete")
                        break
                if not found:
                    logger.info(f"Cannot find guardduty detector with id: {detector}")
                    raise
            else:
                logger.error("Something went wrong")
                logger.exception(error)
                raise error
    else:
        logger.error(f"Unable to update from threatlist source")
        raise

    logger.info(f"Completed Successfully")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Completed Successfully",
            }
        ),
    }
