import os
import json
import boto3
import logging
import requests
from datetime import datetime
from cryptography.fernet import Fernet
from botocore.exceptions import NoCredentialsError
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Specify the AWS region
region = os.getenv('region')
aws_access_key_id = os.getenv('aws_access_key_id')
aws_secret_access_key = os.getenv('aws_secret_access_key')
api_access_code = os.getenv('api_access_code')

# Initialize AWS clients with the specified region
session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name=region
)

s3_client = session.client('s3')
sns_client = session.client('sns')
secrets_client = session.client('secretsmanager')

# S3 bucket and SNS topic
BUCKET_NAME = 'traffic-monitoring-data-bucket'
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:021891607807:traffic-alerts'

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_secret(secret_name):
    try:
        response = secrets_client.get_secret_value(SecretId=secret_name)
        secret = json.loads(response['SecretString'])
        return secret
    except Exception as e:
        logger.error(f"Error retrieving secret {secret_name}: {e}")
        raise e


def lambda_handler(event, context):
    try:
        # Retrieve secrets
        # secrets = get_secret('traffic-monitoring-secrets')
        # subscription_key = secrets['subscription_key']
        subscription_key = 'EWTEjHGbbAg00mgtgcTc6EDqmaPnSsIW5RN7LahFJyo4METm7kqFJQQJ99AJACYeBjF7AiTOAAAgAZMP3spO'
        
        # Extract 'from' location, 'to' location and 'email' from the event input parameters
        from_location = event.get('from')
        to_location = event.get('to')
        email = event.get('email')

        # Fetch real-time traffic data
        url = f'https://funcappazuremap.azurewebsites.net/api/azureMapApi?code={api_access_code}'
        
        # Create the JSON payload
        payload = {
            'from': from_location,
            'to': to_location
        }

        # Send the POST request with the JSON payload
        response = requests.post(url=url,
                                json=payload,
                                headers={'subscription_key': subscription_key})
        response.raise_for_status()
        traffic_data = response.json()

        # Calculate and categorize the congestion level
        congestion_data = calculate_congestion_level(traffic_data)

        # Check for road accidents
        road_accident_data = check_road_accidents(traffic_data)

        # Extract route details
        route_details_data = extract_route_details(traffic_data)

        # Combine congestion_data, road_accident_data, route_details_data into a single json
        output_json = {
            'email': email,
            'route_details': route_details_data,
            'congestion_details': congestion_data,
            'road_accident_details': road_accident_data
        }

        # Generate a key for encryption (store this key securely)
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)

        # Encrypt the JSON data
        json_data = json.dumps(output_json).encode('utf-8')
        encrypted_data = cipher_suite.encrypt(json_data)
        
        # Save data to S3
        s3_client.put_object(
            Bucket=BUCKET_NAME,
            Key=f'traffic_data_{datetime.now().strftime("%Y%m%d%H%M%S")}.json',
            Body=encrypted_data
        )
        logger.info('Traffic data saved to S3')
        
        # Send alerts via SNS
        send_sns_alert(from_location, to_location, email, congestion_data, road_accident_data, route_details_data)
        
        return {
            'statusCode': 200,
            'body': json.dumps('Traffic data processed and alerts sent!')
        }
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching traffic data: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error fetching traffic data')
        }
    except NoCredentialsError as e:
        logger.error(f"Error with AWS credentials: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error with AWS credentials')
        }
    except boto3.exceptions.Boto3Error as e:
        logger.error(f"Error with AWS services: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error with AWS services')
        }

def calculate_congestion_level(data):
    # Extract current speed and free flow speed from the JSON data
    current_speed = data["traffic_flow"]["flowSegmentData"]["currentSpeed"]
    free_flow_speed = data["traffic_flow"]["flowSegmentData"]["freeFlowSpeed"]
    
    # Calculate the congestion level as a percentage reduction in speed
    if free_flow_speed > 0:
        congestion_level = ((free_flow_speed - current_speed) / free_flow_speed) * 100
    else:
        congestion_level = 0
    
    # Categorize the congestion level
    if congestion_level < 20:
        category = "Low"
    elif 20 <= congestion_level < 50:
        category = "Moderate"
    else:
        category = "High"
    
    return {
        "congestion_level": f"{congestion_level:.2f}%",
        "congestion_category": category
    }

def check_road_accidents(data):
    # Check if there are any points of interest (POI) in the traffic incidents data
    incidents = data["traffic_incidents"]["tm"]["poi"]
    
    msg = ''
    # If there are any POIs, it indicates road accidents or incidents
    if incidents:
        msg = 'There are road accidents.'
    else:
        msg = 'There are no road accidents.'
    
    return {
        "road_accidents": msg
    }

def extract_route_details(data):
    route_summary = data["route_details"]["routes"][0]["summary"]
    travel_mode = data["route_details"]["routes"][0]["sections"][0]["travelMode"].capitalize()
    
    # Extracting required details
    distance_km = route_summary["lengthInMeters"] / 1000
    
    # Convert travel time and traffic delay to hours, minutes, and seconds
    travel_time_seconds = route_summary["travelTimeInSeconds"]
    traffic_delay_seconds = route_summary["trafficDelayInSeconds"]
    
    travel_time_hr, travel_time_min = divmod(travel_time_seconds, 3600)
    travel_time_min, travel_time_sec = divmod(travel_time_min, 60)
    
    traffic_delay_hr, traffic_delay_min = divmod(traffic_delay_seconds, 3600)
    traffic_delay_min, traffic_delay_sec = divmod(traffic_delay_min, 60)
    
    # Convert traffic length to km if it's more than 1000 meters
    traffic_length_meters = route_summary["trafficLengthInMeters"]
    if traffic_length_meters > 1000:
        traffic_length = f"{traffic_length_meters / 1000:.2f} km"
    else:
        traffic_length = f"{traffic_length_meters} meters"
    
    departure_time = route_summary["departureTime"]
    arrival_time = route_summary["arrivalTime"]
    
    # Convert departure and arrival times to human-readable format
    departure_time = datetime.fromisoformat(departure_time).strftime('%Y-%m-%d %H:%M:%S')
    arrival_time = datetime.fromisoformat(arrival_time).strftime('%Y-%m-%d %H:%M:%S')
    
    return {
        "distance_km": distance_km,
        "travel_time": f"{travel_time_hr} hr {travel_time_min} min {travel_time_sec} sec",
        "traffic_delay": f"{traffic_delay_hr} hr {traffic_delay_min} min {traffic_delay_sec} sec",
        "traffic_length": traffic_length,
        "departure_time": departure_time,
        "arrival_time": arrival_time,
        "travel_mode": travel_mode
    }


def send_sns_alert(from_location, to_location, email, congestion_data, road_accident_data, route_details_data):
    # Create the message for SNS
    message = (
        f"__Traffic Alert:__\n\n"
        f"Route: {from_location} to {to_location}\n\n"
        f"Congestion Level: {congestion_data.get('congestion_level', 'N/A')} ({congestion_data.get('congestion_category', 'N/A')})\n\n"
        f"Road Accidents: {road_accident_data.get('road_accidents', 'N/A')}\n\n"
        "Route Details:\n"
        f"Distance: {route_details_data.get('distance_km', 'N/A')} km\n"
        f"Travel Time: {route_details_data.get('travel_time', 'N/A')} \n"
        f"Traffic Delay: {route_details_data.get('traffic_delay', 'N/A')} \n"
        f"Traffic Length: {route_details_data.get('traffic_length', 'N/A')}\n"
        f"Departure Time: {route_details_data.get('departure_time', 'N/A')}\n"
        f"Arrival Time: {route_details_data.get('arrival_time', 'N/A')}\n"
        f"Travel Mode: {route_details_data.get('travel_mode', 'N/A')}"
    )
    
    # Publish the message to the SNS topic
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject='Traffic Alert',
        MessageAttributes={
            'email': {
                'DataType': 'String',
                'StringValue': email
            }
        }
    )
    logger.info('SNS alert sent')

if __name__ == '__main__':
    event = {
        "from": "Navi Mumbai, Maharashtra",
        "to": "Agra Mumbai Road Area, Dewas, Madhya Pradesh",
        "email": "kaushikpaul90@gmail.com"
    }
    lambda_handler(event, None)
