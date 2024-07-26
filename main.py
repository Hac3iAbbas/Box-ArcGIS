import os
import hmac
import hashlib
import requests
import tempfile
from fastapi import FastAPI, UploadFile, File, Request, HTTPException
from boxsdk import OAuth2, Client
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# Box API configuration
BOX_CLIENT_ID = os.getenv('BOX_CLIENT_ID')
BOX_CLIENT_SECRET = os.getenv('BOX_CLIENT_SECRET')
BOX_REDIRECT_URI = os.getenv('BOX_REDIRECT_URI')
BOX_DEVELOPER_TOKEN = os.getenv('BOX_DEVELOPER_TOKEN')
BOX_FOLDER_ID = os.getenv('BOX_FOLDER_ID')
BOX_WEBHOOK_SECRET = os.getenv('BOX_WEBHOOK_SECRET')

# Initialize Box client with OAuth2 authentication
auth = OAuth2(
    client_id=BOX_CLIENT_ID,
    client_secret=BOX_CLIENT_SECRET,
    access_token=BOX_DEVELOPER_TOKEN
)
client = Client(auth)

def get_exif_data(image):
    """
    Extract Exchangeable Image File Format (EXIF) data from an image, specifically GPS information.
    """
    exif_data = {}
    info = image._getexif()
    if info:
        for tag, value in info.items():
            tag_name = TAGS.get(tag, tag)
            if tag_name == "GPSInfo":
                gps_data = {}
                for gps_tag in value:
                    gps_tag_name = GPSTAGS.get(gps_tag, gps_tag)
                    gps_data[gps_tag_name] = value[gps_tag]
                exif_data[tag_name] = gps_data
            else:
                exif_data[tag_name] = value
    return exif_data

def get_lat_lon(exif_data):
    """
    Convert EXIF GPS data to latitude and longitude.
    """
    if "GPSInfo" in exif_data:
        gps_info = exif_data["GPSInfo"]
        gps_latitude = gps_info["GPSLatitude"]
        gps_latitude_ref = gps_info["GPSLatitudeRef"]
        gps_longitude = gps_info["GPSLongitude"]
        gps_longitude_ref = gps_info["GPSLongitudeRef"]

        lat = convert_to_degrees(gps_latitude)
        if gps_latitude_ref != "N":
            lat = 0 - lat

        lon = convert_to_degrees(gps_longitude)
        if gps_longitude_ref != "E":
            lon = 0 - lon

        return lat, lon
    return None, None

def convert_to_degrees(value):
    """
    Convert GPS coordinates to degrees.
    """
    d = float(value[0])
    m = float(value[1])
    s = float(value[2])
    return d + (m / 60.0) + (s / 3600.0)

def verify_signature(payload, signature):
    """
    Verify the signature to ensure the request is from Box.
    """
    expected_signature = hmac.new(BOX_WEBHOOK_SECRET.encode(), str(payload).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_signature, signature)

def download_and_process_file(download_url):
    """
    Download the file from Box and extract EXIF data.
    """
    headers = {'Authorization': f'Bearer {BOX_DEVELOPER_TOKEN}'}
    try:
        response = requests.get(download_url, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        
        # Use tempfile to create a temporary file location
        with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as temp_file:
            temp_file.write(response.content)
            file_location = temp_file.name
        
        # Extract EXIF data
        image = Image.open(file_location)
        exif_data = get_exif_data(image)
        latitude, longitude = get_lat_lon(exif_data)
        
        if latitude is not None and longitude is not None:
            print(f"Latitude: {latitude}, Longitude: {longitude}")
        else:
            print("No latitude/longitude found")
    
    except Exception as e:
        print(f"Error downloading or processing file: {e}")

@app.get("/")
async def read_root():
    return {"message": "Hello World"}

@app.get("/callback")
async def callback(request: Request):
    """
    OAuth2 callback route to handle the authorization response from Box.
    """
    code = request.query_params.get('code')
    if code:
        # Exchange the authorization code for an access token
        oauth2 = OAuth2(
            client_id=BOX_CLIENT_ID,
            client_secret=BOX_CLIENT_SECRET,
            store_tokens=store_tokens,
        )
        access_token, refresh_token = oauth2.authenticate(code)
        # You can now use the access token to make Box API calls
        client = Client(oauth2)
        # Do something with the client...
        return {"status": "success", "access_token": access_token}
    return {"status": "error", "message": "Authorization code not found"}

def store_tokens(access_token, refresh_token):
    # Store the tokens securely
    print(f"Access Token: {access_token}")
    print(f"Refresh Token: {refresh_token}")

@app.post("/upload-file/")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload a new file to Box.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=file.filename) as temp_file:
        temp_file.write(await file.read())
        temp_file_location = temp_file.name

    box_folder = client.folder(BOX_FOLDER_ID)
    box_file = box_folder.upload(temp_file_location)
    
    return {"filename": box_file.name, "id": box_file.id}

@app.delete("/delete-file/{file_id}")
async def delete_file(file_id: str):
    """
    Delete a file from Box using its file ID.
    """
    try:
        client.file(file_id).delete()
        return {"status": "File deleted successfully"}
    except Exception as e:
        return {"status": "Error", "message": str(e)}

@app.post("/restore-file/{file_id}")
async def restore_file(file_id: str):
    """
    Restore a deleted file from the trash in Box using its file ID.
    """
    try:
        client.file(file_id).restore()
        return {"status": "File restored successfully"}
    except Exception as e:
        return {"status": "Error", "message": str(e)}

@app.post("/webhook/box")
async def handle_box_webhook(request: Request):
    """
    Handle Box webhook events.
    Verify the payload and process upload events to extract coordinates.
    """
    payload = await request.json()
    signature = request.headers.get('Box-Signature')
    if not verify_signature(payload, signature):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    for event in payload['events']:
        if event['event_type'] == 'UPLOAD':
            file_id = event['source']['id']
            download_url = f"https://api.box.com/2.0/files/{file_id}/content"
            download_and_process_file(download_url)
    
    return {"status": "success"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
