from fastapi import FastAPI, HTTPException, Request
from firebase_admin import credentials, auth, initialize_app
from firebase_admin.exceptions import FirebaseError
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from pydantic import BaseModel
import logging

# Set up logging
logger = logging.getLogger("uvicorn.error")

# Initialize FastAPI app
app = FastAPI() 

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],  # Replace with your React app's URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Firebase Admin SDK
current_folder = Path(__file__).parent.resolve()
cred = credentials.Certificate(current_folder / "serviceAccountKey.json")
initialize_app(cred)

# Pydantic models for request data
class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    display_name: str
    photo_url: str

class OAuthToken(BaseModel):
    id_token: str

@app.middleware("http")
async def add_headers(request, call_next):
    response = await call_next(request)
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    return response

def create_firebase_token(provider_uid, provider_id, email=None):
    try:
        custom_token = auth.create_custom_token(provider_uid, {
            'provider_id': provider_id,
            'email': email
        })
        return custom_token.decode('utf-8')
    except FirebaseError as e:
        raise HTTPException(status_code=400, detail=f"Error creating Firebase token: {str(e)}")

@app.post("/auth/register")
async def register_user(user: UserRegister):
    try:
        user_record = auth.create_user(
            email=user.email,
            password=user.password,
            display_name=user.display_name,
            photo_url=user.photo_url,
            email_verified=False  # Set email_verified to False initially
        )
        
        firebase_token = create_firebase_token(user_record.uid, 'password', user.email)
        
        user_data = {
            'uid': user_record.uid,
            'email': user_record.email,
            'name': user_record.display_name,
            'picture': user_record.photo_url,
            'emailVerified': user_record.email_verified            
        }
        
        return {"firebase_token": firebase_token, "user": user_data}
    except FirebaseError as e:
        raise HTTPException(status_code=400, detail=f"Error creating user: {str(e)}")

@app.post("/auth/login")
async def login_user(user: UserLogin):
    try:
        user_record = auth.get_user_by_email(user.email)
        
        if not user_record.email_verified:
            raise HTTPException(status_code=403, detail="Email not verified. Please check your inbox and verify your email before signing in.")
        
        firebase_token = create_firebase_token(user_record.uid, 'password', user.email)
        
        user_data = {
            'uid': user_record.uid,
            'email': user_record.email,
            'name': user_record.display_name,
            'picture': user_record.photo_url,
            'emailVerified': user_record.email_verified
        }
        
        return {"firebase_token": firebase_token, "user": user_data}
    except FirebaseError as e:
        raise HTTPException(status_code=400, detail=f"Error logging in: {str(e)}")

@app.post("/auth/firebase-login")
async def firebase_login(request: Request):
    try:
        data = await request.json()
        if 'idToken' not in data:
            raise HTTPException(status_code=400, detail="ID token is missing")

        try:
            decoded_token = auth.verify_id_token(data['idToken'])
        except auth.InvalidIdTokenError:
            logger.error(f"Invalid ID token: {data['idToken']}")
            raise HTTPException(status_code=401, detail="Invalid ID token")
        except ValueError as e:
            logger.error(f"Value error in token verification: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid token format")
        
        uid = decoded_token['uid']
        
        try:
            user = auth.get_user(uid)          
            logger.info(f"Firebase user data: {user.__dict__}")
        except auth.UserNotFoundError:
            raise HTTPException(status_code=404, detail="User not found")
        
        user_data = {
            'uid': uid,
            'email': user.email or decoded_token.get('email'),
            'name': user.display_name or decoded_token.get('name'),
            'picture': data.get('photoURL') or user.photo_url or decoded_token.get('picture'),
            'emailVerified': user.email_verified,
            'provider': user.provider_id
        }
        
        if not user_data['email'] and user.provider_data:
            user_data['email'] = next((provider.email for provider in user.provider_data if provider.email), None)
        
        if user.provider_data:
            for provider in user.provider_data:
                user_data['provider'] = provider.provider_id
                if provider.provider_id == 'facebook.com':                   
                    logger.info(f"Facebook provider data: {provider.__dict__}")
                    if provider.photo_url:
                        user_data['picture'] = provider.photo_url
                    break
        
        logger.info(f"Final user data: {user_data}")
        return {"message": "Logged in successfully", "user": user_data}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Unexpected error in firebase_login: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)