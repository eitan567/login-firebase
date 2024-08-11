import React, { useState, useEffect } from 'react';
import './App.css';
import {app} from './firebase';
import axios from 'axios';
import { getAuth, signInWithCustomToken, signInWithPopup, GoogleAuthProvider, FacebookAuthProvider, GithubAuthProvider, OAuthProvider, sendEmailVerification, onAuthStateChanged, signOut } from "firebase/auth";
import { getStorage, ref, uploadBytes, getDownloadURL } from "firebase/storage";

// Initialize Firebase
const auth = getAuth(app);
const storage = getStorage(app);

const LoginRegister = () => {
  const [isActive, setIsActive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState(null);
  const [error, setError] = useState(null);
  const [photoPreview, setPhotoPreview] = useState(null);
  const [verificationSent, setVerificationSent] = useState(false);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        try {
          const idToken = await firebaseUser.getIdToken();
          
          const response = await axios.post("http://localhost:5000/auth/firebase-login", {
            idToken,
          });
          
          const userData = response.data.user;
          
          // Fetch the user's photo from Firebase Storage
          if (userData.uid) {
            try {
              const photoUrl = await getDownloadURL(ref(storage, `user_photos/${userData.uid}`));
              userData.picture = photoUrl;
            } catch (error) {
              console.log("No custom photo found for user, using default if available");
              // If no custom photo, use the one from the provider if available
              if (firebaseUser.photoURL) {
                userData.picture = firebaseUser.photoURL;
              }
            }
          }

          setUser(userData);
          console.log("User signed in:", userData);
        } catch (error) {
          console.error("Error fetching user data:", error);
          setError("Failed to fetch user data. Please try logging in again.");
        }
      } else {
        setUser(null);
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const handleEmailSignUp = async (e) => {
    e.preventDefault();
    const email = e.target.email.value;
    const password = e.target.password.value;
    const displayName = e.target.name.value;
    const photoFile = e.target.photo.files[0];

    try {
      setError(null);
      setVerificationSent(false);
      setLoading(true);

      let photoURL = null;
      if (photoFile) {
        const storageRef = ref(storage, `user_photos/${email}`);
        await uploadBytes(storageRef, photoFile);
        photoURL = await getDownloadURL(storageRef);
      }

      const response = await axios.post("http://localhost:5000/auth/register", {
          email,
          password,
          display_name: displayName,
          photo_url: photoURL,
      });

      const { firebase_token, user } = response.data;

      // Sign in the user
      const userCredential = await signInWithCustomToken(auth, firebase_token);
      
      // Send email verification
      await sendEmailVerification(userCredential.user);
      setVerificationSent(true);

      setUser(null);
      console.log("User registered and verification email sent:", user);
    } catch (error) {
      console.error("Error during sign up:", error.response?.data?.detail || error.message);
      setError(error.response?.data?.detail);
    } finally {
      setLoading(false);
    }
  };

  const handleEmailSignIn = async (e) => {
    e.preventDefault();
       
    const email = e.target.email.value;
    const password = e.target.password.value;

    try {
        setLoading(true);
        setError(null);
        setVerificationSent(false);

        const response = await axios.post("http://localhost:5000/auth/login", { email, password });
        const { firebase_token, user } = response.data;

        // Sign in the user
        const userCredential = await signInWithCustomToken(auth, firebase_token);

        if (!userCredential.user.emailVerified) {
          setError("Please verify your email before signing in.");
          return;
        }

        setUser(user);
        console.log("User signed in:", user);
    } catch (error) {
        console.error("Error during sign in:", error.response?.data?.detail || error.message);
        setError(error.response?.data?.detail);
    } finally {
        setLoading(false);
    }
  };

  const fetchMicrosoftProfilePhoto = async (accessToken) => {
    try {
        const response = await axios.get("https://graph.microsoft.com/v1.0/me/photo/$value", {
            headers: {
                Authorization: `Bearer ${accessToken}`
            },
            responseType: 'arraybuffer'
        });
        
        const imageBlob = new Blob([response.data], { type: response.headers['content-type'] });
        const imageUrl = URL.createObjectURL(imageBlob);
        return imageUrl;
    } catch (error) {
        console.error("Error fetching Microsoft profile photo:", error);
        return null;
    }
  };

  const fetchFacebookProfilePhoto = async (accessToken) => {
    try {
        const response = await axios.get(`https://graph.facebook.com/me/picture?height=200&width=200&access_token=${accessToken}`, {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        });
        return response.request.responseURL;
    } catch (error) {
        console.error("Error fetching Facebook profile photo:", error);
        return null;
    }
  };

  const handleOAuthSignIn = async (providerName) => {
    try {
        let provider;
        
        setError(null);
        setVerificationSent(false);
        setLoading(true);

        switch (providerName) {
            case 'google':
                provider = new GoogleAuthProvider();                
                break;
            case 'facebook':
                provider = new FacebookAuthProvider();
                break;
            case 'github':
                provider = new GithubAuthProvider();
                break;
            case 'microsoft':
                provider = new OAuthProvider('microsoft.com');
                provider.setCustomParameters({
                   prompt: 'consent',
                   tenant: 'consumers'
                });
                provider.addScope('openid');
                provider.addScope('profile');
                break;
            default:
                throw new Error("Unsupported provider");
        }
        provider.addScope('email');

        const result = await signInWithPopup(auth, provider);
        const idToken = await result.user.getIdToken();
        
        const accessToken = result._tokenResponse.oauthAccessToken;

        let photoUrl = null;
        if (providerName === 'microsoft') {
          photoUrl = await fetchMicrosoftProfilePhoto(accessToken);
        } else if (providerName === 'facebook') {
          photoUrl = await fetchFacebookProfilePhoto(accessToken);
        } else {
          photoUrl = result.user.photoURL;
        }
        
        // Upload the photo to Firebase Storage
        if (photoUrl) {
          await uploadPhotoToFirebase(result.user.uid, photoUrl);
        }

        const response = await axios.post("http://localhost:5000/auth/firebase-login", {
            idToken,
        });
                
        const userData = response.data.user;
        if (photoUrl) {
          userData.picture = photoUrl;
        }

        setUser(userData);
        console.log("User signed in with OAuth:", userData);
    } catch (error) {
        console.error("Error during OAuth sign in:", error.response?.data?.detail || error.message);
        setError(error.response?.data?.detail || error.message);
    } finally {
        setLoading(false);
    }
  }

  const uploadPhotoToFirebase = async (uid, photoUrl) => {
    try {
      const response = await fetch(photoUrl);
      const blob = await response.blob();
      const storageRef = ref(storage, `user_photos/${uid}`);
      await uploadBytes(storageRef, blob);
      console.log("Photo uploaded successfully to Firebase Storage");
    } catch (error) {
      console.error("Error uploading photo to Firebase Storage:", error);
    }
  }

  const handleLogout = async () => {
    try {
      await signOut(auth);
      setUser(null);
      console.log("User signed out successfully");
    } catch (error) {
      console.error("Error signing out:", error);
      setError("Failed to sign out. Please try again.");
    }
  };

  const handlePhotoContainerClick = () => {
    document.querySelector('.photo-input').click();
  };

  const handlePhotoChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setPhotoPreview(URL.createObjectURL(file));
    }
  };

  return (
    <>
    {user && (
        <div className='user-login-info'>
            <div className='user-info-container'>
              <div className="user-info">
                  <h2>Logged In User</h2>
                  <p><strong>Name:</strong> {user.name}</p>
                  <p><strong>Email:</strong> {user.email}</p>
                  <p><strong>Provider:</strong> {user.provider}</p>
              </div>
              {user.picture && <img src={user.picture} alt="User profile" className='user-profile'/>}
            </div>
            <button onClick={handleLogout} className="logout-button">Logout</button>
        </div>
      )}
      {error && <p className='login-error'>{error}</p>}
      {verificationSent && (
        <div className="verification-message">
          A verification email has been sent. Please check your inbox and verify your email before signing in.
        </div>
      )}
      <div className={`container ${isActive ? 'active' : ''}`} id="container">
          <div className="form-container sign-up">
              <form onSubmit={handleEmailSignUp}>
                  <h1>Create Account</h1>
                  <div className="social-icons">
                      <a href="#" className="icons" onClick={() => handleOAuthSignIn('google')}><i className='bx bxl-google'></i></a>
                      <a href="#" className="icons" onClick={() => handleOAuthSignIn('facebook')}><i className='bx bxl-facebook'></i></a>
                      <a href="#" className="icons" onClick={() => handleOAuthSignIn('github')}><i className='bx bxl-github'></i></a>
                      <a href="#" className="icons" onClick={() => handleOAuthSignIn('microsoft')}><i className='bx bxl-microsoft'></i></a>
                  </div>
                  <span>Register with E-mail</span>
                 
                  <div className='photo-container' 
                    onClick={handlePhotoContainerClick} 
                    style={{backgroundImage: `url(${photoPreview})`, backgroundSize: 'cover'}}>
                    {!photoPreview && <span className='photo-text'>upload a photo</span>}
                  </div>

                  <input type="file" 
                    name="photo" 
                    accept="image/*" 
                    className='photo-input' 
                    style={{display: 'none'}} 
                    onChange={handlePhotoChange}/>  

                  <input type="text" name="name" placeholder="Name" required />
                  <input type="email" name="email" placeholder="Enter E-mail" required />
                  <input type="password" name="password" placeholder="Enter Password" required />
                  <button type="submit" disabled={loading}>Sign Up</button>
              </form>
          </div>

          <div className="form-container sign-in">
              <form onSubmit={handleEmailSignIn}>
                  <h1>Sign In</h1>
                  <div className="social-icons">
                      <a href="#" className="icons" onClick={() => handleOAuthSignIn('google')}><i className='bx bxl-google'></i></a>
                      <a href="#" className="icons" onClick={() => handleOAuthSignIn('facebook')}><i className='bx bxl-facebook'></i></a>
                      <a href="#" className="icons" onClick={() => handleOAuthSignIn('github')}><i className='bx bxl-github'></i></a>
                      <a href="#" className="icons" onClick={() => handleOAuthSignIn('microsoft')}><i className='bx bxl-microsoft'></i></a>
                  </div>
                  <span>Login With Email & Password</span>
                  <input type="email" name="email" placeholder="Enter E-mail" required />
                  <input type="password" name="password" placeholder="Enter Password" required />
                  <a href="#">Forget Password?</a>
                  <button type="submit" disabled={loading}>Sign In</button>
              </form>
          </div>

          <div className="toggle-container">
              <div className="toggle">
                  <div className="toggle-panel toggle-left">
                      <h1>Welcome To <br />Code with Patel</h1>
                      <p>Sign in With ID & Password</p>
                      <button className="hidden" id="login" onClick={() => setIsActive(false)} disabled={loading}>Sign In</button>
                  </div>
                  <div className="toggle-panel toggle-right">
                      <h1>Hii Coder's</h1>
                      <p>Join "Code With Patel" to Improve Your Coding Skills</p>
                      <button className="hidden" id="register" onClick={() => setIsActive(true)} disabled={loading}>Sign Up</button>
                  </div>
              </div>
          </div>
      </div>      
    </>
  );
};

export default LoginRegister;