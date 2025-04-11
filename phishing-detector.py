import pandas as pd
import numpy as np
import re
import urllib.parse
import tldextract
import warnings
import email
from email.parser import BytesParser, Parser
from email.policy import default
import base64
import quopri
import chardet
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import joblib
import requests
from bs4 import BeautifulSoup
import whois
import datetime
import argparse
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("phishing_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PhishingDetector")

class EmailAnalyzer:
    """Class for extracting features from email content"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'verify', 'update', 'account', 'suspended', 'unusual activity', 'security', 
            'urgent', 'immediate', 'attention required', 'confirm', 'validate', 
            'password', 'click', 'link', 'login', 'credential', 'banking', 'payment',
            'invoice', 'tax', 'refund', 'expired', 'prize', 'won', 'winner', 'lottery'
        ]
    
    def parse_email(self, email_content, is_file=False):
        """Parse email content or file and return email object"""
        try:
            if is_file:
                with open(email_content, 'rb') as f:
                    msg = BytesParser(policy=default).parse(f)
            else:
                msg = Parser(policy=default).parsestr(email_content)
            return msg
        except Exception as e:
            logger.error(f"Error parsing email: {e}")
            return None
    
    def extract_text_from_part(self, part):
        """Extract text from an email part handling various encodings"""
        content_type = part.get_content_type()
        try:
            if content_type == 'text/plain' or content_type == 'text/html':
                charset = part.get_content_charset()
                payload = part.get_payload(decode=True)
                
                # Handle if charset is not provided
                if charset is None:
                    charset_detect = chardet.detect(payload)
                    charset = charset_detect['encoding']
                
                if charset:
                    return payload.decode(charset)
                else:
                    return payload.decode('utf-8', errors='replace')
            return ""
        except Exception as e:
            logger.warning(f"Error extracting text from email part: {e}")
            return ""
    
    def get_email_text(self, msg):
        """Extract all text from email body (plain and HTML)"""
        if msg.is_multipart():
            text_parts = []
            html_parts = []
            
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    text_parts.append(self.extract_text_from_part(part))
                elif content_type == 'text/html':
                    html_parts.append(self.extract_text_from_part(part))
            
            # Prioritize plain text, but fall back to HTML if necessary
            if text_parts:
                return '\n'.join(text_parts)
            elif html_parts:
                # Extract text from HTML
                html_text = '\n'.join(html_parts)
                soup = BeautifulSoup(html_text, 'html.parser')
                return soup.get_text()
            else:
                return ""
        else:
            return self.extract_text_from_part(msg)
    
    def extract_urls(self, email_text, html_content):
        """Extract URLs from email text and HTML content"""
        urls = []
        
        # Extract URLs from plain text
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        if email_text:
            text_urls = re.findall(url_pattern, email_text)
            urls.extend(text_urls)
        
        # Extract URLs from HTML content
        if html_content:
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    if href.startswith('http') or href.startswith('www'):
                        urls.append(href)
            except Exception as e:
                logger.warning(f"Error extracting URLs from HTML: {e}")
        
        return list(set(urls))  # Remove duplicates
    
    def extract_features(self, email_content, is_file=False):
        """Extract features from email for phishing detection"""
        features = {}
        
        # Parse email
        msg = self.parse_email(email_content, is_file)
        if not msg:
            return None
        
        # Basic email header features
        features['has_subject'] = 1 if 'subject' in msg else 0
        if 'subject' in msg:
            subject = msg['subject']
            features['subject_length'] = len(subject)
            features['subject_suspicious_words'] = sum(word.lower() in subject.lower() 
                                                    for word in self.suspicious_keywords)
        else:
            features['subject_length'] = 0
            features['subject_suspicious_words'] = 0
        
        # Sender information
        features['has_from'] = 1 if 'from' in msg else 0
        if 'from' in msg:
            from_field = msg['from']
            # Check if sender email domain matches display name domain
            if '@' in from_field:
                try:
                    display_name = from_field.split('<')[0].strip() if '<' in from_field else ""
                    email_addr = re.findall(r'[\w\.-]+@[\w\.-]+', from_field)[0]
                    domain = email_addr.split('@')[1]
                    
                    features['from_domain'] = domain
                    features['display_name_contains_domain'] = 1 if domain.lower() in display_name.lower() else 0
                    
                    # Check for free email providers often used in phishing
                    free_email_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
                    features['is_free_email'] = 1 if domain.lower() in free_email_domains else 0
                except:
                    features['from_domain'] = ""
                    features['display_name_contains_domain'] = 0
                    features['is_free_email'] = 0
            else:
                features['from_domain'] = ""
                features['display_name_contains_domain'] = 0
                features['is_free_email'] = 0
        else:
            features['from_domain'] = ""
            features['display_name_contains_domain'] = 0
            features['is_free_email'] = 0
        
        # Reply-To mismatch
        features['has_reply_to'] = 1 if 'reply-to' in msg else 0
        if 'reply-to' in msg and 'from' in msg:
            try:
                reply_to = re.findall(r'[\w\.-]+@[\w\.-]+', msg['reply-to'])[0].split('@')[1]
                from_domain = features['from_domain']
                features['reply_to_mismatch'] = 1 if from_domain and reply_to != from_domain else 0
            except:
                features['reply_to_mismatch'] = 0
        else:
            features['reply_to_mismatch'] = 0
        
        # Get email body content
        email_text = self.get_email_text(msg)
        
        # Get HTML content if available
        html_content = None
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/html':
                    html_content = self.extract_text_from_part(part)
                    break
        elif msg.get_content_type() == 'text/html':
            html_content = self.extract_text_from_part(msg)
        
        # Extract text features
        if email_text:
            features['body_length'] = len(email_text)
            features['body_suspicious_words'] = sum(word.lower() in email_text.lower() 
                                                 for word in self.suspicious_keywords)
            features['has_urgent_language'] = 1 if re.search(r'urgent|immediate|alert|attention|important', 
                                                        email_text.lower()) else 0
            features['has_misspellings'] = self.check_for_misspellings(email_text)
        else:
            features['body_length'] = 0
            features['body_suspicious_words'] = 0
            features['has_urgent_language'] = 0
            features['has_misspellings'] = 0
        
        # URL related features
        urls = self.extract_urls(email_text, html_content)
        features['url_count'] = len(urls)
        
        if urls:
            # Analyze the first URL found (often the primary call-to-action)
            primary_url = urls[0]
            try:
                url_features = self.analyze_url(primary_url)
                features.update({f"url_{k}": v for k, v in url_features.items()})
            except:
                # Default URL features if analysis fails
                features['url_length'] = 0
                features['url_suspicious_words'] = 0
                features['url_has_https'] = 0
        else:
            features['url_length'] = 0
            features['url_suspicious_words'] = 0
            features['url_has_https'] = 0
        
        # HTML specific features
        if html_content:
            html_features = self.analyze_html(html_content)
            features.update(html_features)
        else:
            features['html_has_forms'] = 0
            features['html_has_password_field'] = 0
            features['html_external_links'] = 0
        
        # Check for attachments
        features['has_attachments'] = 0
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = part.get('Content-Disposition', '')
                if 'attachment' in content_disposition:
                    features['has_attachments'] = 1
                    break
        
        # Check if email has SPF, DKIM or DMARC
        features['has_spf'] = 1 if 'received-spf' in msg else 0
        features['has_dkim'] = 1 if 'dkim-signature' in msg else 0
        features['has_dmarc'] = 1 if 'arc-authentication-results' in msg and 'dmarc=pass' in msg['arc-authentication-results'].lower() else 0
        
        return features
    
    def analyze_url(self, url):
        """Analyze a URL for phishing indicators"""
        features = {}
        features['length'] = len(url)
        features['suspicious_words'] = sum(word.lower() in url.lower() 
                                         for word in self.suspicious_keywords)
        features['has_https'] = 1 if url.startswith('https') else 0
        return features
    
    def analyze_html(self, html_content):
        """Extract features from HTML content"""
        features = {}
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Check for forms
            forms = soup.find_all('form')
            features['html_has_forms'] = 1 if forms else 0
            
            # Check for password fields
            password_fields = soup.find_all('input', {'type': 'password'})
            features['html_has_password_field'] = 1 if password_fields else 0
            
            # Count external links
            links = soup.find_all('a', href=True)
            external_links = sum(1 for link in links if link['href'].startswith('http'))
            features['html_external_links'] = external_links
            
        except Exception as e:
            logger.warning(f"Error analyzing HTML: {e}")
            features['html_has_forms'] = 0
            features['html_has_password_field'] = 0
            features['html_external_links'] = 0
        
        return features
    
    def check_for_misspellings(self, text):
        """Simple check for potential misspellings or grammar issues
        This is a simplified version - a real implementation would use a spelling library"""
        # Look for common brand names with misspellings
        misspelled_brands = [
            r'paypa[^l]', r'amaz[^o]n', r'micros[^o]ft', r'g[^o][^o]gle', 
            r'faceb[^o][^o]k', r'appl[^e]', r'netfli[^x]', r'linkedl[^n]'
        ]
        
        for pattern in misspelled_brands:
            if re.search(pattern, text.lower()):
                return 1
        
        # Quick check for doubled consonants often misused
        doubled_consonants = [r'tt', r'pp', r'cc', r'ss', r'ff', r'gg', r'll']
        words = re.findall(r'\b\w+\b', text.lower())
        
        for word in words:
            for pattern in doubled_consonants:
                if pattern in word and len(word) < 5:  # Short words with doubled consonants are suspicious
                    return 1
        
        return 0

class PhishingDetector:
    def __init__(self, model_path=None):
        """Initialize the phishing detector with an optional pre-trained model"""
        self.model = None
        self.url_vectorizer = None
        self.email_vectorizer = None
        self.scaler = None
        self.email_analyzer = EmailAnalyzer()
        
        if model_path and os.path.exists(model_path):
            try:
                self.load_model(model_path)
                logger.info(f"Model loaded from {model_path}")
            except Exception as e:
                logger.error(f"Error loading model: {e}")
        
    def extract_features(self, url, html_content=None):
        """Extract features from URL and optionally from HTML content"""
        features = {}
        
        # URL-based features
        features['url_length'] = len(url)
        features['domain_length'] = len(urllib.parse.urlparse(url).netloc)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['has_https'] = 1 if url.startswith('https') else 0
        
        # Extract domain info
        domain_info = tldextract.extract(url)
        features['domain'] = domain_info.domain
        features['suffix'] = domain_info.suffix
        
        # Additional URL features
        parsed_url = urllib.parse.urlparse(url)
        features['has_query'] = 1 if parsed_url.query else 0
        features['query_length'] = len(parsed_url.query)
        features['path_length'] = len(parsed_url.path)
        features['subdomain_length'] = len(domain_info.subdomain)
        
        # Suspicious keywords in URL
        suspicious_words = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 
                           'password', 'credential', 'authenticate', 'validation']
        features['suspicious_words'] = sum(word in url.lower() for word in suspicious_words)
        
        if html_content:
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # HTML based features
                features['form_count'] = len(soup.find_all('form'))
                features['input_count'] = len(soup.find_all('input'))
                features['a_tag_count'] = len(soup.find_all('a'))
                features['img_count'] = len(soup.find_all('img'))
                features['script_count'] = len(soup.find_all('script'))
                features['external_links'] = sum(1 for link in soup.find_all('a', href=True) 
                                              if link['href'].startswith('http') and domain_info.domain not in link['href'])
                
                # Check for password fields
                features['password_fields'] = len(soup.find_all('input', {'type': 'password'}))
                
                # Meta information
                features['has_favicon'] = 1 if soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon') else 0
                
                # HTML title
                title_tag = soup.find('title')
                features['has_title'] = 1 if title_tag else 0
                features['title_length'] = len(title_tag.text) if title_tag else 0
            except Exception as e:
                logger.warning(f"Error extracting HTML features: {e}")
                # Set default values for HTML features if extraction fails
                for feature in ['form_count', 'input_count', 'a_tag_count', 'img_count', 
                               'script_count', 'external_links', 'password_fields',
                               'has_favicon', 'has_title', 'title_length']:
                    features[feature] = 0
        else:
            # Set default values when no HTML content provided
            for feature in ['form_count', 'input_count', 'a_tag_count', 'img_count', 
                           'script_count', 'external_links', 'password_fields',
                           'has_favicon', 'has_title', 'title_length']:
                features[feature] = 0
        
        # Try to get WHOIS information
        try:
            whois_info = whois.whois(url)
            
            # Check if domain creation date exists and is valid
            if whois_info.creation_date:
                creation_date = whois_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                # Calculate domain age in days
                if isinstance(creation_date, datetime.datetime):
                    domain_age = (datetime.datetime.now() - creation_date).days
                    features['domain_age'] = domain_age
                else:
                    features['domain_age'] = -1
            else:
                features['domain_age'] = -1
                
            # Check if registrar information exists
            features['has_registrar'] = 1 if whois_info.registrar else 0
            
        except Exception:
            features['domain_age'] = -1
            features['has_registrar'] = 0
        
        return features
        
    def fetch_url_content(self, url, timeout=5):
        """Fetch HTML content from the URL with a specified timeout"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
            return response.text if response.status_code == 200 else None
        except Exception as e:
            logger.warning(f"Error fetching URL content: {e}")
            return None
    
    def prepare_features_for_model(self, features_dict, type='url'):
        """Convert features dictionary to format required by the model"""
        # Create a DataFrame from the features dictionary
        df = pd.DataFrame([features_dict])
        
        if type == 'url':
            # Extract the text features that need vectorization
            if 'domain' in df.columns:
                text_features = df['domain'].fillna('')
                
                if self.url_vectorizer:
                    # Transform text features using the pre-trained vectorizer
                    text_vectors = self.url_vectorizer.transform(text_features).toarray()
                else:
                    # Create a basic representation if vectorizer is not available
                    text_vectors = np.zeros((1, 1))
                
                # Select numerical features
                numerical_cols = [col for col in df.columns 
                                if col != 'domain' and col != 'suffix']
            else:
                text_vectors = np.zeros((1, 1))
                numerical_cols = [col for col in df.columns if col != 'suffix']
                
        elif type == 'email':
            # For email, we'll vectorize the 'from_domain' field
            if 'from_domain' in df.columns:
                text_features = df['from_domain'].fillna('')
                
                if self.email_vectorizer:
                    # Transform text features using the pre-trained vectorizer
                    text_vectors = self.email_vectorizer.transform(text_features).toarray()
                else:
                    # Create a basic representation if vectorizer is not available
                    text_vectors = np.zeros((1, 1))
                
                # Select numerical features
                numerical_cols = [col for col in df.columns 
                                if col != 'from_domain']
            else:
                text_vectors = np.zeros((1, 1))
                numerical_cols = df.columns.tolist()
        
        numerical_features = df[numerical_cols].fillna(0).values
        
        if self.scaler:
            # Scale numerical features using the pre-trained scaler
            numerical_features = self.scaler.transform(numerical_features)
        
        # Combine text and numerical features
        return np.hstack((text_vectors, numerical_features))
    
    def train(self, dataset_path, test_size=0.2, random_state=42, data_type='url'):
        """Train the phishing detection model on the provided dataset"""
        try:
            # Load dataset
            logger.info(f"Loading dataset from {dataset_path}")
            df = pd.read_csv(dataset_path)
            
            # Check required columns based on data type
            if data_type == 'url':
                if 'url' not in df.columns or 'is_phishing' not in df.columns:
                    raise ValueError("URL dataset must contain 'url' and 'is_phishing' columns")
                
                logger.info(f"URL dataset loaded with {len(df)} entries")
                
                # Extract features for each URL
                logger.info("Extracting features from URLs")
                features_list = []
                for _, row in df.iterrows():
                    url = row['url']
                    try:
                        features = self.extract_features(url)
                        features['is_phishing'] = row['is_phishing']
                        features_list.append(features)
                    except Exception as e:
                        logger.warning(f"Error extracting features for {url}: {e}")
                
                features_df = pd.DataFrame(features_list)
                
                if len(features_df) == 0:
                    raise ValueError("No valid features extracted from URL dataset")
                
                logger.info(f"Features extracted for {len(features_df)} URLs")
                
                # Prepare features and target
                X = features_df.drop(['is_phishing', 'suffix'], axis=1)
                y = features_df['is_phishing']
                
                # Save domain feature for vectorization
                domains = X['domain'].fillna('')
                X = X.drop('domain', axis=1)
                
                # Create and fit the text vectorizer
                self.url_vectorizer = CountVectorizer(max_features=100)
                domain_features = self.url_vectorizer.fit_transform(domains).toarray()
                
                # Scale numerical features
                self.scaler = StandardScaler()
                X_scaled = self.scaler.fit_transform(X)
                
                # Combine domain features and numerical features
                X_combined = np.hstack((domain_features, X_scaled))
                
            elif data_type == 'email':
                if 'email_path' not in df.columns or 'is_phishing' not in df.columns:
                    raise ValueError("Email dataset must contain 'email_path' and 'is_phishing' columns")
                
                logger.info(f"Email dataset loaded with {len(df)} entries")
                
                # Extract features for each email
                logger.info("Extracting features from emails")
                features_list = []
                for _, row in df.iterrows():
                    email_path = row['email_path']
                    try:
                        features = self.email_analyzer.extract_features(email_path, is_file=True)
                        if features:  # Skip emails that couldn't be parsed
                            features['is_phishing'] = row['is_phishing']
                            features_list.append(features)
                    except Exception as e:
                        logger.warning(f"Error extracting features for email {email_path}: {e}")
                
                features_df = pd.DataFrame(features_list)
                
                if len(features_df) == 0:
                    raise ValueError("No valid features extracted from email dataset")
                
                logger.info(f"Features extracted for {len(features_df)} emails")
                
                # Prepare features and target
                X = features_df.drop('is_phishing', axis=1)
                y = features_df['is_phishing']
                
                # Save from_domain feature for vectorization if it exists
                if 'from_domain' in X.columns:
                    domains = X['from_domain'].fillna('')
                    X = X.drop('from_domain', axis=1)
                    
                    # Create and fit the text vectorizer
                    self.email_vectorizer = TfidfVectorizer(max_features=100)
                    domain_features = self.email_vectorizer.fit_transform(domains).toarray()
                else:
                    domain_features = np.zeros((X.shape[0], 1))
                
                # Scale numerical features
                self.scaler = StandardScaler()
                X_scaled = self.scaler.fit_transform(X)
                
                # Combine domain features and numerical features
                X_combined = np.hstack((domain_features, X_scaled))
            
            # Split the dataset
            X_train, X_test, y_train, y_test = train_test_split(
                X_combined, y, test_size=test_size, random_state=random_state
            )
            
            # Train the model
            logger.info("Training the model")
            self.model = RandomForestClassifier(
                n_estimators=100, 
                max_depth=20,
                min_samples_split=5,
                random_state=random_state,
                n_jobs=-1
            )
            self.model.fit(X_train, y_train)
            
            # Evaluate the model
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            logger.info(f"Model trained successfully with accuracy: {accuracy:.4f}")
            logger.info("\nClassification Report:\n" + 
                       classification_report(y_test, y_pred))
            
            # Return evaluation metrics
            return {
                'accuracy': accuracy,
                'classification_report': classification_report(y_test, y_pred, output_dict=True),
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
            }
            
        except Exception as e:
            logger.error(f"Error during training: {e}")
            raise
    
    def save_model(self, model_dir="models"):
        """Save the trained model, vectorizers, and scaler to disk"""
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
        
        if not self.model:
            raise ValueError("No trained model available to save")
        
        model_path = os.path.join(model_dir, "phishing_model.joblib")
        url_vectorizer_path = os.path.join(model_dir, "url_vectorizer.joblib") 
        email_vectorizer_path = os.path.join(model_dir, "email_vectorizer.joblib")
        scaler_path = os.path.join(model_dir, "scaler.joblib")
        
        joblib.dump(self.model, model_path)
        
        if self.url_vectorizer:
            joblib.dump(self.url_vectorizer, url_vectorizer_path)
            
        if self.email_vectorizer:
            joblib.dump(self.email_vectorizer, email_vectorizer_path)
            
        if self.scaler:
            joblib.dump(self.scaler, scaler_path)
        
        logger.info(f"Model and related components saved to {model_dir}")
    
    def load_model(self, model_dir="models"):
        """Load a trained model, vectorizers, and scaler from disk"""
        model_path = os.path.join(model_dir, "phishing_model.joblib")
        url_vectorizer_path = os.path.join(model_dir, "url_vectorizer.joblib")
        email_vectorizer_path = os.path.join(model_dir, "email_vectorizer.joblib")
        scaler_path = os.path.join(model_dir, "scaler.joblib")
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found at {model_path}")
        
        self.model = joblib.load(model_path)
        
        if os.path.exists(url_vectorizer_path):
            self.url_vectorizer = joblib.load(url_vectorizer_path)
        
        if os.path.exists(email_vectorizer_path):
            self.email_vectorizer = joblib.load(email_vectorizer_path)
        
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
        
        logger.info(f"Model loaded from {model_dir}")
    
    def predict_url(self, url, fetch_content=True):
        """Predict if a URL is phishing or legitimate"""
        if not self.model:
            raise ValueError("Model not loaded or trained")
        
        try:
            # Get HTML content if requested
            html_content = None
            if fetch_content:
                html_content = self.fetch_url_content(url)
            
            # Extract features
            features = self.extract_features(url, html_content)
            
            # Prepare features for prediction
            X = self.prepare_features_for_model(features, type='url')
            
            # Make prediction
            prediction = self.model.predict(X)[0]
            probability = self.model.predict_proba(X)[0][1]  # Probability of being phishing
            
            return {
                'url': url,
                'is_phishing': bool(prediction),
                'probability': float(probability),
                'features': features
            }
            
        except Exception as e:
            logger.error(f"Error during URL prediction: {e}")
            raise
    
    def predict_email(self, email_content, is_file=False):
        """Predict if an email is phishing or legitimate"""
        if not self.model:
            raise ValueError("Model not loaded or trained")
            
        try:
            # Extract features from email
            features = self.email_analyzer.extract_features(email_content, is_file)
            if not features:
                return {
                    'error': 'Could not parse email content'
                }
            
            # Prepare features for prediction
            X = self.prepare_features_for_model(features, type='email')
            
            # Make prediction
            prediction = self.model.predict(X)[0]
            probability = self.model.predict_proba(X)[0][1]  # Probability of being phishing
            
            # Get URLs from email for further analysis
            email_msg = self.email_analyzer.parse_email(email_content, is_file)
            email_text = self.email_analyzer.get_email_text(email_msg)
            
            # Extract HTML content if available
            html_content = None
            if email_msg.is_multipart():
                for part in email_msg.walk():
                    if part.get_content_type() == 'text/html':
                        html_content = self.email_analyzer.extract_text_from_part(part)
                        break
            elif email_msg.get_content_type() == 'text/html':
                html_content = self.email_analyzer.extract_text_from_part(email_msg)
            
            # Extract and analyze URLs from email
            urls = self.email_analyzer.extract_urls(email_text, html_content)
            url_analysis = []
            
            for url in urls[:5]:  # Analyze up to 5 URLs to limit processing time
                try:
                    url_result = self.predict_url(url, fetch_content=False)
                    url_analysis.append({
                        'url': url,
                        'is_phishing': url_result['is_phishing'],
                        'probability': url_result['probability']
                    })
                except Exception as e:
                    url_analysis.append({
                        'url': url,
                        'error': str(e)
                    })
            
            return {
                'is_phishing': bool(prediction),
                'probability': float(probability),
                'features': features,
                'urls_found': urls,
                'url_analysis': url_analysis
            }
            
        except Exception as e:
            logger.error(f"Error during email prediction: {e}")
            raise
    
    def analyze_urls_from_file(self, file_path, output_path=None, fetch_content=True):
        """Analyze multiple URLs from a file and save results"""
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            results = []
            for url in urls:
                try:
                    result = self.predict_url(url, fetch_content)
                    results.append(result)
                    status = "PHISHING" if result['is_phishing'] else "LEGITIMATE"
                    logger.info(f"URL: {url} - {status} ({result['probability']:.2f})")
                except Exception as e:
                    logger.warning(f"Error analyzing URL {url}: {e}")
                    results.append({
                        'url': url,
                        'error': str(e)
                    })
            
            # Save results if output path is provided
            if output_path:
                with open(output_path, 'w') as f:
                    for result in results:
                        if 'error' in result:
                            f.write(f"{result['url']},ERROR,{result['error']}\n")
                        else:
                            f.write(f"{result['url']},{int(result['is_phishing'])},{result['probability']:.4f}\n")
                logger.info(f"Results saved to {output_path}")
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing URLs from file: {e}")
            raise
    
    def analyze_emails_from_directory(self, directory_path, output_path=None):
        """Analyze multiple emails from a directory and save results"""
        try:
            if not os.path.isdir(directory_path):
                raise ValueError(f"Directory not found: {directory_path}")
            
            # Get all files from directory
            email_files = [os.path.join(directory_path, f) for f in os.listdir(directory_path) 
                          if os.path.isfile(os.path.join(directory_path, f))]
            
            results = []
            for email_file in email_files:
                try:
                    result = self.predict_email(email_file, is_file=True)
                    result['filename'] = os.path.basename(email_file)
                    results.append(result)
                    status = "PHISHING" if result['is_phishing'] else "LEGITIMATE"
                    logger.info(f"Email: {email_file} - {status} ({result['probability']:.2f})")
                except Exception as e:
                    logger.warning(f"Error analyzing email {email_file}: {e}")
                    results.append({
                        'filename': os.path.basename(email_file),
                        'error': str(e)
                    })
            
            # Save results if output path is provided
            if output_path:
                with open(output_path, 'w') as f:
                    # Write header
                    f.write("filename,is_phishing,probability,urls_found\n")
                    for result in results:
                        if 'error' in result:
                            f.write(f"{result['filename']},ERROR,0.0,0\n")
                        else:
                            url_count = len(result.get('urls_found', []))
                            f.write(f"{result['filename']},{int(result['is_phishing'])},{result['probability']:.4f},{url_count}\n")
                logger.info(f"Results saved to {output_path}")
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing emails from directory: {e}")
            raise

def main():
    """Main function to handle command-line interface"""
    parser = argparse.ArgumentParser(description="Phishing Detector for URLs and Emails")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Train command
    train_parser = subparsers.add_parser("train", help="Train the model")
    train_parser.add_argument("--dataset", "-d", required=True, help="Path to dataset CSV file")
    train_parser.add_argument("--output", "-o", default="models", help="Directory to save model")
    train_parser.add_argument("--type", "-t", choices=['url', 'email'], default='url', 
                             help="Type of dataset: 'url' or 'email'")
    
    # URL prediction command
    url_parser = subparsers.add_parser("url", help="Predict if a URL is phishing")
    url_parser.add_argument("--url", "-u", help="URL to analyze")
    url_parser.add_argument("--file", "-f", help="File containing URLs to analyze (one per line)")
    url_parser.add_argument("--model", "-m", default="models", help="Directory with model files")
    url_parser.add_argument("--output", "-o", help="Path to save results")
    url_parser.add_argument("--no-fetch", action="store_true", help="Do not fetch HTML content")
    
    # Email prediction command
    email_parser = subparsers.add_parser("email", help="Predict if an email is phishing")
    email_parser.add_argument("--file", "-f", help="Path to email file")
    email_parser.add_argument("--directory", "-d", help="Directory containing email files")
    email_parser.add_argument("--model", "-m", default="models", help="Directory with model files")
    email_parser.add_argument("--output", "-o", help="Path to save results")
    
    args = parser.parse_args()
    
    if args.command == "train":
        detector = PhishingDetector()
        metrics = detector.train(args.dataset, data_type=args.type)
        detector.save_model(args.output)
        
        print(f"\nTraining completed with accuracy: {metrics['accuracy']:.4f}")
        print("\nConfusion Matrix:")
        cm = np.array(metrics['confusion_matrix'])
        print(f"TN: {cm[0,0]}, FP: {cm[0,1]}")
        print(f"FN: {cm[1,0]}, TP: {cm[1,1]}")
        
    elif args.command == "url":
        detector = PhishingDetector(args.model)
        
        if args.url:
            result = detector.predict_url(args.url, fetch_content=not args.no_fetch)
            status = "PHISHING" if result['is_phishing'] else "LEGITIMATE"
            print(f"\nURL: {args.url}")
            print(f"Status: {status}")
            print(f"Confidence: {result['probability']:.2f}")
            
            # Print some important features
            print("\nKey Features:")
            features = result['features']
            if 'suspicious_words' in features:
                print(f"- Suspicious words: {features['suspicious_words']}")
            if 'has_https' in features:
                print(f"- HTTPS: {'Yes' if features['has_https'] else 'No'}")
            if 'domain_age' in features and features['domain_age'] > 0:
                print(f"- Domain age: {features['domain_age']} days")
            if 'password_fields' in features:
                print(f"- Password fields: {features['password_fields']}")
            
        elif args.file:
            results = detector.analyze_urls_from_file(
                args.file, 
                args.output if args.output else None,
                fetch_content=not args.no_fetch
            )
            
            print(f"\nAnalyzed {len(results)} URLs:")
            phishing_count = sum(1 for r in results if 'is_phishing' in r and r['is_phishing'])
            print(f"- Phishing: {phishing_count}")
            print(f"- Legitimate: {len(results) - phishing_count - sum(1 for r in results if 'error' in r)}")
            print(f"- Errors: {sum(1 for r in results if 'error' in r)}")
            
            if args.output:
                print(f"\nResults saved to {args.output}")
        else:
            print("Error: Either --url or --file must be specified.")
            
    elif args.command == "email":
        detector = PhishingDetector(args.model)
        
        if args.file:
            result = detector.predict_email(args.file, is_file=True)
            
            if 'error' in result:
                print(f"Error analyzing email: {result['error']}")
            else:
                status = "PHISHING" if result['is_phishing'] else "LEGITIMATE"
                print(f"\nEmail: {args.file}")
                print(f"Status: {status}")
                print(f"Confidence: {result['probability']:.2f}")
                
                # Print URLs found
                urls = result.get('urls_found', [])
                if urls:
                    print(f"\nFound {len(urls)} URLs in the email:")
                    for i, url in enumerate(urls[:5], 1):  # Show up to 5 URLs
                        print(f"  {i}. {url}")
                    
                    if len(urls) > 5:
                        print(f"  ... and {len(urls) - 5} more")
                
                # Print URL analysis
                url_analysis = result.get('url_analysis', [])
                if url_analysis:
                    print("\nURL Analysis:")
                    for analysis in url_analysis:
                        if 'error' in analysis:
                            print(f"  - {analysis['url']}: Error - {analysis['error']}")
                        else:
                            status = "PHISHING" if analysis['is_phishing'] else "LEGITIMATE"
                            print(f"  - {analysis['url']}: {status} ({analysis['probability']:.2f})")
                
                # Print key features
                print("\nKey Email Features:")
                features = result['features']
                if 'subject_suspicious_words' in features:
                    print(f"- Suspicious words in subject: {features['subject_suspicious_words']}")
                if 'body_suspicious_words' in features:
                    print(f"- Suspicious words in body: {features['body_suspicious_words']}")
                if 'reply_to_mismatch' in features and features['reply_to_mismatch']:
                    print(f"- Reply-To mismatch detected")
                if 'has_urgent_language' in features and features['has_urgent_language']:
                    print(f"- Urgent language detected")
                if 'display_name_contains_domain' in features and not features['display_name_contains_domain']:
                    print(f"- Sender display name does not match domain")
                    
        elif args.directory:
            results = detector.analyze_emails_from_directory(
                args.directory,
                args.output if args.output else None
            )
            
            print(f"\nAnalyzed {len(results)} emails:")
            phishing_count = sum(1 for r in results if 'is_phishing' in r and r['is_phishing'])
            print(f"- Phishing: {phishing_count}")
            print(f"- Legitimate: {len(results) - phishing_count - sum(1 for r in results if 'error' in r)}")
            print(f"- Errors: {sum(1 for r in results if 'error' in r)}")
            
            if args.output:
                print(f"\nResults saved to {args.output}")
        else:
            print("Error: Either --file or --directory must be specified.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
