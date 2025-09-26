import streamlit as st
import requests
from requests.auth import HTTPBasicAuth
import pandas as pd
import re
import time
import json
import csv
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
import logging
from urllib.parse import urlparse
import plotly.express as px
import plotly.graph_objects as go
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="WordPress Security Suite - Mass Email Cleaner",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://developer.wordpress.org/rest-api/',
        'Report a bug': None,
        'About': "WordPress Mass Suspicious Email Cleaner v2.0 - Advanced security tool for WordPress administrators"
    }
)

# Custom CSS for better UI
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin-bottom: 2rem;
    }
    .warning-box {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .danger-box {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        border-left: 4px solid #667eea;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'users' not in st.session_state:
    st.session_state.users = []
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []
if 'deletion_log' not in st.session_state:
    st.session_state.deletion_log = []
if 'connection_status' not in st.session_state:
    st.session_state.connection_status = False

# Header
st.markdown("""
<div class="main-header">
    <h1>🔐 WordPress Security Suite - Mass Email Cleaner</h1>
    <p>Advanced tool to scan, analyze, and clean suspicious email accounts and their content from WordPress sites</p>
</div>
""", unsafe_allow_html=True)

# Safety warning
st.markdown("""
<div class="warning-box">
    <h3>⚠️ CRITICAL SAFETY NOTICE</h3>
    <ul>
        <li><strong>ALWAYS</strong> create a full backup before running any deletion operations</li>
        <li><strong>TEST</strong> on a staging environment first</li>
        <li><strong>VERIFY</strong> your suspicious email patterns to avoid false positives</li>
        <li><strong>REVIEW</strong> all selected users and their content before deletion</li>
        <li>Deletions are <strong>IRREVERSIBLE</strong> through this tool</li>
    </ul>
</div>
""", unsafe_allow_html=True)

# Sidebar Configuration
with st.sidebar:
    st.header("🔧 Configuration")
    
    with st.expander("🌐 WordPress Connection", expanded=True):
        wp_site = st.text_input(
            "WordPress Site URL", 
            value="https://example.com",
            help="Full URL without trailing slash, e.g., https://mysite.com",
            placeholder="https://yoursite.com"
        )
        
        wp_username = st.text_input(
            "Admin Username", 
            help="WordPress admin username with user management permissions"
        )
        
        wp_app_password = st.text_input(
            "Application Password", 
            type="password",
            help="WordPress Application Password (recommended) or regular password"
        )
        
        col1, col2 = st.columns(2)
        with col1:
            use_ssl_verify = st.checkbox("Verify SSL", value=True)
        with col2:
            timeout_seconds = st.number_input("Timeout (s)", min_value=5, max_value=300, value=30)
    
    with st.expander("⚙️ Advanced Options"):
        batch_size = st.number_input("Batch Size", min_value=10, max_value=200, value=50, 
                                   help="Number of users to fetch per API request")
        
        rate_limit_delay = st.slider("Rate Limit Delay (ms)", min_value=0, max_value=2000, value=100,
                                   help="Delay between API requests to avoid rate limiting")
        
        max_workers = st.number_input("Max Concurrent Workers", min_value=1, max_value=10, value=3,
                                    help="Number of concurrent threads for batch operations")
        
        enable_logging = st.checkbox("Enable Detailed Logging", value=True)
        
        auto_backup = st.checkbox("Auto-create backups", value=True,
                                help="Automatically create CSV backups before operations")
    
    with st.expander("🗑️ Deletion Behavior"):
        deletion_mode = st.selectbox(
            "User Deletion Mode",
            options=["reassign_posts", "delete_posts", "skip_users_with_posts"],
            format_func=lambda x: {
                "reassign_posts": "Reassign posts to another user",
                "delete_posts": "Delete all user posts",
                "skip_users_with_posts": "Skip users who have posts"
            }[x]
        )
        
        if deletion_mode == "reassign_posts":
            reassign_user_id = st.text_input(
                "Reassign to User ID",
                value="1",
                help="User ID to reassign posts to (usually admin user ID = 1)"
            )
        else:
            reassign_user_id = None
        
        delete_media = st.checkbox("Delete user media files", value=False,
                                 help="Also delete media files uploaded by the user")
        
        force_delete = st.checkbox("Force delete (bypass trash)", value=True)

# Connection validation and testing
def validate_url(url: str) -> bool:
    """Validate WordPress URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def test_wp_connection(site: str, username: str, password: str, verify_ssl: bool = True) -> Tuple[bool, str]:
    """Test WordPress API connection"""
    try:
        if not validate_url(site):
            return False, "Invalid URL format"
        
        auth = HTTPBasicAuth(username, password)
        headers = {"User-Agent": "wp-security-suite/2.0"}
        
        # Test basic connectivity
        response = requests.get(
            f"{site.rstrip('/')}/wp-json/wp/v2/users/me",
            auth=auth,
            headers=headers,
            verify=verify_ssl,
            timeout=timeout_seconds
        )
        
        if response.status_code == 200:
            user_info = response.json()
            capabilities = user_info.get('capabilities', {})
            
            # Check if user has required permissions
            required_caps = ['list_users', 'delete_users', 'edit_users']
            missing_caps = [cap for cap in required_caps if not capabilities.get(cap, False)]
            
            if missing_caps:
                return False, f"Missing required capabilities: {', '.join(missing_caps)}"
            
            return True, f"Connected successfully as {user_info.get('name', username)}"
        else:
            return False, f"HTTP {response.status_code}: {response.text[:100]}"
            
    except requests.exceptions.SSLError:
        return False, "SSL certificate verification failed"
    except requests.exceptions.Timeout:
        return False, "Connection timeout"
    except requests.exceptions.ConnectionError:
        return False, "Connection failed - check URL and network"
    except Exception as e:
        return False, f"Connection error: {str(e)}"

# Test connection
if wp_site and wp_username and wp_app_password:
    if st.sidebar.button("🔌 Test Connection"):
        with st.spinner("Testing connection..."):
            success, message = test_wp_connection(wp_site, wp_username, wp_app_password, use_ssl_verify)
            if success:
                st.sidebar.success(message)
                st.session_state.connection_status = True
            else:
                st.sidebar.error(message)
                st.session_state.connection_status = False
    
    # Show connection status
    if st.session_state.connection_status:
        st.sidebar.success("✅ Connected")
    else:
        st.sidebar.warning("⚠️ Not tested")
else:
    st.sidebar.warning("⚠️ Configure connection settings")

# Main content area
if not wp_site or not wp_username or not wp_app_password:
    st.error("Please configure WordPress connection in the sidebar to continue.")
    st.stop()

# WordPress API Helper Class
class WordPressAPI:
    def __init__(self, site: str, username: str, password: str, verify_ssl: bool = True, timeout: int = 30):
        self.site = site.rstrip('/')
        self.auth = HTTPBasicAuth(username, password)
        self.headers = {"User-Agent": "wp-security-suite/2.0"}
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make authenticated request to WordPress API"""
        url = f"{self.site}/wp-json/wp/v2/{endpoint}"
        kwargs.update({
            'auth': self.auth,
            'headers': self.headers,
            'verify': self.verify_ssl,
            'timeout': self.timeout
        })
        
        response = self.session.request(method, url, **kwargs)
        
        if enable_logging:
            logger.info(f"{method} {url} - Status: {response.status_code}")
            
        response.raise_for_status()
        return response
    
    def get_users(self, page: int = 1, per_page: int = 100, **params) -> List[Dict]:
        """Fetch users with pagination"""
        params.update({'per_page': per_page, 'page': page})
        response = self._make_request('GET', 'users', params=params)
        return response.json()
    
    def get_all_users(self, progress_callback=None) -> List[Dict]:
        """Fetch all users with progress tracking"""
        users = []
        page = 1
        
        while True:
            try:
                batch = self.get_users(page=page, per_page=batch_size)
                if not batch:
                    break
                    
                users.extend(batch)
                
                if progress_callback:
                    progress_callback(len(users))
                    
                if len(batch) < batch_size:
                    break
                    
                page += 1
                time.sleep(rate_limit_delay / 1000)  # Convert ms to seconds
                
            except requests.HTTPError as e:
                if e.response.status_code == 400:  # No more pages
                    break
                raise e
                
        return users
    
    def get_user_posts(self, user_id: int, page: int = 1, per_page: int = 50) -> List[Dict]:
        """Get posts by specific user"""
        params = {'author': user_id, 'per_page': per_page, 'page': page, 'status': 'any'}
        response = self._make_request('GET', 'posts', params=params)
        return response.json()
    
    def get_all_user_posts(self, user_id: int) -> List[Dict]:
        """Get all posts by user"""
        posts = []
        page = 1
        
        while True:
            batch = self.get_user_posts(user_id, page=page)
            if not batch:
                break
            posts.extend(batch)
            if len(batch) < 50:
                break
            page += 1
            time.sleep(rate_limit_delay / 1000)
            
        return posts
    
    def get_user_media(self, user_id: int) -> List[Dict]:
        """Get media files uploaded by user"""
        params = {'author': user_id, 'per_page': 100}
        response = self._make_request('GET', 'media', params=params)
        return response.json()
    
    def delete_post(self, post_id: int, force: bool = True) -> Dict:
        """Delete a post"""
        params = {'force': str(force).lower()}
        response = self._make_request('DELETE', f'posts/{post_id}', params=params)
        return response.json()
    
    def delete_media(self, media_id: int, force: bool = True) -> Dict:
        """Delete media file"""
        params = {'force': str(force).lower()}
        response = self._make_request('DELETE', f'media/{media_id}', params=params)
        return response.json()
    
    def delete_user(self, user_id: int, reassign: Optional[int] = None, force: bool = True) -> Dict:
        """Delete a user"""
        params = {'force': str(force).lower()}
        if reassign:
            params['reassign'] = str(reassign)
            
        response = self._make_request('DELETE', f'users/{user_id}', params=params)
        return response.json()

# Initialize API client
wp_api = WordPressAPI(wp_site, wp_username, wp_app_password, use_ssl_verify, timeout_seconds)

# Suspicious Email Detection
class SuspiciousEmailDetector:
    def __init__(self):
        self.patterns = []
        self.domains = set()
        self.substrings = set()
        self.regexes = []
        
    def add_domains(self, domains: List[str]):
        """Add suspicious domains"""
        self.domains.update(d.strip().lower() for d in domains if d.strip())
    
    def add_substrings(self, substrings: List[str]):
        """Add suspicious substrings"""
        self.substrings.update(s.strip().lower() for s in substrings if s.strip())
    
    def add_regexes(self, patterns: List[str]):
        """Add regex patterns"""
        for pattern in patterns:
            if pattern.strip():
                try:
                    self.regexes.append(re.compile(pattern.strip(), re.IGNORECASE))
                except re.error as e:
                    st.error(f"Invalid regex pattern '{pattern}': {e}")
    
    def is_suspicious(self, email: str) -> Tuple[bool, List[str]]:
        """Check if email is suspicious and return reasons"""
        if not email:
            return False, []
            
        email_lower = email.lower()
        reasons = []
        
        # Check domain
        try:
            domain = email_lower.split('@', 1)[1]
            if domain in self.domains:
                reasons.append(f"Suspicious domain: {domain}")
        except IndexError:
            reasons.append("Invalid email format")
        
        # Check substrings
        for substring in self.substrings:
            if substring in email_lower:
                reasons.append(f"Contains suspicious substring: {substring}")
        
        # Check regex patterns
        for regex in self.regexes:
            if regex.search(email):
                reasons.append(f"Matches suspicious pattern: {regex.pattern}")
        
        return len(reasons) > 0, reasons

# Suspicious Email Configuration
st.header("🎯 Suspicious Email Detection Rules")

col1, col2 = st.columns([2, 1])

with col1:
    with st.expander("📝 Configure Detection Patterns", expanded=True):
        
        tab1, tab2, tab3, tab4 = st.tabs(["🌐 Domains", "🔤 Substrings", "🔍 Regex", "📦 Presets"])
        
        with tab1:
            st.markdown("**Suspicious email domains** (one per line)")
            default_domains = """mailinator.com
disposable.com
tempmail.com
10minutemail.com
guerrillamail.com
yopmail.com
throwaway.email
temp-mail.org
fake-mail.ml
sharklasers.com"""
            domains_text = st.text_area("Domains", value=default_domains, height=150)
        
        with tab2:
            st.markdown("**Suspicious substrings** in email addresses")
            default_substrings = """spam
test
bot
fake
temp
disposable
throwaway
admin
noreply"""
            substrings_text = st.text_area("Substrings", value=default_substrings, height=150)
        
        with tab3:
            st.markdown("**Regex patterns** for advanced matching")
            default_regex = r"""^user\d+@.*$
^test\d*@.*$
^admin\d*@.*$
.*\+.*@.*$
^[a-z]{1,3}\d+@.*$"""
            regex_text = st.text_area("Regex Patterns", value=default_regex, height=150)
        
        with tab4:
            st.markdown("**Quick presets** for common scenarios")
            
            if st.button("🎭 Anti-Spam Preset"):
                domains_text = """mailinator.com
guerrillamail.com
10minutemail.com
tempmail.com
yopmail.com"""
                st.rerun()
            
            if st.button("🤖 Anti-Bot Preset"):
                substrings_text = """bot
spam
fake
test
admin
noreply"""
                st.rerun()
            
            if st.button("🧪 Test Account Preset"):
                regex_text = r"""^test\d*@.*$
^user\d+@.*$
^demo\d*@.*$"""
                st.rerun()

# Initialize detector
detector = SuspiciousEmailDetector()
detector.add_domains(domains_text.splitlines())
detector.add_substrings(substrings_text.splitlines())
detector.add_regexes(regex_text.splitlines())

with col2:
    st.markdown("**🔍 Test Detection**")
    test_email = st.text_input("Test email address", placeholder="test@example.com")
    
    if test_email:
        is_sus, reasons = detector.is_suspicious(test_email)
        if is_sus:
            st.error(f"🚨 SUSPICIOUS")
            for reason in reasons:
                st.write(f"• {reason}")
        else:
            st.success("✅ Clean")

# User Scanning Section
st.header("👥 User Analysis & Scanning")

col1, col2, col3 = st.columns([2, 1, 1])

with col1:
    if st.button("🔍 Scan All Users", type="primary", use_container_width=True):
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        def update_progress(current_count):
            status_text.text(f"Fetched {current_count} users...")
            
        try:
            with st.spinner("Scanning WordPress users..."):
                users = wp_api.get_all_users(progress_callback=update_progress)
                st.session_state.users = users
                
                # Add to scan history
                scan_result = {
                    'timestamp': datetime.now(),
                    'total_users': len(users),
                    'suspicious_count': sum(1 for u in users if detector.is_suspicious(u.get('email', ''))[0])
                }
                st.session_state.scan_history.append(scan_result)
                
                progress_bar.progress(1.0)
                status_text.text(f"✅ Scan complete! Found {len(users)} users")
                
        except Exception as e:
            st.error(f"❌ Scan failed: {str(e)}")
            progress_bar.empty()
            status_text.empty()

with col2:
    if st.session_state.users:
        st.metric("Total Users", len(st.session_state.users))

with col3:
    if st.session_state.users:
        suspicious_count = sum(1 for u in st.session_state.users if detector.is_suspicious(u.get('email', ''))[0])
        st.metric("Suspicious", suspicious_count, delta=f"{suspicious_count/len(st.session_state.users)*100:.1f}%")

# Display scan results
if st.session_state.users:
    
    # Prepare user data for display
    user_data = []
    for user in st.session_state.users:
        email = user.get('email', '')
        is_suspicious, reasons = detector.is_suspicious(email)
        
        user_data.append({
            'id': user.get('id'),
            'name': user.get('name', ''),
            'username': user.get('slug', ''),
            'email': email,
            'roles': ', '.join(user.get('roles', [])),
            'registered': user.get('date_registered', ''),
            'suspicious': is_suspicious,
            'reasons': '; '.join(reasons) if reasons else '',
            'post_count': user.get('post_count', 0) if 'post_count' in user else 'Unknown'
        })
    
    df = pd.DataFrame(user_data)
    
    # Analytics Dashboard
    st.subheader("📊 User Analytics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Total Users", len(df))
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        suspicious_users = len(df[df['suspicious']])
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Suspicious Users", suspicious_users, delta=f"{suspicious_users/len(df)*100:.1f}%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        clean_users = len(df[~df['suspicious']])
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Clean Users", clean_users)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        admin_users = len(df[df['roles'].str.contains('administrator', na=False)])
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Admin Users", admin_users)
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Visualizations
    col1, col2 = st.columns(2)
    
    with col1:
        # Pie chart of user status
        fig_pie = px.pie(
            values=[suspicious_users, clean_users],
            names=['Suspicious', 'Clean'],
            title="User Security Status",
            color_discrete_map={'Suspicious': '#ff6b6b', 'Clean': '#51cf66'}
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        # Role distribution
        role_counts = df['roles'].value_counts().head(10)
        fig_bar = px.bar(
            x=role_counts.values,
            y=role_counts.index,
            orientation='h',
            title="Top User Roles",
            labels={'x': 'Count', 'y': 'Role'}
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    
    # Filtering options
    st.subheader("🔍 Filter & Review Users")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        show_filter = st.selectbox(
            "Show users:",
            ["All", "Suspicious only", "Clean only", "Admins only"],
            index=1  # Default to suspicious only
        )
    
    with col2:
        role_filter = st.selectbox(
            "Filter by role:",
            ["All roles"] + sorted(df['roles'].unique().tolist())
        )
    
    with col3:
        search_term = st.text_input("Search users:", placeholder="Email, name, username...")
    
    # Apply filters
    filtered_df = df.copy()
    
    if show_filter == "Suspicious only":
        filtered_df = filtered_df[filtered_df['suspicious']]
    elif show_filter == "Clean only":
        filtered_df = filtered_df[~filtered_df['suspicious']]
    elif show_filter == "Admins only":
        filtered_df = filtered_df[filtered_df['roles'].str.contains('administrator', na=False)]
    
    if role_filter != "All roles":
        filtered_df = filtered_df[filtered_df['roles'].str.contains(role_filter, na=False)]
    
    if search_term:
        mask = (
            filtered_df['email'].str.contains(search_term, case=False, na=False) |
            filtered_df['name'].str.contains(search_term, case=False, na=False) |
            filtered_df['username'].str.contains(search_term, case=False, na=False)
        )
        filtered_df = filtered_df[mask]
    
    # Display filtered results
    st.markdown(f"**Showing {len(filtered_df)} of {len(df)} users**")
    
    # Configure dataframe display
    column_config = {
        'suspicious': st.column_config.CheckboxColumn('Suspicious'),
        'id': st.column_config.NumberColumn('ID', width='small'),
        'email': st.column_config.TextColumn('Email', width='large'),
        'reasons': st.column_config.TextColumn('Detection Reasons', width='large'),
    }
    
    # Display the dataframe
    edited_df = st.data_editor(
        filtered_df,
        column_config=column_config,
        hide_index=True,
        height=400,
        use_container_width=True,
        key="user_selection",
        disabled=['id', 'name', 'username', 'email', 'roles', 'registered', 'reasons', 'post_count']
    )
    
    # Export options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📥 Export All Users CSV"):
            csv_data = df.to_csv(index=False)
            st.download_button(
                "Download CSV",
                data=csv_data,
                file_name=f"wp_users_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with col2:
        if st.button("📥 Export Suspicious Users CSV"):
            suspicious_df = df[df['suspicious']]
            csv_data = suspicious_df.to_csv(index=False)
            st.download_button(
                "Download Suspicious CSV",
                data=csv_data,
                file_name=f"wp_suspicious_users_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with col3:
        if st.button("📊 Generate Report"):
            # Create detailed report
            report_data = {
                'scan_timestamp': datetime.now().isoformat(),
                'total_users': len(df),
                'suspicious_users': len(df[df['suspicious']]),
                'detection_rules': {
                    'domains': domains_text.splitlines(),
                    'substrings': substrings_text.splitlines(),
                    'regex_patterns': regex_text.splitlines()
                },
                'user_details': df.to_dict(orient='records')
            }
            
            report_json = json.dumps(report_data, indent=2)
            st.download_button(
                "Download Report JSON",
                data=report_json,
                file_name=f"wp_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

# Content Analysis Section
if st.session_state.users:
    st.header("📄 Content Analysis")
    
    # Select users for content analysis
    suspicious_users_list = [u for u in st.session_state.users if detector.is_suspicious(u.get('email', ''))[0]]
    
    if suspicious_users_list:
        selected_user_ids = st.multiselect(
            "Select suspicious users to analyze their content:",
            options=[u['id'] for u in suspicious_users_list],
            default=[u['id'] for u in suspicious_users_list[:5]],  # Default to first 5
            format_func=lambda x: f"ID {x}: {next(u['name'] for u in suspicious_users_list if u['id'] == x)} ({next(u['email'] for u in suspicious_users_list if u['id'] == x)})"
        )
        
        if selected_user_ids and st.button("📊 Analyze Content"):
            content_analysis = {}
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i, user_id in enumerate(selected_user_ids):
                status_text.text(f"Analyzing user {user_id}...")
                
                try:
                    posts = wp_api.get_all_user_posts(user_id)
                    media = wp_api.get_user_media(user_id)
                    
                    content_analysis[user_id] = {
                        'posts': posts,
                        'media': media,
                        'post_count': len(posts),
                        'media_count': len(media)
                    }
                    
                except Exception as e:
                    st.error(f"Failed to analyze user {user_id}: {str(e)}")
                    content_analysis[user_id] = {
                        'posts': [],
                        'media': [],
                        'post_count': 0,
                        'media_count': 0,
                        'error': str(e)
                    }
                
                progress_bar.progress((i + 1) / len(selected_user_ids))
            
            # Display content analysis results
            st.subheader("📈 Content Analysis Results")
            
            if content_analysis:
                # Summary metrics
                total_posts = sum(data['post_count'] for data in content_analysis.values())
                total_media = sum(data['media_count'] for data in content_analysis.values())
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Users Analyzed", len(content_analysis))
                with col2:
                    st.metric("Total Posts", total_posts)
                with col3:
                    st.metric("Total Media", total_media)
                with col4:
                    avg_posts = total_posts / len(content_analysis) if content_analysis else 0
                    st.metric("Avg Posts/User", f"{avg_posts:.1f}")
                
                # Detailed breakdown
                content_details = []
                for user_id, data in content_analysis.items():
                    user_info = next((u for u in suspicious_users_list if u['id'] == user_id), {})
                    content_details.append({
                        'user_id': user_id,
                        'name': user_info.get('name', ''),
                        'email': user_info.get('email', ''),
                        'posts': data['post_count'],
                        'media': data['media_count'],
                        'has_content': data['post_count'] > 0 or data['media_count'] > 0,
                        'error': data.get('error', '')
                    })
                
                content_df = pd.DataFrame(content_details)
                st.dataframe(content_df, use_container_width=True)
                
                # Store analysis for deletion phase
                st.session_state.content_analysis = content_analysis
            
            progress_bar.empty()
            status_text.empty()

# Deletion Management Section
if st.session_state.users:
    st.header("🗑️ Deletion Management")
    
    # Safety checks
    st.markdown("""
    <div class="danger-box">
        <h3>⚠️ FINAL WARNING</h3>
        <p>You are about to permanently delete user accounts and potentially their content. This action cannot be undone through this tool.</p>
        <p><strong>Ensure you have:</strong></p>
        <ul>
            <li>✅ Complete database backup</li>
            <li>✅ Tested on staging environment</li>
            <li>✅ Verified the list of users to delete</li>
            <li>✅ Confirmed deletion settings</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    # User selection for deletion
    suspicious_users_del = [u for u in st.session_state.users if detector.is_suspicious(u.get('email', ''))[0]]
    
    if suspicious_users_del:
        st.subheader("👤 Select Users for Deletion")
        
        # Bulk selection options
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("Select All Suspicious"):
                st.session_state.selected_for_deletion = [u['id'] for u in suspicious_users_del]
        
        with col2:
            if st.button("Select No Content"):
                no_content_ids = []
                if hasattr(st.session_state, 'content_analysis'):
                    no_content_ids = [
                        user_id for user_id, data in st.session_state.content_analysis.items()
                        if data['post_count'] == 0 and data['media_count'] == 0
                    ]
                st.session_state.selected_for_deletion = no_content_ids
        
        with col3:
            if st.button("Clear Selection"):
                st.session_state.selected_for_deletion = []
        
        with col4:
            if st.button("Select Recent Only"):
                # Select users registered in last 30 days (if date available)
                recent_cutoff = datetime.now() - timedelta(days=30)
                recent_ids = []
                for u in suspicious_users_del:
                    reg_date = u.get('date_registered', '')
                    if reg_date:
                        try:
                            user_date = datetime.fromisoformat(reg_date.replace('Z', '+00:00'))
                            if user_date > recent_cutoff:
                                recent_ids.append(u['id'])
                        except:
                            pass
                st.session_state.selected_for_deletion = recent_ids
        
        # Initialize selection if not exists
        if 'selected_for_deletion' not in st.session_state:
            st.session_state.selected_for_deletion = []
        
        # Individual user selection
        deletion_candidates = []
        for user in suspicious_users_del:
            user_content_info = ""
            if hasattr(st.session_state, 'content_analysis') and user['id'] in st.session_state.content_analysis:
                analysis = st.session_state.content_analysis[user['id']]
                user_content_info = f" ({analysis['post_count']} posts, {analysis['media_count']} media)"
            
            deletion_candidates.append({
                'id': user['id'],
                'display': f"ID {user['id']}: {user['name']} ({user['email']}){user_content_info}",
                'email': user['email'],
                'name': user['name']
            })
        
        selected_user_ids = st.multiselect(
            f"Users to delete ({len(deletion_candidates)} suspicious users found):",
            options=[u['id'] for u in deletion_candidates],
            default=st.session_state.selected_for_deletion,
            format_func=lambda x: next(u['display'] for u in deletion_candidates if u['id'] == x)
        )
        
        # Update session state
        st.session_state.selected_for_deletion = selected_user_ids
        
        if selected_user_ids:
            st.info(f"Selected {len(selected_user_ids)} users for deletion")
            
            # Dry run simulation
            st.subheader("🔍 Deletion Preview (Dry Run)")
            
            if st.button("🎭 Run Dry Run Simulation"):
                dry_run_results = []
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                for i, user_id in enumerate(selected_user_ids):
                    status_text.text(f"Simulating deletion for user {user_id}...")
                    
                    user_info = next((u for u in suspicious_users_del if u['id'] == user_id), {})
                    
                    try:
                        # Simulate getting posts and media
                        posts = wp_api.get_all_user_posts(user_id)
                        media = wp_api.get_user_media(user_id) if delete_media else []
                        
                        actions = []
                        
                        if deletion_mode == "delete_posts":
                            actions.extend([f"Delete post {p['id']}: {p['title']['rendered'][:50]}..." for p in posts])
                            if delete_media:
                                actions.extend([f"Delete media {m['id']}: {m['title']['rendered']}" for m in media])
                        elif deletion_mode == "reassign_posts" and reassign_user_id:
                            if posts:
                                actions.append(f"Reassign {len(posts)} posts to user {reassign_user_id}")
                            if delete_media:
                                actions.extend([f"Delete media {m['id']}: {m['title']['rendered']}" for m in media])
                        elif deletion_mode == "skip_users_with_posts" and posts:
                            actions.append("SKIP: User has posts and skip mode enabled")
                        
                        actions.append(f"Delete user account {user_id}")
                        
                        dry_run_results.append({
                            'user_id': user_id,
                            'name': user_info.get('name', ''),
                            'email': user_info.get('email', ''),
                            'posts_count': len(posts),
                            'media_count': len(media),
                            'actions': actions,
                            'will_skip': deletion_mode == "skip_users_with_posts" and len(posts) > 0
                        })
                        
                    except Exception as e:
                        dry_run_results.append({
                            'user_id': user_id,
                            'name': user_info.get('name', ''),
                            'email': user_info.get('email', ''),
                            'posts_count': 0,
                            'media_count': 0,
                            'actions': [f"ERROR: {str(e)}"],
                            'will_skip': False
                        })
                    
                    progress_bar.progress((i + 1) / len(selected_user_ids))
                
                # Display dry run results
                st.markdown("### 📋 Deletion Plan")
                
                for result in dry_run_results:
                    with st.expander(f"User {result['user_id']}: {result['name']} ({result['email']})"):
                        if result['will_skip']:
                            st.warning("⏭️ **WILL BE SKIPPED** - Has posts and skip mode enabled")
                        else:
                            st.write(f"**Posts:** {result['posts_count']}")
                            st.write(f"**Media:** {result['media_count']}")
                            st.write("**Planned Actions:**")
                            for action in result['actions']:
                                if action.startswith("ERROR"):
                                    st.error(f"• {action}")
                                else:
                                    st.write(f"• {action}")
                
                # Summary statistics
                will_delete_count = len([r for r in dry_run_results if not r['will_skip']])
                will_skip_count = len([r for r in dry_run_results if r['will_skip']])
                total_posts_affected = sum(r['posts_count'] for r in dry_run_results if not r['will_skip'])
                total_media_affected = sum(r['media_count'] for r in dry_run_results if not r['will_skip'])
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Users to Delete", will_delete_count)
                with col2:
                    st.metric("Users to Skip", will_skip_count)
                with col3:
                    st.metric("Posts Affected", total_posts_affected)
                with col4:
                    st.metric("Media Affected", total_media_affected)
                
                # Store dry run results
                st.session_state.dry_run_results = dry_run_results
                
                progress_bar.empty()
                status_text.empty()
            
            # Backup creation
            st.subheader("💾 Create Backup")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("📦 Create Users Backup"):
                    selected_users_data = [u for u in st.session_state.users if u['id'] in selected_user_ids]
                    backup_data = {
                        'timestamp': datetime.now().isoformat(),
                        'deletion_settings': {
                            'mode': deletion_mode,
                            'reassign_to': reassign_user_id,
                            'delete_media': delete_media,
                            'force_delete': force_delete
                        },
                        'users': selected_users_data
                    }
                    
                    backup_json = json.dumps(backup_data, indent=2)
                    st.download_button(
                        "📥 Download User Backup",
                        data=backup_json,
                        file_name=f"wp_users_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True
                    )
            
            with col2:
                if st.button("📊 Create Full Report"):
                    # Create comprehensive report
                    report = {
                        'scan_info': {
                            'timestamp': datetime.now().isoformat(),
                            'wp_site': wp_site,
                            'total_users_scanned': len(st.session_state.users),
                            'suspicious_users_found': len(suspicious_users_del),
                            'users_selected_for_deletion': len(selected_user_ids)
                        },
                        'detection_rules': {
                            'domains': domains_text.splitlines(),
                            'substrings': substrings_text.splitlines(),
                            'regex_patterns': regex_text.splitlines()
                        },
                        'deletion_settings': {
                            'mode': deletion_mode,
                            'reassign_to': reassign_user_id,
                            'delete_media': delete_media,
                            'force_delete': force_delete
                        },
                        'selected_users': [u for u in st.session_state.users if u['id'] in selected_user_ids],
                        'dry_run_results': st.session_state.get('dry_run_results', [])
                    }
                    
                    report_json = json.dumps(report, indent=2)
                    st.download_button(
                        "📥 Download Full Report",
                        data=report_json,
                        file_name=f"wp_deletion_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True
                    )
            
            # Final deletion execution
            st.subheader("💥 Execute Deletion")
            
            # Multi-step confirmation
            confirm_step_1 = st.checkbox("✅ I have created a full database backup")
            confirm_step_2 = st.checkbox("✅ I have tested this process on a staging environment")
            confirm_step_3 = st.checkbox("✅ I have reviewed the dry run results and am satisfied")
            confirm_step_4 = st.checkbox("✅ I understand this action is irreversible")
            
            all_confirmed = confirm_step_1 and confirm_step_2 and confirm_step_3 and confirm_step_4
            
            if all_confirmed:
                # Final confirmation phrase
                confirmation_phrase = st.text_input(
                    "Type 'CONFIRM PERMANENT DELETION' to enable the deletion button:",
                    placeholder="CONFIRM PERMANENT DELETION"
                )
                
                if confirmation_phrase == "CONFIRM PERMANENT DELETION":
                    if st.button("🔥 EXECUTE PERMANENT DELETION", type="primary", use_container_width=True):
                        # Execute deletion with detailed logging
                        deletion_start_time = datetime.now()
                        deletion_results = {
                            'start_time': deletion_start_time,
                            'users_processed': [],
                            'errors': [],
                            'summary': {}
                        }
                        
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        results_container = st.empty()
                        
                        def execute_user_deletion(user_id: int) -> Dict:
                            """Execute deletion for a single user"""
                            result = {
                                'user_id': user_id,
                                'timestamp': datetime.now(),
                                'actions_taken': [],
                                'errors': [],
                                'success': False
                            }
                            
                            try:
                                user_info = next((u for u in suspicious_users_del if u['id'] == user_id), {})
                                
                                # Get user content
                                posts = wp_api.get_all_user_posts(user_id)
                                media = wp_api.get_user_media(user_id) if delete_media else []
                                
                                # Skip if has posts and skip mode enabled
                                if deletion_mode == "skip_users_with_posts" and posts:
                                    result['actions_taken'].append("Skipped - user has posts")
                                    result['success'] = True
                                    return result
                                
                                # Handle posts
                                if deletion_mode == "delete_posts":
                                    for post in posts:
                                        try:
                                            wp_api.delete_post(post['id'], force=force_delete)
                                            result['actions_taken'].append(f"Deleted post {post['id']}")
                                        except Exception as e:
                                            result['errors'].append(f"Failed to delete post {post['id']}: {str(e)}")
                                
                                # Handle media
                                if delete_media:
                                    for media_item in media:
                                        try:
                                            wp_api.delete_media(media_item['id'], force=force_delete)
                                            result['actions_taken'].append(f"Deleted media {media_item['id']}")
                                        except Exception as e:
                                            result['errors'].append(f"Failed to delete media {media_item['id']}: {str(e)}")
                                
                                # Delete user
                                reassign_id = int(reassign_user_id) if reassign_user_id and reassign_user_id.isdigit() else None
                                wp_api.delete_user(user_id, reassign=reassign_id, force=force_delete)
                                result['actions_taken'].append(f"Deleted user {user_id}")
                                result['success'] = True
                                
                            except Exception as e:
                                result['errors'].append(f"Failed to delete user {user_id}: {str(e)}")
                            
                            return result
                        
                        # Execute deletions
                        if max_workers > 1:
                            # Parallel execution
                            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                                future_to_user = {
                                    executor.submit(execute_user_deletion, user_id): user_id 
                                    for user_id in selected_user_ids
                                }
                                
                                completed = 0
                                for future in as_completed(future_to_user):
                                    user_id = future_to_user[future]
                                    try:
                                        result = future.result()
                                        deletion_results['users_processed'].append(result)
                                    except Exception as e:
                                        deletion_results['errors'].append(f"Failed to process user {user_id}: {str(e)}")
                                    
                                    completed += 1
                                    progress_bar.progress(completed / len(selected_user_ids))
                                    status_text.text(f"Processed {completed}/{len(selected_user_ids)} users...")
                                    
                                    # Show real-time results
                                    with results_container.container():
                                        successful = len([r for r in deletion_results['users_processed'] if r['success']])
                                        failed = len([r for r in deletion_results['users_processed'] if not r['success']])
                                        st.write(f"✅ Successful: {successful} | ❌ Failed: {failed}")
                                    
                                    time.sleep(rate_limit_delay / 1000)
                        else:
                            # Sequential execution
                            for i, user_id in enumerate(selected_user_ids):
                                status_text.text(f"Processing user {user_id} ({i+1}/{len(selected_user_ids)})...")
                                result = execute_user_deletion(user_id)
                                deletion_results['users_processed'].append(result)
                                
                                progress_bar.progress((i + 1) / len(selected_user_ids))
                                
                                # Show real-time results
                                with results_container.container():
                                    successful = len([r for r in deletion_results['users_processed'] if r['success']])
                                    failed = len([r for r in deletion_results['users_processed'] if not r['success']])
                                    st.write(f"✅ Successful: {successful} | ❌ Failed: {failed}")
                                
                                time.sleep(rate_limit_delay / 1000)
                        
                        # Final results
                        deletion_end_time = datetime.now()
                        deletion_results['end_time'] = deletion_end_time
                        deletion_results['duration'] = (deletion_end_time - deletion_start_time).total_seconds()
                        
                        # Calculate summary
                        successful_deletions = [r for r in deletion_results['users_processed'] if r['success']]
                        failed_deletions = [r for r in deletion_results['users_processed'] if not r['success']]
                        
                        deletion_results['summary'] = {
                            'total_users': len(selected_user_ids),
                            'successful': len(successful_deletions),
                            'failed': len(failed_deletions),
                            'skipped': len([r for r in successful_deletions if 'Skipped' in str(r['actions_taken'])]),
                            'total_actions': sum(len(r['actions_taken']) for r in deletion_results['users_processed']),
                            'total_errors': sum(len(r['errors']) for r in deletion_results['users_processed'])
                        }
                        
                        # Store results in session state
                        st.session_state.deletion_log.append(deletion_results)
                        
                        # Display final results
                        st.markdown("### 🎯 Deletion Complete")
                        
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.success(f"✅ Successful\n{deletion_results['summary']['successful']}")
                        with col2:
                            if deletion_results['summary']['failed'] > 0:
                                st.error(f"❌ Failed\n{deletion_results['summary']['failed']}")
                            else:
                                st.success(f"❌ Failed\n{deletion_results['summary']['failed']}")
                        with col3:
                            st.info(f"⏭️ Skipped\n{deletion_results['summary']['skipped']}")
                        with col4:
                            st.info(f"⏱️ Duration\n{deletion_results['duration']:.1f}s")
                        
                        # Detailed results
                        with st.expander("📋 Detailed Results"):
                            for result in deletion_results['users_processed']:
                                status_icon = "✅" if result['success'] else "❌"
                                st.write(f"{status_icon} **User {result['user_id']}**")
                                
                                if result['actions_taken']:
                                    st.write("Actions taken:")
                                    for action in result['actions_taken']:
                                        st.write(f"  • {action}")
                                
                                if result['errors']:
                                    st.write("Errors:")
                                    for error in result['errors']:
                                        st.error(f"  • {error}")
                                
                                st.write("---")
                        
                        # Download deletion report
                        deletion_report_json = json.dumps(deletion_results, indent=2, default=str)
                        st.download_button(
                            "📥 Download Deletion Report",
                            data=deletion_report_json,
                            file_name=f"wp_deletion_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json"
                        )
                        
                        progress_bar.empty()
                        status_text.empty()
                        
                else:
                    st.error("Type the exact confirmation phrase to enable deletion")
            else:
                st.warning("Please complete all confirmation checkboxes to proceed")

# History and Logs Section
if st.session_state.scan_history or st.session_state.deletion_log:
    st.header("📚 History & Logs")
    
    tab1, tab2 = st.tabs(["🔍 Scan History", "🗑️ Deletion Log"])
    
    with tab1:
        if st.session_state.scan_history:
            st.subheader("Previous Scans")
            
            scan_df = pd.DataFrame([
                {
                    'timestamp': scan['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'total_users': scan['total_users'],
                    'suspicious_found': scan['suspicious_count'],
                    'suspicious_percentage': f"{scan['suspicious_count']/scan['total_users']*100:.1f}%"
                }
                for scan in st.session_state.scan_history
            ])
            
            st.dataframe(scan_df, use_container_width=True)
            
            # Trend chart
            if len(st.session_state.scan_history) > 1:
                fig = px.line(
                    scan_df, 
                    x='timestamp', 
                    y='suspicious_found',
                    title='Suspicious Users Trend Over Time',
                    markers=True
                )
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No scan history available yet.")
    
    with tab2:
        if st.session_state.deletion_log:
            st.subheader("Deletion Operations")
            
            for i, log_entry in enumerate(st.session_state.deletion_log):
                with st.expander(f"Deletion #{i+1} - {log_entry['start_time'].strftime('%Y-%m-%d %H:%M:%S')}"):
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Total Users", log_entry['summary']['total_users'])
                    with col2:
                        st.metric("Successful", log_entry['summary']['successful'])
                    with col3:
                        st.metric("Failed", log_entry['summary']['failed'])
                    with col4:
                        st.metric("Duration", f"{log_entry['duration']:.1f}s")
                    
                    # Download individual log
                    log_json = json.dumps(log_entry, indent=2, default=str)
                    st.download_button(
                        f"📥 Download Log #{i+1}",
                        data=log_json,
                        file_name=f"wp_deletion_log_{i+1}_{log_entry['start_time'].strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        key=f"download_log_{i}"
                    )
        else:
            st.info("No deletion operations performed yet.")

# Footer
st.markdown("---")
st.markdown("""
### 📖 Usage Guidelines & Best Practices

**Before Running:**
- Always create a complete database backup
- Test on a staging environment first
- Review WordPress user roles and permissions
- Understand the implications of your deletion settings

**Detection Rules:**
- Start with conservative patterns and gradually expand
- Use the test feature to validate your rules
- Consider legitimate users who might match patterns
- Regular expressions are powerful but can be dangerous if too broad

**Deletion Process:**
- Run dry-run simulations first
- Start with small batches for testing
- Monitor for any unexpected behavior
- Keep detailed logs of all operations

**Recovery:**
- This tool cannot restore deleted users or content
- Always maintain external backups
- Document your deletion criteria and results
- Consider user communication before bulk deletions

**Security:**
- Use WordPress Application Passwords instead of regular passwords
- Ensure your admin account has appropriate permissions
- Monitor for rate limiting from your hosting provider
- Be aware of hosting provider backup retention policies

---

**WordPress Mass Email Cleaner v2.0** | Built for WordPress administrators | Use responsibly
""")

# Cleanup session management (optional)
if st.sidebar.button("🧹 Clear All Session Data"):
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.rerun()
