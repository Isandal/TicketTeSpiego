import streamlit as st
import database as db
import time
import datetime
import pytz

# --- Timezone Configuration ---
TIMEZONE = pytz.timezone('Europe/Rome')

def get_current_time():
    return datetime.datetime.now(TIMEZONE)

# --- Page Configuration ---
st.set_page_config(page_title="Ticket Management System", page_icon="🎫", layout="wide")

# --- Session State Initialization ---
if 'user' not in st.session_state:
    st.session_state.user = None
if 'role' not in st.session_state:
    st.session_state.role = None
if 'page' not in st.session_state:
    st.session_state.page = 'Login'

# --- Authentication Logic ---
def login():
    st.title("🔐 Login")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            user = db.authenticate_user(username, password)
            if user:
                st.session_state.user = user
                st.session_state.role = user['Role']
                st.success(f"Welcome back, {user['Username']}!")
                time.sleep(1) # Give user time to see success message
                st.rerun()
            else:
                st.error("Invalid username or password")

def logout():
    st.session_state.user = None
    st.session_state.role = None
    st.session_state.page = 'Login'
    st.rerun()

# --- Helper for Chat ---
def render_chat(ticket_id, user_id):
    st.subheader("💬 Discussion")
    messages = db.get_ticket_messages(ticket_id)
    for msg in messages:
        role = msg['Role']
        sender = msg['Username']
        content = msg['MessageContent']
        timestamp_str = msg['Timestamp']
        
        try:
            # Try to parse and localize timestamp
            # Assuming format matches what SQLite default or our inserts provide
            # If it's already localized string, this might fail or need adjustment
            # For robustness, we try to parse standard SQL formats
            try:
                dt = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                dt = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
            
            # Assume DB stores UTC or naive (treated as UTC for conversion)
            dt = pytz.utc.localize(dt)
            display_time = dt.astimezone(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            display_time = timestamp_str

        if role == 'Client':
            st.markdown(f"**👤 {sender}** ({display_time}):\n> {content}")
        else:
            st.markdown(f"**🛠️ {sender}** ({display_time}):\n> {content}")
            
    with st.form(f"chat_form_{ticket_id}"):
        new_msg = st.text_area("Reply", height=100)
        if st.form_submit_button("Send"):
            if new_msg:
                db.add_message(ticket_id, user_id, new_msg)
                st.success("Message sent!")
                st.rerun()

# --- Client Dashboard ---
def client_dashboard():
    user = st.session_state.user
    client = db.get_client_details(user['ID'])
    
    st.sidebar.title(f"👤 {user['Username']}")
    st.sidebar.caption(f"{client['CompanyName']}")
    
    menu = st.sidebar.radio("Menu", ["New Ticket", "My Tickets"])
    
    if st.sidebar.button("Logout"):
        logout()

    if menu == "New Ticket":
        st.title("📝 Submit New Ticket")
        with st.form("new_ticket_form"):
            device = st.text_input("Device Name")
            severity = st.selectbox("Severity", ["Low", "Medium", "High", "Blocking"])
            description = st.text_area("Description")
            submitted = st.form_submit_button("Submit Ticket")
            
            if submitted:
                if device and description:
                    db.create_ticket(client['ID'], device, severity, description)
                    st.success("Ticket submitted successfully!")
                else:
                    st.error("Please fill in all fields.")
                    
    elif menu == "My Tickets":
        st.title("📂 My Tickets")
        tickets = db.get_tickets_by_client(client['ID'])
        
        if not tickets:
            st.info("No tickets found.")
        else:
            for ticket in tickets:
                with st.expander(f"#{ticket['ID']} - {ticket['DeviceName']} ({ticket['Status']})"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Created:** {ticket['CreationDate']}")
                        st.write(f"**Severity:** {ticket['Severity']}")
                    with col2:
                        st.write(f"**Status:** {ticket['Status']}")
                        st.write(f"**Technician:** {ticket['TechnicianID'] if ticket['TechnicianID'] else 'Unassigned'}")
                    
                    st.write(f"**Description:**\n{ticket['Description']}")
                    
                    st.markdown("---")
                    render_chat(ticket['ID'], user['ID'])

# --- Technician Dashboard ---
def technician_dashboard():
    user = st.session_state.user
    tech = db.get_technician_details(user['ID'])
    
    st.sidebar.title(f"🛠️ {user['Username']}")
    st.sidebar.caption("Technician")
    
    menu = st.sidebar.radio("Menu", ["Ticket Pool", "My Tasks", "Work Logs"])
    
    if st.sidebar.button("Logout"):
        logout()

    if menu == "Ticket Pool":
        st.title("🏊 Ticket Pool (Open)")
        tickets = db.get_open_tickets()
        
        if not tickets:
            st.info("No open tickets.")
        else:
            for ticket in tickets:
                with st.expander(f"#{ticket['ID']} - {ticket['CompanyName']} - {ticket['DeviceName']}"):
                    st.write(f"**Severity:** {ticket['Severity']}")
                    st.write(f"**Description:** {ticket['Description']}")
                    
                    if st.button(f"Assign to Me #{ticket['ID']}"):
                        db.update_ticket_status(ticket['ID'], 'In Progress', tech['ID'])
                        st.success("Ticket assigned!")
                        st.rerun()

    elif menu == "My Tasks":
        st.title("📋 My Tasks")
        tickets = db.get_technician_tickets(tech['ID'])
        
        if not tickets:
            st.info("No tickets assigned to you.")
        else:
            for ticket in tickets:
                with st.expander(f"#{ticket['ID']} - {ticket['CompanyName']} - {ticket['DeviceName']} ({ticket['Status']})"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Created:** {ticket['CreationDate']}")
                        st.write(f"**Severity:** {ticket['Severity']}")
                    with col2:
                        st.write(f"**Status:** {ticket['Status']}")
                    
                    st.write(f"**Description:**\n{ticket['Description']}")
                    
                    # Status Change
                    current_status = ticket['Status']
                    new_status = st.selectbox(f"Change Status #{ticket['ID']}", 
                                              ['In Progress', 'Closed'], 
                                              index=['In Progress', 'Closed'].index(current_status) if current_status in ['In Progress', 'Closed'] else 0)
                    
                    if new_status != current_status:
                        if st.button(f"Update Status #{ticket['ID']}"):
                            db.update_ticket_status(ticket['ID'], new_status)
                            st.success(f"Status updated to {new_status}")
                            st.rerun()
                    
                    st.markdown("---")
                    render_chat(ticket['ID'], user['ID'])

    elif menu == "Work Logs":
        st.title("📝 Work Logs (Scheda Interventi)")
        
        # --- Work Log Form ---
        st.subheader("Log New Intervention")
        with st.form("work_log_form"):
            clients = db.get_all_clients()
            client_options = {f"{c['CompanyName']}": c['ID'] for c in clients}
            
            col1, col2 = st.columns(2)
            with col1:
                selected_client_name = st.selectbox("Client", options=list(client_options.keys()))
                intervention_type = st.selectbox("Type", ['On-site', 'Remote', 'Phone Call'])
                start_date = st.date_input("Start Date", value=get_current_time().date())
            
            with col2:
                start_time = st.time_input("Start Time", value=get_current_time().time())
                
                # Duration mapping
                duration_options = [f"{h}h {m}m" for h in range(0, 9) for m in [0, 15, 30, 45]][1:] # Skip 0h 0m
                duration_map = {f"{h}h {m}m": h*60 + m for h in range(0, 9) for m in [0, 15, 30, 45] if not (h==0 and m==0)}
                
                duration_str = st.selectbox("Duration", options=duration_options, index=3) # Default 1h
                duration_minutes = duration_map[duration_str]
                
            description = st.text_area("Description")
            
            submitted = st.form_submit_button("Save Log")
            
            if submitted:
                if selected_client_name and description:
                    client_id = client_options[selected_client_name]
                    # Combine date and time
                    start_dt = datetime.datetime.combine(start_date, start_time)
                    # Convert to string for DB (or keep as is if DB handles it, but consistency is good)
                    # Input is Rome time.
                    local_dt = TIMEZONE.localize(start_dt)
                    utc_dt = local_dt.astimezone(pytz.utc)
                    
                    db.create_work_log(tech['ID'], client_id, utc_dt, duration_minutes, description, intervention_type)
                    st.success("Work log saved successfully!")
                    st.rerun()
                else:
                    st.error("Please fill in all fields.")

        # --- Work Log List ---
        st.subheader("History")
        logs = db.get_technician_work_logs(tech['ID'])
        
        if logs:
            log_data = []
            for log in logs:
                # Convert duration minutes to H:MM
                h = log['DurationMinutes'] // 60
                m = log['DurationMinutes'] % 60
                duration_fmt = f"{h}:{m:02d}"
                
                # Convert timestamp for display
                try:
                    # Try parsing with microsecond and timezone if present
                    try:
                        dt = datetime.datetime.strptime(log['StartDateTime'], "%Y-%m-%d %H:%M:%S.%f%z")
                    except ValueError:
                        # Try without timezone
                        try:
                            dt = datetime.datetime.strptime(log['StartDateTime'], "%Y-%m-%d %H:%M:%S.%f")
                        except ValueError:
                             # Try without microsecond
                            dt = datetime.datetime.strptime(log['StartDateTime'], "%Y-%m-%d %H:%M:%S")
                except Exception:
                    dt = None
                
                if dt:
                     # Assume stored as UTC if no tzinfo, or convert if tzinfo
                    if dt.tzinfo is None:
                        dt = pytz.utc.localize(dt)
                    display_dt = dt.astimezone(TIMEZONE).strftime("%Y-%m-%d %H:%M")
                else:
                    display_dt = log['StartDateTime']

                log_data.append({
                    "Date": display_dt,
                    "Client": log['CompanyName'],
                    "Type": log['InterventionType'],
                    "Duration": duration_fmt,
                    "Description": log['Description']
                })
            
            st.dataframe(log_data, use_container_width=True)
        else:
            st.info("No work logs found.")

# --- Admin Dashboard ---
def admin_dashboard():
    st.sidebar.title(f"👑 {st.session_state.user['Username']}")
    st.sidebar.caption("Administrator")
    
    menu = st.sidebar.radio("Menu", ["Manage Technicians", "Manage Clients", "View Users", "Admin Profile"])
    
    if st.sidebar.button("Logout"):
        logout()

    if menu == "Manage Technicians":
        st.title("🛠️ Manage Technicians")
        tab1, tab2 = st.tabs(["Add New", "Edit Existing"])
        
        with tab1:
            st.subheader("Create New Technician")
            with st.form("create_tech_form"):
                col1, col2 = st.columns(2)
                with col1:
                    username = st.text_input("Username")
                    password = st.text_input("Password", type="password")
                    first_name = st.text_input("First Name")
                with col2:
                    last_name = st.text_input("Last Name")
                    email = st.text_input("Email")
                    phone = st.text_input("Phone")
                
                submitted = st.form_submit_button("Create Technician")
                
                if submitted:
                    if username and password and first_name and last_name:
                        profile_data = {
                            'FirstName': first_name,
                            'LastName': last_name,
                            'Email': email,
                            'Phone': phone
                        }
                        success, msg = db.create_user_and_profile(username, password, 'Technician', profile_data)
                        if success:
                            st.success(msg)
                        else:
                            st.error(msg)
                    else:
                        st.error("Please fill in required fields (Username, Password, Name).")

        with tab2:
            st.subheader("Edit Technician")
            techs = db.get_all_technicians()
            tech_options = {f"{t['FirstName']} {t['LastName']} ({t['Username']})": t for t in techs}
            
            selected_tech_name = st.selectbox("Select Technician", options=list(tech_options.keys()))
            
            if selected_tech_name:
                selected_tech = tech_options[selected_tech_name]
                with st.form("edit_tech_form"):
                    st.markdown("#### Profile Details")
                    col1, col2 = st.columns(2)
                    with col1:
                        new_first_name = st.text_input("First Name", value=selected_tech['FirstName'])
                        new_last_name = st.text_input("Last Name", value=selected_tech['LastName'])
                    with col2:
                        new_email = st.text_input("Email", value=selected_tech['Email'])
                        new_phone = st.text_input("Phone", value=selected_tech['Phone'])
                    
                    st.markdown("#### Credentials (Optional)")
                    col3, col4 = st.columns(2)
                    with col3:
                        new_username = st.text_input("Username", value=selected_tech['Username'])
                    with col4:
                        new_password = st.text_input("New Password (leave blank to keep current)", type="password")

                    update_submitted = st.form_submit_button("Update Technician")
                    
                    if update_submitted:
                        success, msg = db.update_technician_profile(selected_tech['ID'], new_first_name, new_last_name, new_email, new_phone, new_username, new_password)
                        if success:
                            st.success(msg)
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(msg)

    elif menu == "Manage Clients":
        st.title("🏢 Manage Clients")
        tab1, tab2 = st.tabs(["Add New", "Edit Existing"])
        
        with tab1:
            st.subheader("Create New Client")
            with st.form("create_client_form"):
                col1, col2 = st.columns(2)
                with col1:
                    username = st.text_input("Username")
                    password = st.text_input("Password", type="password")
                    company_name = st.text_input("Company Name")
                with col2:
                    email = st.text_input("Email")
                    address = st.text_input("Address")
                    phone = st.text_input("Phone")
                
                submitted = st.form_submit_button("Create Client")
                
                if submitted:
                    if username and password and company_name:
                        profile_data = {
                            'CompanyName': company_name,
                            'Email': email,
                            'Address': address,
                            'Phone': phone
                        }
                        success, msg = db.create_user_and_profile(username, password, 'Client', profile_data)
                        if success:
                            st.success(msg)
                        else:
                            st.error(msg)
                    else:
                        st.error("Please fill in required fields (Username, Password, Company Name).")

        with tab2:
            st.subheader("Edit Client")
            clients = db.get_all_clients()
            client_options = {f"{c['CompanyName']} ({c['Username']})": c for c in clients}
            
            selected_client_name = st.selectbox("Select Client", options=list(client_options.keys()))
            
            if selected_client_name:
                selected_client = client_options[selected_client_name]
                with st.form("edit_client_form"):
                    st.markdown("#### Profile Details")
                    col1, col2 = st.columns(2)
                    with col1:
                        new_company_name = st.text_input("Company Name", value=selected_client['CompanyName'])
                        new_email = st.text_input("Email", value=selected_client['Email'])
                    with col2:
                        new_address = st.text_input("Address", value=selected_client['Address'])
                        new_phone = st.text_input("Phone", value=selected_client['Phone'])
                    
                    st.markdown("#### Credentials (Optional)")
                    col3, col4 = st.columns(2)
                    with col3:
                        new_username = st.text_input("Username", value=selected_client['Username'])
                    with col4:
                        new_password = st.text_input("New Password (leave blank to keep current)", type="password")
                    
                    update_submitted = st.form_submit_button("Update Client")
                    
                    if update_submitted:
                        success, msg = db.update_client_profile(selected_client['ID'], new_company_name, new_email, new_address, new_phone, new_username, new_password)
                        if success:
                            st.success(msg)
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(msg)

    elif menu == "View Users":
        st.title("👥 All Users")
        users = db.get_all_users()
        
        # Convert to simple list of dicts for dataframe
        user_list = []
        for u in users:
            user_list.append({'ID': u['ID'], 'Username': u['Username'], 'Role': u['Role']})
            
        st.dataframe(user_list, use_container_width=True)

    elif menu == "Admin Profile":
        st.title("👤 Admin Profile")
        user = st.session_state.user
        
        with st.form("admin_profile_form"):
            st.subheader("Update Credentials")
            new_username = st.text_input("Username", value=user['Username'])
            new_password = st.text_input("New Password (leave blank to keep current)", type="password")
            
            submitted = st.form_submit_button("Update Profile")
            
            if submitted:
                success, msg = db.update_user_credentials(user['ID'], new_username, new_password)
                if success:
                    st.success(msg)
                    if new_password:
                        st.info("Password changed. Please log in again.")
                        time.sleep(2)
                        logout()
                    else:
                        # Update session state username if changed
                        st.session_state.user = db.authenticate_user(new_username, user['Password']) # Re-fetch user? No password might be hashed.
                        # Easier to just force re-login or manually update session dict if we knew the password wasn't changed.
                        # But if username changed, we should probably re-login to be safe/clean.
                        st.info("Profile updated. Please log in again.")
                        time.sleep(2)
                        logout()
                else:
                    st.error(msg)

# --- Main Routing ---
def main():
    if st.session_state.user is None:
        login()
    else:
        if st.session_state.role == 'Client':
            client_dashboard()
        elif st.session_state.role == 'Technician':
            technician_dashboard()
        elif st.session_state.role == 'Admin':
            admin_dashboard()
        else:
            st.error("Unknown Role")

if __name__ == "__main__":
    main()
