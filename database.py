import sqlite3
import hashlib
import datetime
import os

DB_FILE = "tickets.db"

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    # --- Migration Check for Admin Role ---
    # Check if 'Admin' is allowed in Users table check constraint
    # Since we can't easily check the constraint definition directly in a robust way across versions without parsing SQL,
    # we will try to insert an Admin user in a transaction and rollback. If it fails, we migrate.
    # However, a simpler check is to see if we need to migrate by checking if the table exists and if we want to force a schema update.
    # Given the simplicity requirement, we will perform a safe migration if the table exists.
    
    # Check if Users table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Users'")
    table_exists = c.fetchone()

    if table_exists:
        # Check if we can insert a role 'Admin' (hacky but effective for this constraint)
        try:
            c.execute("BEGIN TRANSACTION")
            # We use a dummy insert that we will rollback
            c.execute("INSERT INTO Users (Username, Password, Role) VALUES ('__check_admin__', 'pass', 'Admin')")
            c.execute("ROLLBACK")
            # If we are here, 'Admin' is allowed.
        except sqlite3.IntegrityError:
            print("Migrating Users table to support Admin role...")
            c.execute("ROLLBACK")
            # Migration needed
            c.execute("ALTER TABLE Users RENAME TO Users_Old")
            
            # Create new Users table
            c.execute('''CREATE TABLE Users (
                            ID INTEGER PRIMARY KEY AUTOINCREMENT,
                            Username TEXT UNIQUE NOT NULL,
                            Password TEXT NOT NULL,
                            Role TEXT NOT NULL CHECK(Role IN ('Client', 'Technician', 'Admin'))
                        )''')
            
            # Copy data
            c.execute("INSERT INTO Users (ID, Username, Password, Role) SELECT ID, Username, Password, Role FROM Users_Old")
            c.execute("DROP TABLE Users_Old")
            conn.commit()
    else:
        # Create Users Table (New)
        c.execute('''CREATE TABLE IF NOT EXISTS Users (
                        ID INTEGER PRIMARY KEY AUTOINCREMENT,
                        Username TEXT UNIQUE NOT NULL,
                        Password TEXT NOT NULL,
                        Role TEXT NOT NULL CHECK(Role IN ('Client', 'Technician', 'Admin'))
                    )''')

    # Clients Table
    c.execute('''CREATE TABLE IF NOT EXISTS Clients (
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    UserID INTEGER UNIQUE NOT NULL,
                    CompanyName TEXT,
                    Email TEXT,
                    Address TEXT,
                    Phone TEXT,
                    FOREIGN KEY(UserID) REFERENCES Users(ID)
                )''')

    # Technicians Table
    c.execute('''CREATE TABLE IF NOT EXISTS Technicians (
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    UserID INTEGER UNIQUE NOT NULL,
                    FirstName TEXT,
                    LastName TEXT,
                    Phone TEXT,
                    Email TEXT,
                    FOREIGN KEY(UserID) REFERENCES Users(ID)
                )''')

    # Tickets Table
    c.execute('''CREATE TABLE IF NOT EXISTS Tickets (
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    ClientID INTEGER NOT NULL,
                    TechnicianID INTEGER,
                    CreationDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    DateStarted TIMESTAMP,
                    DeviceName TEXT,
                    Description TEXT,
                    Severity TEXT CHECK(Severity IN ('Low', 'Medium', 'High', 'Blocking')),
                    Status TEXT DEFAULT 'Open' CHECK(Status IN ('Open', 'In Progress', 'Closed')),
                    FOREIGN KEY(ClientID) REFERENCES Clients(ID),
                    FOREIGN KEY(TechnicianID) REFERENCES Technicians(ID)
                )''')

    # Ticket_Messages Table
    c.execute('''CREATE TABLE IF NOT EXISTS Ticket_Messages (
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    TicketID INTEGER NOT NULL,
                    SenderID INTEGER NOT NULL,
                    MessageContent TEXT NOT NULL,
                    Timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(TicketID) REFERENCES Tickets(ID),
                    FOREIGN KEY(SenderID) REFERENCES Users(ID)
                )''')

    # WorkLogs Table
    c.execute('''CREATE TABLE IF NOT EXISTS WorkLogs (
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    TechnicianID INTEGER NOT NULL,
                    ClientID INTEGER NOT NULL,
                    StartDateTime TIMESTAMP NOT NULL,
                    DurationMinutes INTEGER NOT NULL,
                    Description TEXT,
                    InterventionType TEXT CHECK(InterventionType IN ('On-site', 'Remote', 'Phone Call')),
                    FOREIGN KEY(TechnicianID) REFERENCES Technicians(ID),
                    FOREIGN KEY(ClientID) REFERENCES Clients(ID)
                )''')

    conn.commit()
    conn.close()

def populate_dummy_data():
    conn = get_db_connection()
    c = conn.cursor()

    # Check if Admin exists
    c.execute("SELECT * FROM Users WHERE Username = 'admin'")
    admin = c.fetchone()
    
    if not admin:
        # Create Admin User
        admin_pass = hash_password("admin123")
        c.execute("INSERT INTO Users (Username, Password, Role) VALUES (?, ?, ?)", ("admin", admin_pass, "Admin"))
        print("Admin user created.")
    else:
        # Ensure existing admin has Admin role (if they were a technician before)
        if admin['Role'] != 'Admin':
            c.execute("UPDATE Users SET Role = 'Admin' WHERE ID = ?", (admin['ID'],))
            print("Updated existing admin user to Admin role.")

    # Check if Tech exists (rename old admin tech if needed or create new)
    c.execute("SELECT * FROM Users WHERE Username = 'tech'")
    tech = c.fetchone()
    if not tech:
         # Create Technician User
        tech_pass = hash_password("tech123")
        c.execute("INSERT INTO Users (Username, Password, Role) VALUES (?, ?, ?)", ("tech", tech_pass, "Technician"))
        tech_user_id = c.lastrowid
        c.execute("INSERT INTO Technicians (UserID, FirstName, LastName, Phone, Email) VALUES (?, ?, ?, ?, ?)",
                  (tech_user_id, "John", "Doe", "555-0101", "tech@support.com"))
        print("Tech user created.")

    # Check if Client exists
    c.execute("SELECT * FROM Users WHERE Username = 'client'")
    client = c.fetchone()
    if not client:
        # Create Client User
        client_pass = hash_password("client123")
        c.execute("INSERT INTO Users (Username, Password, Role) VALUES (?, ?, ?)", ("client", client_pass, "Client"))
        client_user_id = c.lastrowid
        c.execute("INSERT INTO Clients (UserID, CompanyName, Email, Address, Phone) VALUES (?, ?, ?, ?, ?)",
                  (client_user_id, "Acme Corp", "contact@acme.com", "123 Business Rd", "555-0202"))
        print("Client user created.")

    conn.commit()
    conn.close()

# --- Helper Functions ---

def authenticate_user(username, password):
    conn = get_db_connection()
    c = conn.cursor()
    hashed_pw = hash_password(password)
    c.execute("SELECT * FROM Users WHERE Username = ? AND Password = ?", (username, hashed_pw))
    user = c.fetchone()
    conn.close()
    return user

def create_user_and_profile(username, password, role, profile_data):
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        hashed_pw = hash_password(password)
        c.execute("INSERT INTO Users (Username, Password, Role) VALUES (?, ?, ?)", (username, hashed_pw, role))
        user_id = c.lastrowid
        
        if role == 'Technician':
            c.execute("INSERT INTO Technicians (UserID, FirstName, LastName, Phone, Email) VALUES (?, ?, ?, ?, ?)",
                      (user_id, profile_data['FirstName'], profile_data['LastName'], profile_data['Phone'], profile_data['Email']))
        elif role == 'Client':
            c.execute("INSERT INTO Clients (UserID, CompanyName, Email, Address, Phone) VALUES (?, ?, ?, ?, ?)",
                      (user_id, profile_data['CompanyName'], profile_data['Email'], profile_data['Address'], profile_data['Phone']))
        
        conn.commit()
        return True, "User created successfully."
    except sqlite3.IntegrityError as e:
        conn.rollback()
        return False, f"Error: {str(e)}"
    finally:
        conn.close()

def get_all_users():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT ID, Username, Role FROM Users ORDER BY Role, Username")
    users = c.fetchall()
    conn.close()
    return users

def get_all_technicians():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''SELECT t.*, u.Username 
                 FROM Technicians t 
                 JOIN Users u ON t.UserID = u.ID 
                 ORDER BY u.Username''')
    techs = c.fetchall()
    conn.close()
    return techs

def get_all_clients():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''SELECT c.*, u.Username 
                 FROM Clients c 
                 JOIN Users u ON c.UserID = u.ID 
                 ORDER BY u.Username''')
    clients = c.fetchall()
    conn.close()
    return clients

def update_technician_profile(tech_id, first_name, last_name, email, phone, new_username=None, new_password=None):
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        # Update Profile
        c.execute("UPDATE Technicians SET FirstName = ?, LastName = ?, Email = ?, Phone = ? WHERE ID = ?",
                  (first_name, last_name, email, phone, tech_id))
        
        # Get UserID
        c.execute("SELECT UserID FROM Technicians WHERE ID = ?", (tech_id,))
        user_id = c.fetchone()['UserID']
        
        # Update Credentials if provided
        if new_username:
             c.execute("UPDATE Users SET Username = ? WHERE ID = ?", (new_username, user_id))
        
        if new_password:
            hashed_pw = hash_password(new_password)
            c.execute("UPDATE Users SET Password = ? WHERE ID = ?", (hashed_pw, user_id))
            
        conn.commit()
        return True, "Technician updated successfully."
    except sqlite3.IntegrityError:
        conn.rollback()
        return False, "Username already exists."
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()

def update_client_profile(client_id, company_name, email, address, phone, new_username=None, new_password=None):
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        # Update Profile
        c.execute("UPDATE Clients SET CompanyName = ?, Email = ?, Address = ?, Phone = ? WHERE ID = ?",
                  (company_name, email, address, phone, client_id))
        
        # Get UserID
        c.execute("SELECT UserID FROM Clients WHERE ID = ?", (client_id,))
        user_id = c.fetchone()['UserID']
        
        # Update Credentials if provided
        if new_username:
             c.execute("UPDATE Users SET Username = ? WHERE ID = ?", (new_username, user_id))
        
        if new_password:
            hashed_pw = hash_password(new_password)
            c.execute("UPDATE Users SET Password = ? WHERE ID = ?", (hashed_pw, user_id))
            
        conn.commit()
        return True, "Client updated successfully."
    except sqlite3.IntegrityError:
        conn.rollback()
        return False, "Username already exists."
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()

def update_user_credentials(user_id, new_username, new_password=None):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        if new_username:
            c.execute("UPDATE Users SET Username = ? WHERE ID = ?", (new_username, user_id))
        
        if new_password:
            hashed_pw = hash_password(new_password)
            c.execute("UPDATE Users SET Password = ? WHERE ID = ?", (hashed_pw, user_id))
            
        conn.commit()
        return True, "Credentials updated successfully."
    except sqlite3.IntegrityError:
        conn.rollback()
        return False, "Username already exists."
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()

def create_work_log(technician_id, client_id, start_datetime, duration_minutes, description, intervention_type):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO WorkLogs (TechnicianID, ClientID, StartDateTime, DurationMinutes, Description, InterventionType) VALUES (?, ?, ?, ?, ?, ?)",
              (technician_id, client_id, start_datetime, duration_minutes, description, intervention_type))
    conn.commit()
    conn.close()

def get_technician_work_logs(technician_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''SELECT w.*, c.CompanyName 
                 FROM WorkLogs w 
                 JOIN Clients c ON w.ClientID = c.ID 
                 WHERE w.TechnicianID = ? 
                 ORDER BY w.StartDateTime DESC''', (technician_id,))
    logs = c.fetchall()
    conn.close()
    return logs

def get_client_details(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM Clients WHERE UserID = ?", (user_id,))
    client = c.fetchone()
    conn.close()
    return client

def get_technician_details(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM Technicians WHERE UserID = ?", (user_id,))
    tech = c.fetchone()
    conn.close()
    return tech

def create_ticket(client_id, device_name, severity, description):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO Tickets (ClientID, DeviceName, Severity, Description, Status) VALUES (?, ?, ?, ?, 'Open')",
              (client_id, device_name, severity, description))
    conn.commit()
    conn.close()

def get_tickets_by_client(client_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM Tickets WHERE ClientID = ? ORDER BY CreationDate DESC", (client_id,))
    tickets = c.fetchall()
    conn.close()
    return tickets

def get_open_tickets():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''SELECT t.*, c.CompanyName 
                 FROM Tickets t 
                 JOIN Clients c ON t.ClientID = c.ID 
                 WHERE t.Status = 'Open' 
                 ORDER BY t.CreationDate ASC''')
    tickets = c.fetchall()
    conn.close()
    return tickets

def get_technician_tickets(technician_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''SELECT t.*, c.CompanyName 
                 FROM Tickets t 
                 JOIN Clients c ON t.ClientID = c.ID 
                 WHERE t.TechnicianID = ? 
                 ORDER BY t.Status, t.CreationDate DESC''', (technician_id,))
    tickets = c.fetchall()
    conn.close()
    return tickets

def update_ticket_status(ticket_id, status, technician_id=None):
    conn = get_db_connection()
    c = conn.cursor()
    if technician_id and status == 'In Progress':
         c.execute("UPDATE Tickets SET Status = ?, TechnicianID = ?, DateStarted = CURRENT_TIMESTAMP WHERE ID = ?", (status, technician_id, ticket_id))
    else:
         c.execute("UPDATE Tickets SET Status = ? WHERE ID = ?", (status, ticket_id))
    conn.commit()
    conn.close()

def add_message(ticket_id, sender_id, message):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO Ticket_Messages (TicketID, SenderID, MessageContent) VALUES (?, ?, ?)",
              (ticket_id, sender_id, message))
    conn.commit()
    conn.close()

def get_ticket_messages(ticket_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''SELECT m.*, u.Username, u.Role 
                 FROM Ticket_Messages m 
                 JOIN Users u ON m.SenderID = u.ID 
                 WHERE m.TicketID = ? 
                 ORDER BY m.Timestamp ASC''', (ticket_id,))
    messages = c.fetchall()
    conn.close()
    return messages

def get_ticket_by_id(ticket_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM Tickets WHERE ID = ?", (ticket_id,))
    ticket = c.fetchone()
    conn.close()
    return ticket

if __name__ == "__main__":
    init_db()
    populate_dummy_data()
