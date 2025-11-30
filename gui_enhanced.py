import customtkinter as ctk
from tkinter import messagebox
import pyperclip
from password_manager import (
    check_key, new_key, read_key, backup_passwords, encrypt_with_new_key,
    save_entry, get_all_entries, get_entry_by_title, delete_entry, 
    get_categories, generate_password, write_file_atomic
)

class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("🔒 Secure Vault")
        self.geometry("450x350")
        self.resizable(True, True)
        self.minsize(450, 350)
        
        # Modern color scheme
        self.colors = {
            'primary': '#3b82f6',      # Blue
            'primary_hover': '#2563eb',
            'success': '#10b981',      # Green
            'danger': '#ef4444',       # Red
            'danger_hover': '#dc2626',
            'warning': '#f59e0b',      # Orange
            'bg_dark': '#1a1a1a',
            'bg_medium': '#2d2d2d',
            'bg_light': '#3a3a3a',
            'text_primary': '#ffffff',
            'text_secondary': '#9ca3af',
            'border': '#404040'
        }
        
        # Check if user needs to login or create account
        self.logged_in = False
        self.current_filter_category = "All"
        
        self.show_login_screen()
    
    def show_login_screen(self):
        """Show login or welcome screen"""
        self.login_frame = ctk.CTkFrame(self)
        self.login_frame.pack(pady=10, padx=5, fill="both", expand=True)
        # self.geometry("200x500")
        
        login_file_path = ".\\login.txt"
        try:
            with open(login_file_path, 'r') as file:
                login_data = file.readlines()
        except:
            login_data = []
        
        if login_data == []:
            # First time setup
            self.show_welcome_screen()
        elif login_data[0] == "logged_in\n":
            # Existing user login
            self.show_password_entry()
        else:
            exit()
    
    def show_welcome_screen(self):
        """First time setup"""
        # Icon/Logo area
        icon_frame = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        icon_frame.pack(pady=20)
        
        ctk.CTkLabel(
            icon_frame, 
            text="🔐", 
            font=("Arial", 48)
        ).pack()
        
        ctk.CTkLabel(
            self.login_frame, 
            text="Welcome to Secure Vault", 
            font=("Arial", 20, "bold"),
            text_color=self.colors['primary']
        ).pack(pady=8)
        
        ctk.CTkLabel(
            self.login_frame, 
            text="Create your master password to get started", 
            font=("Arial", 11),
            text_color=self.colors['text_secondary']
        ).pack(pady=5)
        
        # Input container
        input_frame = ctk.CTkFrame(self.login_frame, fg_color=self.colors['bg_medium'], corner_radius=12)
        input_frame.pack(pady=20, padx=40, fill="x")
        
        self.entry_key = ctk.CTkEntry(
            input_frame, 
            placeholder_text="Master password (minimum 8 characters)", 
            show="*",
            height=40,
            font=("Arial", 12),
            border_width=0,
            corner_radius=8
        )
        self.entry_key.pack(pady=(15, 8), padx=15, fill="x")
        
        self.reentry_key = ctk.CTkEntry(
            input_frame, 
            placeholder_text="Confirm master password", 
            show="*",
            height=40,
            font=("Arial", 12),
            border_width=0,
            corner_radius=8
        )
        self.reentry_key.pack(pady=(8, 15), padx=15, fill="x")
        
        submit_button = ctk.CTkButton(
            self.login_frame, 
            text="Create Vault",
            command=self.welcome_submit,
            width=200,
            height=42,
            font=("Arial", 13, "bold"),
            fg_color=self.colors['primary'],
            hover_color=self.colors['primary_hover'],
            corner_radius=8
        )
        submit_button.pack(pady=15)
        
        # Info text
        ctk.CTkLabel(
            self.login_frame,
            text="💡 Choose a strong password you won't forget.",
            font=("Arial", 10),
            text_color=self.colors['text_secondary'],
            justify="center"
        ).pack(pady=8)
        
        self.error_label = None
        self.bind('<Return>', lambda e: self.welcome_submit())
    
    def show_password_entry(self):
        """Login screen for existing users"""
        # Icon/Logo area
        icon_frame = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        icon_frame.pack(pady=30)
        
        ctk.CTkLabel(
            icon_frame, 
            text="🔒 Secure Vault", 
            font=("Arial", 30, "bold")
        ).pack()
        
        ctk.CTkLabel(
            self.login_frame, 
            text="Enter your master password to unlock", 
            font=("Arial", 11),
            text_color=self.colors['text_secondary']
        ).pack(pady=2)
        
        # Input container
        input_frame = ctk.CTkFrame(self.login_frame, fg_color=self.colors['bg_medium'], corner_radius=12)
        input_frame.pack(pady=25, padx=50, fill="x")
        
        self.entry_key = ctk.CTkEntry(
            input_frame, 
            placeholder_text="Master password", 
            show="*",
            height=42,
            font=("Arial", 12),
            border_width=0,
            corner_radius=8
        )
        self.entry_key.pack(pady=5, padx=5, fill="x")
        
        submit_button = ctk.CTkButton(
            self.login_frame, 
            text="🔓 Unlock Vault",
            command=self.login_submit,
            width=200,
            height=42,
            font=("Arial", 13, "bold"),
            fg_color=self.colors['primary'],
            hover_color=self.colors['primary_hover'],
            corner_radius=8
        )
        submit_button.pack(pady=10)
        
        self.error_label = None
        self.bind('<Return>', lambda e: self.login_submit())
    
    def welcome_submit(self):
        """Handle first time setup"""
        user_input = self.entry_key.get()
        reuser_input = self.reentry_key.get()
        
        if user_input == "" or len(user_input) < 8:
            self.show_error("Master password must be at least 8 characters long.")
            return
        
        if user_input != reuser_input:
            self.show_error("Passwords don't match. Try again.")
            return
        
        new_key(user_input)
        self.show_main_screen()
    
    def login_submit(self):
        """Handle login"""
        user_input = self.entry_key.get()
        
        if check_key(user_input):
            self.show_main_screen()
        else:
            self.show_error("Wrong password. Try again.")
    
    def show_error(self, message):
        """Show error message"""
        if self.error_label:
            self.error_label.destroy()
        self.error_label = ctk.CTkLabel(
            self.login_frame, 
            text=message, 
            text_color="red"
        )
        self.error_label.pack(pady=10)
        self.entry_key.delete(0, "end")
        if hasattr(self, 'reentry_key'):
            self.reentry_key.delete(0, "end")
    
    def show_main_screen(self):
        """Show main application interface"""
        self.logged_in = True
        self.unbind('<Return>')
        self.login_frame.destroy()
        
        # Don't reset geometry - let user's window size persist
        self.geometry("1000x600")
        
        # Main container with gradient-like background
        self.main_frame = ctk.CTkFrame(self, fg_color=self.colors['bg_dark'])
        self.main_frame.pack(pady=0, padx=0, fill="both", expand=True)
        
        # Top bar with modern design
        top_bar = ctk.CTkFrame(self.main_frame, fg_color=self.colors['bg_medium'], height=70, corner_radius=0)
        top_bar.pack(fill="x", padx=0, pady=0)
        top_bar.pack_propagate(False)
        
        # Left side - Logo and title
        left_section = ctk.CTkFrame(top_bar, fg_color="transparent")
        left_section.pack(side="left", padx=20, pady=15)
        
        ctk.CTkLabel(
            left_section, 
            text="🔐", 
            font=("Arial", 28)
        ).pack(side="left", padx=(0, 10))
        
        title_frame = ctk.CTkFrame(left_section, fg_color="transparent")
        title_frame.pack(side="left")
        
        ctk.CTkLabel(
            title_frame, 
            text="Secure Vault", 
            font=("Arial", 20, "bold"),
            text_color=self.colors['text_primary']
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            title_frame,
            text="Your encrypted password manager",
            font=("Arial", 10),
            text_color=self.colors['text_secondary']
        ).pack(anchor="w")
        
        # Right side - Action buttons
        right_section = ctk.CTkFrame(top_bar, fg_color="transparent")
        right_section.pack(side="right", padx=20, pady=15)
        
        ctk.CTkButton(
            right_section, 
            text="🔑 Change Password", 
            command=self.change_master_password,
            width=160,
            height=35,
            fg_color=self.colors['bg_light'],
            hover_color=self.colors['bg_dark'],
            corner_radius=8,
            font=("Arial", 12)
        ).pack(side="right", padx=5)
        
        ctk.CTkButton(
            right_section, 
            text="🔄", 
            command=self.refresh_entries,
            width=35,
            height=35,
            fg_color=self.colors['bg_light'],
            hover_color=self.colors['bg_dark'],
            corner_radius=8,
            font=("Arial", 16)
        ).pack(side="right", padx=5)
        
        # Search and filter bar with modern design
        filter_frame = ctk.CTkFrame(self.main_frame, fg_color=self.colors['bg_medium'], corner_radius=12)
        filter_frame.pack(fill="x", padx=20, pady=(15, 10))
        
        filter_inner = ctk.CTkFrame(filter_frame, fg_color="transparent")
        filter_inner.pack(fill="x", padx=15, pady=12)
        
        # Search section
        search_section = ctk.CTkFrame(filter_inner, fg_color="transparent")
        search_section.pack(side="left", fill="x", expand=True)
        
        ctk.CTkLabel(
            search_section, 
            text="🔍", 
            font=("Arial", 18)
        ).pack(side="left", padx=(0, 8))
        
        self.search_var = ctk.StringVar()
        self.search_var.trace("w", lambda *args: self.filter_entries())
        search_entry = ctk.CTkEntry(
            search_section, 
            textvariable=self.search_var, 
            placeholder_text="Search entries by title...",
            height=40,
            font=("Arial", 13),
            border_width=0,
            fg_color=self.colors['bg_light'],
            corner_radius=8
        )
        search_entry.pack(side="left", fill="x", expand=True, padx=5)
        
        # Category filter
        category_section = ctk.CTkFrame(filter_inner, fg_color="transparent")
        category_section.pack(side="right", padx=(15, 0))
        
        ctk.CTkLabel(
            category_section, 
            text="📁 Category:", 
            font=("Arial", 12),
            text_color=self.colors['text_secondary']
        ).pack(side="left", padx=(0, 8))
        
        self.category_var = ctk.StringVar(value="All")
        self.category_menu = ctk.CTkOptionMenu(
            category_section,
            variable=self.category_var,
            values=["All"] + get_categories(),
            command=lambda x: self.filter_entries(),
            width=180,
            height=40,
            fg_color=self.colors['bg_light'],
            button_color=self.colors['bg_light'],
            button_hover_color=self.colors['bg_dark'],
            dropdown_fg_color=self.colors['bg_medium'],
            corner_radius=8,
            font=("Arial", 12)
        )
        self.category_menu.pack(side="left")
        
        # Content area with scrollable list
        content_frame = ctk.CTkFrame(self.main_frame, fg_color=self.colors['bg_medium'], corner_radius=12)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Headers with modern styling
        headers_frame = ctk.CTkFrame(content_frame, fg_color=self.colors['bg_dark'], corner_radius=0)
        headers_frame.pack(fill="x", padx=0, pady=0)
        
        headers_inner = ctk.CTkFrame(headers_frame, fg_color="transparent")
        headers_inner.pack(fill="x", padx=20, pady=12)
        
        ctk.CTkLabel(
            headers_inner, 
            text="TITLE", 
            font=("Arial", 11, "bold"), 
            text_color=self.colors['text_secondary'],
            width=250,
            anchor="w"
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkLabel(
            headers_inner, 
            text="USERNAME", 
            font=("Arial", 11, "bold"), 
            text_color=self.colors['text_secondary'],
            width=220,
            anchor="w"
        ).pack(side="left", padx=10)
        
        ctk.CTkLabel(
            headers_inner, 
            text="CATEGORY", 
            font=("Arial", 11, "bold"), 
            text_color=self.colors['text_secondary'],
            width=130,
            anchor="w"
        ).pack(side="left", padx=10)
        
        ctk.CTkLabel(
            headers_inner, 
            text="ACTIONS", 
            font=("Arial", 11, "bold"), 
            text_color=self.colors['text_secondary'],
            anchor="e"
        ).pack(side="right", padx=10)
        
        # Scrollable entries list with custom scrollbar
        self.entries_scroll = ctk.CTkScrollableFrame(
            content_frame, 
            fg_color=self.colors['bg_dark'],
            corner_radius=0,
            scrollbar_button_color=self.colors['bg_light'],
            scrollbar_button_hover_color=self.colors['bg_medium']
        )
        self.entries_scroll.pack(fill="both", expand=True, padx=0, pady=(0, 0))
        
        # Bottom action buttons with modern gradient-style
        action_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        action_frame.pack(fill="x", padx=20, pady=(10, 15))
        
        ctk.CTkButton(
            action_frame, 
            text="➕  Add New Entry", 
            command=self.add_entry_dialog,
            width=200,
            height=50,
            font=("Arial", 14, "bold"),
            fg_color=self.colors['primary'],
            hover_color=self.colors['primary_hover'],
            corner_radius=10
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            action_frame, 
            text="🎲  Generate Password", 
            command=self.generate_password_dialog,
            width=200,
            height=50,
            font=("Arial", 14, "bold"),
            fg_color=self.colors['success'],
            hover_color="#059669",
            corner_radius=10
        ).pack(side="left", padx=5)
        
        # Stats display
        stats_frame = ctk.CTkFrame(action_frame, fg_color="transparent")
        stats_frame.pack(side="right", padx=10)
        
        entries_count = len(get_all_entries())
        ctk.CTkLabel(
            stats_frame,
            text=f"📊 {entries_count} entries stored",
            font=("Arial", 12),
            text_color=self.colors['text_secondary']
        ).pack()
        
        # Load entries
        self.refresh_entries()
        backup_passwords()
    
    def refresh_entries(self):
        """Reload and display all entries"""
        # Update category menu
        categories = ["All"] + get_categories()
        self.category_menu.configure(values=categories)
        
        self.filter_entries()
    
    def filter_entries(self):
        """Filter and display entries based on search and category"""
        # Clear current entries
        for widget in self.entries_scroll.winfo_children():
            widget.destroy()
        
        # Get all entries
        all_entries = get_all_entries()
        
        # Filter by search
        search_term = self.search_var.get().lower()
        if search_term:
            all_entries = [e for e in all_entries if search_term in e.get("title", "").lower()]
        
        # Filter by category
        selected_category = self.category_var.get()
        if selected_category != "All":
            all_entries = [e for e in all_entries if e.get("category") == selected_category]
        
        # Display entries
        if not all_entries:
            empty_frame = ctk.CTkFrame(self.entries_scroll, fg_color="transparent")
            empty_frame.pack(pady=80)
            
            ctk.CTkLabel(
                empty_frame, 
                text="🔍",
                font=("Arial", 48)
            ).pack(pady=10)
            
            ctk.CTkLabel(
                empty_frame, 
                text="No entries found",
                font=("Arial", 18, "bold"),
                text_color=self.colors['text_primary']
            ).pack(pady=5)
            
            ctk.CTkLabel(
                empty_frame, 
                text="Click 'Add New Entry' to create your first entry",
                font=("Arial", 12),
                text_color=self.colors['text_secondary']
            ).pack(pady=5)
            return
        
        for entry in all_entries:
            self.create_entry_row(entry)
    
    def create_entry_row(self, entry):
        """Create a row for an entry"""
        row_frame = ctk.CTkFrame(
            self.entries_scroll, 
            fg_color=self.colors['bg_medium'], 
            corner_radius=10,
            border_width=1,
            border_color=self.colors['border']
        )
        row_frame.pack(fill="x", pady=5, padx=12)
        
        # Inner container for better padding
        inner_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
        inner_frame.pack(fill="x", padx=15, pady=12)
        
        # Type icon
        type_icon = {"password": "🔑", "note": "📝", "card": "💳"}.get(entry.get("type", "password"), "🔑")
        ctk.CTkLabel(
            inner_frame, 
            text=type_icon, 
            font=("Arial", 20),
            width=30
        ).pack(side="left", padx=(0, 10))
        
        # Title
        title_label = ctk.CTkLabel(
            inner_frame, 
            text=entry.get("title", "Untitled"), 
            font=("Arial", 13, "bold"),
            width=250,
            anchor="w",
            text_color=self.colors['text_primary']
        )
        title_label.pack(side="left", padx=(0, 10))
        
        # Username
        username_text = entry.get("username", "-")
        if len(username_text) > 30:
            username_text = username_text[:27] + "..."
        username_label = ctk.CTkLabel(
            inner_frame, 
            text=username_text, 
            font=("Arial", 12),
            width=220,
            anchor="w",
            text_color=self.colors['text_secondary']
        )
        username_label.pack(side="left", padx=10)
        
        # Category badge
        category_badge = ctk.CTkLabel(
            inner_frame, 
            text=entry.get("category", "General"), 
            font=("Arial", 11),
            width=130,
            anchor="w",
            text_color=self.colors['primary'],
            fg_color=self.colors['bg_dark'],
            corner_radius=6
        )
        category_badge.pack(side="left", padx=10, pady=2)
        
        # Action buttons with modern styling
        button_frame = ctk.CTkFrame(inner_frame, fg_color="transparent")
        button_frame.pack(side="right")
        
        ctk.CTkButton(
            button_frame, 
            text="👁️", 
            command=lambda e=entry: self.view_entry_dialog(e),
            width=45,
            height=35,
            font=("Arial", 16),
            fg_color=self.colors['bg_light'],
            hover_color=self.colors['primary'],
            corner_radius=8
        ).pack(side="left", padx=2)
        
        ctk.CTkButton(
            button_frame, 
            text="✏️", 
            command=lambda e=entry: self.edit_entry_dialog(e),
            width=45,
            height=35,
            font=("Arial", 16),
            fg_color=self.colors['bg_light'],
            hover_color=self.colors['warning'],
            corner_radius=8
        ).pack(side="left", padx=2)
        
        ctk.CTkButton(
            button_frame, 
            text="🗑️", 
            command=lambda e=entry: self.delete_entry_confirm(e),
            width=45,
            height=35,
            font=("Arial", 16),
            fg_color=self.colors['danger'],
            hover_color=self.colors['danger_hover'],
            corner_radius=8
        ).pack(side="left", padx=2)
    
    def add_entry_dialog(self):
        """Show dialog to add new entry"""
        self.entry_dialog = ctk.CTkToplevel(self)
        self.entry_dialog.title("Add New Entry")
        self.entry_dialog.geometry("550x650")
        self.entry_dialog.resizable(True, True)
        self.entry_dialog.minsize(500, 600)
        self.entry_dialog.grab_set()
        
        # Header
        header = ctk.CTkFrame(self.entry_dialog, fg_color=self.colors['primary'], corner_radius=0)
        header.pack(fill="x")
        
        ctk.CTkLabel(
            header,
            text="➕  Add New Entry",
            font=("Arial", 20, "bold"),
            text_color="white"
        ).pack(pady=20)
        
        frame = ctk.CTkFrame(self.entry_dialog, fg_color=self.colors['bg_dark'])
        frame.pack(pady=0, padx=0, fill="both", expand=True)
        
        scroll_frame = ctk.CTkScrollableFrame(frame, fg_color="transparent")
        scroll_frame.pack(fill="both", expand=True, padx=25, pady=20)
        
        # Entry type
        ctk.CTkLabel(scroll_frame, text="Entry Type", font=("Arial", 11, "bold"), text_color=self.colors['text_secondary']).pack(anchor="w", pady=(5, 5))
        entry_type_var = ctk.StringVar(value="password")
        ctk.CTkOptionMenu(
            scroll_frame, 
            variable=entry_type_var, 
            values=["password", "note", "card"],
            height=40,
            corner_radius=8,
            fg_color=self.colors['bg_medium'],
            button_color=self.colors['bg_medium'],
            button_hover_color=self.colors['bg_light'],
            dropdown_fg_color=self.colors['bg_medium']
        ).pack(fill="x", pady=(0, 15))
        
        # Title
        ctk.CTkLabel(scroll_frame, text="Title *", font=("Arial", 11, "bold"), text_color=self.colors['text_secondary']).pack(anchor="w", pady=(5, 5))
        title_entry = ctk.CTkEntry(
            scroll_frame, 
            placeholder_text="e.g., Gmail, Bank Account",
            height=40,
            corner_radius=8,
            border_width=0,
            fg_color=self.colors['bg_medium']
        )
        title_entry.pack(fill="x", pady=(0, 15))
        
        # Username
        ctk.CTkLabel(scroll_frame, text="Username/Email", font=("Arial", 11, "bold"), text_color=self.colors['text_secondary']).pack(anchor="w", pady=(5, 5))
        username_entry = ctk.CTkEntry(
            scroll_frame, 
            placeholder_text="Optional",
            height=40,
            corner_radius=8,
            border_width=0,
            fg_color=self.colors['bg_medium']
        )
        username_entry.pack(fill="x", pady=(0, 15))
        
        # Password
        ctk.CTkLabel(scroll_frame, text="Password", font=("Arial", 11, "bold"), text_color=self.colors['text_secondary']).pack(anchor="w", pady=(5, 5))
        pass_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        pass_frame.pack(fill="x", pady=(0, 5))
        
        password_visible = [False]  # Use list to allow modification in nested function
        
        password_entry = ctk.CTkEntry(
            pass_frame, 
            placeholder_text="Optional", 
            show="*",
            height=40,
            corner_radius=8,
            border_width=0,
            fg_color=self.colors['bg_medium']
        )
        password_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        def toggle_password_visibility():
            password_visible[0] = not password_visible[0]
            if password_visible[0]:
                password_entry.configure(show="")
            else:
                password_entry.configure(show="*")
        
        ctk.CTkButton(
            pass_frame, 
            text="👁️", 
            command=toggle_password_visibility,
            width=45,
            height=40,
            corner_radius=8,
            fg_color=self.colors['bg_light'],
            hover_color=self.colors['bg_medium'],
            font=("Arial", 16)
        ).pack(side="right", padx=(0, 5))
        
        ctk.CTkButton(
            pass_frame, 
            text="🎲", 
            command=lambda: [password_entry.delete(0, "end"), password_entry.insert(0, generate_password())],
            width=45,
            height=40,
            corner_radius=8,
            fg_color=self.colors['success'],
            hover_color="#059669",
            font=("Arial", 16)
        ).pack(side="right")
        
        # URL
        ctk.CTkLabel(scroll_frame, text="URL", font=("Arial", 11, "bold"), text_color=self.colors['text_secondary']).pack(anchor="w", pady=(5, 5))
        url_entry = ctk.CTkEntry(
            scroll_frame, 
            placeholder_text="https://...",
            height=40,
            corner_radius=8,
            border_width=0,
            fg_color=self.colors['bg_medium']
        )
        url_entry.pack(fill="x", pady=(0, 15))
        
        # Category
        ctk.CTkLabel(scroll_frame, text="Category", font=("Arial", 11, "bold"), text_color=self.colors['text_secondary']).pack(anchor="w", pady=(5, 5))
        category_var = ctk.StringVar(value="General")
        category_menu = ctk.CTkOptionMenu(
            scroll_frame, 
            variable=category_var, 
            values=get_categories() + ["Email", "Banking", "Social Media", "Work", "Personal", "Shopping"],
            height=40,
            corner_radius=8,
            fg_color=self.colors['bg_medium'],
            button_color=self.colors['bg_medium'],
            button_hover_color=self.colors['bg_light'],
            dropdown_fg_color=self.colors['bg_medium']
        )
        category_menu.pack(fill="x", pady=(0, 15))
        
        # Notes
        ctk.CTkLabel(scroll_frame, text="Notes", font=("Arial", 11, "bold"), text_color=self.colors['text_secondary']).pack(anchor="w", pady=(5, 5))
        notes_entry = ctk.CTkTextbox(
            scroll_frame, 
            height=100,
            corner_radius=8,
            border_width=0,
            fg_color=self.colors['bg_medium']
        )
        notes_entry.pack(fill="x", pady=(0, 15))
        
        # Save button
        def save():
            title = title_entry.get().strip()
            if not title:
                messagebox.showerror("Error", "Title is required!")
                return
            
            data_no, data_yes = save_entry(
                title=title,
                username=username_entry.get(),
                password=password_entry.get(),
                url=url_entry.get(),
                notes=notes_entry.get("1.0", "end-1c"),
                category=category_var.get(),
                entry_type=entry_type_var.get()
            )
            
            if data_yes is not None and data_no is not None:
                if messagebox.askyesno("Overwrite", f"Entry '{title}' already exists. Overwrite?"):
                    write_file_atomic(".\\password.txt", data_yes)
            
            backup_passwords()
            self.refresh_entries()
            self.entry_dialog.destroy()
        
        button_frame = ctk.CTkFrame(frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=25, pady=(0, 20))
        
        ctk.CTkButton(
            button_frame, 
            text="💾  Save Entry", 
            command=save, 
            height=50,
            font=("Arial", 14, "bold"),
            fg_color=self.colors['success'],
            hover_color="#059669",
            corner_radius=10
        ).pack(fill="x")
    
    def view_entry_dialog(self, entry):
        """Show dialog to view entry details"""
        dialog = ctk.CTkToplevel(self)
        dialog.title(f"View: {entry.get('title')}")
        dialog.geometry("500x500")
        dialog.resizable(True, True)
        dialog.minsize(450, 400)
        dialog.grab_set()
        
        frame = ctk.CTkFrame(dialog)
        frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        def create_field(label, value, is_password=False):
            # Only show fields that have values
            if not value:
                return
            
            ctk.CTkLabel(frame, text=f"{label}:", font=("Arial", 12, "bold")).pack(anchor="w", pady=(10, 5))
            field_frame = ctk.CTkFrame(frame, fg_color="#2b2b2b")
            field_frame.pack(fill="x", pady=5)
            
            if is_password:
                text_var = ctk.StringVar(value="**********")
                label_widget = ctk.CTkLabel(field_frame, textvariable=text_var, anchor="w")
                label_widget.pack(side="left", padx=10, pady=10, fill="x", expand=True)
                
                def toggle():
                    if text_var.get() == "**********":
                        text_var.set(value)
                    else:
                        text_var.set("**********")
                
                ctk.CTkButton(field_frame, text="👁️", command=toggle, width=40).pack(side="right", padx=5)
            else:
                ctk.CTkLabel(field_frame, text=value, anchor="w").pack(side="left", padx=10, pady=10, fill="x", expand=True)
            
            ctk.CTkButton(
                field_frame, 
                text="📋", 
                command=lambda v=value: [pyperclip.copy(v), messagebox.showinfo("Copied", "Copied to clipboard!")],
                width=40
            ).pack(side="right", padx=5)
        
        # Always show title
        create_field("Title", entry.get("title"))
        
        # Show other fields only if they have values
        create_field("Username", entry.get("username"))
        create_field("Password", entry.get("password"), is_password=True)
        create_field("URL", entry.get("url"))
        
        # Show category only if not default "General" or if it has a value
        category = entry.get("category")
        if category and category != "General":
            create_field("Category", category)
        
        notes = entry.get("notes", "")
        if notes:
            ctk.CTkLabel(frame, text="Notes:", font=("Arial", 12, "bold")).pack(anchor="w", pady=(10, 5))
            notes_box = ctk.CTkTextbox(frame, height=100)
            notes_box.pack(fill="x", pady=5)
            notes_box.insert("1.0", notes)
            notes_box.configure(state="disabled")
        
        ctk.CTkButton(frame, text="Close", command=dialog.destroy).pack(pady=20)
    
    def edit_entry_dialog(self, entry):
        """Show dialog to edit entry"""
        self.entry_dialog = ctk.CTkToplevel(self)
        self.entry_dialog.title(f"Edit: {entry.get('title')}")
        self.entry_dialog.geometry("500x550")
        self.entry_dialog.resizable(True, True)
        self.entry_dialog.minsize(450, 500)
        self.entry_dialog.grab_set()
        
        frame = ctk.CTkFrame(self.entry_dialog)
        frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        # Similar to add_entry_dialog but pre-filled
        ctk.CTkLabel(frame, text="Entry Type:", font=("Arial", 12, "bold")).pack(anchor="w", pady=(10, 5))
        entry_type_var = ctk.StringVar(value=entry.get("type", "password"))
        ctk.CTkOptionMenu(frame, variable=entry_type_var, values=["password", "note", "card"]).pack(fill="x", pady=5)
        
        ctk.CTkLabel(frame, text="Title: *", font=("Arial", 12, "bold")).pack(anchor="w", pady=(10, 5))
        title_entry = ctk.CTkEntry(frame)
        title_entry.insert(0, entry.get("title", ""))
        title_entry.pack(fill="x", pady=5)
        title_entry.configure(state="disabled")  # Can't change title (used as key)
        
        ctk.CTkLabel(frame, text="Username/Email:", font=("Arial", 12, "bold")).pack(anchor="w", pady=(10, 5))
        username_entry = ctk.CTkEntry(frame)
        username_entry.insert(0, entry.get("username", ""))
        username_entry.pack(fill="x", pady=5)
        
        ctk.CTkLabel(frame, text="Password:", font=("Arial", 12, "bold")).pack(anchor="w", pady=(10, 5))
        pass_frame = ctk.CTkFrame(frame, fg_color="transparent")
        pass_frame.pack(fill="x", pady=5)
        
        password_visible_edit = [False]  # Use list to allow modification in nested function
        
        password_entry = ctk.CTkEntry(pass_frame, show="*")
        password_entry.insert(0, entry.get("password", ""))
        password_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        def toggle_password_visibility_edit():
            password_visible_edit[0] = not password_visible_edit[0]
            if password_visible_edit[0]:
                password_entry.configure(show="")
            else:
                password_entry.configure(show="*")
        
        ctk.CTkButton(
            pass_frame, 
            text="👁️", 
            command=toggle_password_visibility_edit,
            width=40
        ).pack(side="right", padx=(0, 5))
        
        ctk.CTkButton(
            pass_frame, 
            text="🎲", 
            command=lambda: [password_entry.delete(0, "end"), password_entry.insert(0, generate_password())],
            width=40
        ).pack(side="right")
        
        ctk.CTkLabel(frame, text="URL:", font=("Arial", 12, "bold")).pack(anchor="w", pady=(10, 5))
        url_entry = ctk.CTkEntry(frame)
        url_entry.insert(0, entry.get("url", ""))
        url_entry.pack(fill="x", pady=5)
        
        ctk.CTkLabel(frame, text="Category:", font=("Arial", 12, "bold")).pack(anchor="w", pady=(10, 5))
        category_var = ctk.StringVar(value=entry.get("category", "General"))
        category_menu = ctk.CTkOptionMenu(
            frame, 
            variable=category_var, 
            values=get_categories() + ["Email", "Banking", "Social Media", "Work", "Personal", "Shopping"]
        )
        category_menu.pack(fill="x", pady=5)
        
        ctk.CTkLabel(frame, text="Notes:", font=("Arial", 12, "bold")).pack(anchor="w", pady=(10, 5))
        notes_entry = ctk.CTkTextbox(frame, height=80)
        notes_entry.insert("1.0", entry.get("notes", ""))
        notes_entry.pack(fill="x", pady=5)
        
        def save():
            data_no, data_yes = save_entry(
                title=title_entry.get(),
                username=username_entry.get(),
                password=password_entry.get(),
                url=url_entry.get(),
                notes=notes_entry.get("1.0", "end-1c"),
                category=category_var.get(),
                entry_type=entry_type_var.get()
            )
            
            if data_yes is not None:
                write_file_atomic(".\\password.txt", data_yes)
            
            backup_passwords()
            self.refresh_entries()
            self.entry_dialog.destroy()
        
        ctk.CTkButton(frame, text="💾 Save Changes", command=save, height=40).pack(pady=20)
    
    def delete_entry_confirm(self, entry):
        """Confirm and delete entry"""
        if messagebox.askyesno("Delete", f"Delete '{entry.get('title')}'?"):
            data_no, data_yes = delete_entry(entry.get("title"))
            write_file_atomic(".\\password.txt", data_yes)
            backup_passwords()
            self.refresh_entries()
    
    def generate_password_dialog(self):
        """Show password generator dialog"""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Password Generator")
        dialog.geometry("500x700")
        dialog.resizable(True, True)
        dialog.minsize(480, 550)
        dialog.grab_set()
        
        # Header
        header = ctk.CTkFrame(dialog, fg_color=self.colors['success'], corner_radius=0)
        header.pack(fill="x")
        
        ctk.CTkLabel(
            header,
            text="🎲  Password Generator",
            font=("Arial", 20, "bold"),
            text_color="white"
        ).pack(pady=20)
        
        frame = ctk.CTkFrame(dialog, fg_color=self.colors['bg_dark'])
        frame.pack(pady=0, padx=0, fill="both", expand=True)
        
        content_frame = ctk.CTkFrame(frame, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=30, pady=25)
        
        # Generated password display (at top for visibility)
        ctk.CTkLabel(
            content_frame, 
            text="Generated Password:", 
            font=("Arial", 11, "bold"), 
            text_color=self.colors['text_secondary']
        ).pack(anchor="w", pady=(5, 5))
        
        password_var = ctk.StringVar(value="")
        password_display = ctk.CTkEntry(
            content_frame, 
            textvariable=password_var, 
            font=("Courier", 14, "bold"),
            height=50,
            justify="center",
            fg_color=self.colors['bg_medium'],
            border_width=2,
            border_color=self.colors['success'],
            corner_radius=8
        )
        password_display.pack(fill="x", pady=(0, 20))
        
        # Separator
        separator = ctk.CTkFrame(content_frame, height=2, fg_color=self.colors['border'])
        separator.pack(fill="x", pady=15)
        
        # Length slider
        ctk.CTkLabel(
            content_frame, 
            text="Password Length:", 
            font=("Arial", 12, "bold")
        ).pack(anchor="w", pady=(10, 5))
        
        length_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        length_frame.pack(fill="x", pady=5)
        
        length_var = ctk.IntVar(value=16)
        length_label = ctk.CTkLabel(
            length_frame, 
            text="16 characters", 
            font=("Arial", 13, "bold"),
            text_color=self.colors['primary'],
            width=120
        )
        length_label.pack(side="right")
        
        def update_length(val):
            length_label.configure(text=f"{int(float(val))} characters")
        
        length_slider = ctk.CTkSlider(
            length_frame, 
            from_=8, 
            to=32, 
            variable=length_var, 
            command=update_length,
            fg_color=self.colors['bg_medium'],
            progress_color=self.colors['success'],
            button_color=self.colors['success'],
            button_hover_color="#059669"
        )
        length_slider.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Options with modern checkboxes
        options_label = ctk.CTkLabel(
            content_frame, 
            text="Character Types:", 
            font=("Arial", 12, "bold")
        )
        options_label.pack(anchor="w", pady=(20, 10))
        
        options_frame = ctk.CTkFrame(content_frame, fg_color=self.colors['bg_medium'], corner_radius=8)
        options_frame.pack(fill="x", pady=5)
        
        uppercase_var = ctk.BooleanVar(value=True)
        lowercase_var = ctk.BooleanVar(value=True)
        digits_var = ctk.BooleanVar(value=True)
        symbols_var = ctk.BooleanVar(value=True)
        
        ctk.CTkCheckBox(
            options_frame, 
            text="Uppercase Letters (A-Z)", 
            variable=uppercase_var,
            font=("Arial", 12),
            checkbox_width=24,
            checkbox_height=24,
            fg_color=self.colors['success'],
            hover_color="#059669"
        ).pack(anchor="w", padx=15, pady=8)
        
        ctk.CTkCheckBox(
            options_frame, 
            text="Lowercase Letters (a-z)", 
            variable=lowercase_var,
            font=("Arial", 12),
            checkbox_width=24,
            checkbox_height=24,
            fg_color=self.colors['success'],
            hover_color="#059669"
        ).pack(anchor="w", padx=15, pady=8)
        
        ctk.CTkCheckBox(
            options_frame, 
            text="Numbers (0-9)", 
            variable=digits_var,
            font=("Arial", 12),
            checkbox_width=24,
            checkbox_height=24,
            fg_color=self.colors['success'],
            hover_color="#059669"
        ).pack(anchor="w", padx=15, pady=8)
        
        ctk.CTkCheckBox(
            options_frame, 
            text="Symbols (!@#$%^&*)", 
            variable=symbols_var,
            font=("Arial", 12),
            checkbox_width=24,
            checkbox_height=24,
            fg_color=self.colors['success'],
            hover_color="#059669"
        ).pack(anchor="w", padx=15, pady=8)
        
        # Generate function
        def generate():
            pwd = generate_password(
                length=length_var.get(),
                use_uppercase=uppercase_var.get(),
                use_lowercase=lowercase_var.get(),
                use_digits=digits_var.get(),
                use_symbols=symbols_var.get()
            )
            password_var.set(pwd)
        
        def copy():
            pwd = password_var.get()
            if pwd:
                pyperclip.copy(pwd)
                messagebox.showinfo("Copied", "Password copied to clipboard!")
        
        # Buttons with proper spacing
        button_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=(20, 10))
        
        generate_btn = ctk.CTkButton(
            button_frame, 
            text="🎲  Generate New Password", 
            command=generate, 
            height=50,
            font=("Arial", 14, "bold"),
            fg_color=self.colors['success'],
            hover_color="#059669",
            corner_radius=10
        )
        generate_btn.pack(fill="x", pady=(0, 8))
        
        copy_btn = ctk.CTkButton(
            button_frame, 
            text="📋  Copy to Clipboard", 
            command=copy, 
            height=50,
            font=("Arial", 14, "bold"),
            fg_color=self.colors['primary'],
            hover_color=self.colors['primary_hover'],
            corner_radius=10
        )
        copy_btn.pack(fill="x")
        
        # Generate initial password
        generate()
    
    def change_master_password(self):
        """Change master password dialog"""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Change Master Password")
        dialog.geometry("400x300")
        dialog.resizable(True, True)
        dialog.minsize(350, 250)
        dialog.grab_set()
        
        frame = ctk.CTkFrame(dialog)
        frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(frame, text="Change Master Password", font=("Arial", 16, "bold")).pack(pady=20)
        
        ctk.CTkLabel(frame, text="Current Password:").pack(anchor="w", pady=(10, 5))
        old_pass = ctk.CTkEntry(frame, show="*")
        old_pass.pack(fill="x", pady=5)
        
        ctk.CTkLabel(frame, text="New Password:").pack(anchor="w", pady=(10, 5))
        new_pass = ctk.CTkEntry(frame, show="*")
        new_pass.pack(fill="x", pady=5)
        
        error_label = None
        
        def change():
            nonlocal error_label
            old = old_pass.get()
            new = new_pass.get()
            
            if not check_key(old):
                if error_label:
                    error_label.destroy()
                error_label = ctk.CTkLabel(frame, text="Wrong current password!", text_color="red")
                error_label.pack(pady=5)
                return
            
            if len(new) < 8:
                if error_label:
                    error_label.destroy()
                error_label = ctk.CTkLabel(frame, text="New password must be at least 8 characters!", text_color="red")
                error_label.pack(pady=5)
                return
            
            if old == new:
                if error_label:
                    error_label.destroy()
                error_label = ctk.CTkLabel(frame, text="New password must be different!", text_color="red")
                error_label.pack(pady=5)
                return
            
            encrypt_with_new_key(new)
            messagebox.showinfo("Success", "Master password changed successfully!")
            dialog.destroy()
        
        ctk.CTkButton(frame, text="Change Password", command=change, height=40).pack(pady=20)


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    
    app = PasswordManagerApp()
    app.mainloop()
