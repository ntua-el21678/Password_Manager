import flet as ft
import os
import subprocess
import sys
import ctypes
import pyperclip
from password_manager import (
    check_key, new_key, read_key, backup_passwords, encrypt_with_new_key,
    save_entry, get_all_entries, get_entry_by_title, delete_entry, 
    get_categories, generate_password, write_file_atomic
)


class PasswordManagerApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "🔒 Secure Vault"
        self.page.window.width = 450
        self.page.window.height = 450
        self.page.window.min_width = 450
        self.page.window.min_height = 350
        page.window.left = 750  # Center of screen (approximate)
        page.window.top = 200
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.bgcolor = "#1a1a1a"
        self.page.padding = 0
        
        # Modern color scheme
        self.colors = {
            'primary': '#3b82f6',
            'primary_hover': '#2563eb',
            'success': '#10b981',
            'danger': '#ef4444',
            'danger_hover': '#dc2626',
            'warning': '#f59e0b',
            'bg_dark': '#1a1a1a',
            'bg_medium': '#2d2d2d',
            'bg_light': '#3a3a3a',
            'text_primary': '#ffffff',
            'text_secondary': '#9ca3af',
            'border': '#404040'
        }
        
        self.logged_in = False
        self.current_filter_category = "All"
        self.search_value = ""
        self.category_value = "All"
        self.password_generator_process = None
        
        self.show_login_screen()
    
    def show_login_screen(self):
        """Show login or welcome screen"""
        self.page.controls.clear()
        
        login_file_path = ".\\login.txt"
        try:
            with open(login_file_path, 'r') as file:
                login_data = file.readlines()
        except:
            login_data = []
        
        if login_data == []:
            self.show_welcome_screen()
        elif login_data[0] == "logged_in\n":
            self.show_password_entry()
        else:
            self.page.window.close()
    
    def show_welcome_screen(self):
        """First time setup"""
        self.entry_key = ft.TextField(
            hint_text="Master password (minimum 8 characters)",
            password=True,
            can_reveal_password=True,
            height=50,
            border_radius=8,
            border_color="transparent",
            bgcolor=self.colors['bg_light'],
            text_style=ft.TextStyle(size=14),
            on_submit=lambda e: self.welcome_submit()
        )
        
        self.reentry_key = ft.TextField(
            hint_text="Confirm master password",
            password=True,
            can_reveal_password=True,
            height=50,
            border_radius=8,
            border_color="transparent",
            bgcolor=self.colors['bg_light'],
            text_style=ft.TextStyle(size=14),
            on_submit=lambda e: self.welcome_submit()
        )
        
        self.error_label = ft.Text("", color="red", size=12)
        
        login_frame = ft.Container(
            content=ft.Column(
                controls=[
                    ft.Container(height=20),
                    ft.Text("🔐", size=48, text_align=ft.TextAlign.CENTER),
                    ft.Text(
                        "Welcome to Secure Vault",
                        size=24,
                        weight=ft.FontWeight.BOLD,
                        color=self.colors['primary'],
                        text_align=ft.TextAlign.CENTER
                    ),
                    ft.Text(
                        "Create your master password to get started",
                        size=12,
                        color=self.colors['text_secondary'],
                        text_align=ft.TextAlign.CENTER
                    ),
                    ft.Container(height=15),
                    ft.Container(
                        content=ft.Column(
                            controls=[
                                self.entry_key,
                                self.reentry_key,
                            ],
                            spacing=10,
                        ),
                        bgcolor=self.colors['bg_medium'],
                        border_radius=12,
                        padding=5,
                        margin=ft.margin.symmetric(horizontal=40)
                    ),
                    ft.Container(height=10),
                    ft.ElevatedButton(
                        content=ft.Text("Create Vault"),
                        on_click=lambda e: self.welcome_submit(),
                        width=200,
                        height=45,
                        style=ft.ButtonStyle(
                            bgcolor=self.colors['primary'],
                            color="white",
                            shape=ft.RoundedRectangleBorder(radius=8)
                        )
                    ),
                    ft.Container(height=10),
                    ft.Text(
                        "💡 Choose a strong password you won't forget.",
                        size=11,
                        color=self.colors['text_secondary'],
                        text_align=ft.TextAlign.CENTER
                    ),
                    self.error_label,
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=8
            ),
            expand=True,
            bgcolor=self.colors['bg_dark'],
            padding=10
        )
        
        self.page.add(login_frame)
        self.page.update()
    
    def show_password_entry(self):
        """Login screen for existing users"""
        self.entry_key = ft.TextField(
            hint_text="Master password",
            password=True,
            can_reveal_password=True,
            height=50,
            border_radius=8,
            border_color="transparent",
            bgcolor=self.colors['bg_light'],
            text_style=ft.TextStyle(size=14),
            on_submit=lambda e: self.login_submit()
        )
        
        self.error_label = ft.Text("", color="red", size=12)
        
        login_frame = ft.Container(
            content=ft.Column(
                controls=[
                    ft.Container(height=30),
                    ft.Text(
                        "🔒 Secure Vault",
                        size=32,
                        weight=ft.FontWeight.BOLD,
                        text_align=ft.TextAlign.CENTER
                    ),
                    ft.Text(
                        "Enter your master password to unlock",
                        size=12,
                        color=self.colors['text_secondary'],
                        text_align=ft.TextAlign.CENTER
                    ),
                    ft.Container(height=20),
                    ft.Container(
                        content=self.entry_key,
                        bgcolor=self.colors['bg_medium'],
                        border_radius=12,
                        padding=7,
                        margin=ft.margin.symmetric(horizontal=50)
                    ),
                    ft.Container(height=15),
                    ft.ElevatedButton(
                        content=ft.Text("🔓 Unlock Vault"),
                        on_click=lambda e: self.login_submit(),
                        width=200,
                        height=45,
                        style=ft.ButtonStyle(
                            bgcolor=self.colors['primary'],
                            color="white",
                            shape=ft.RoundedRectangleBorder(radius=8)
                        )
                    ),
                    self.error_label,
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=8
            ),
            expand=True,
            bgcolor=self.colors['bg_dark'],
            padding=10
        )
        
        self.page.add(login_frame)
        self.page.update()
    
    def welcome_submit(self):
        """Handle first time setup"""
        user_input = self.entry_key.value or ""
        reuser_input = self.reentry_key.value or ""
        
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
        user_input = self.entry_key.value or ""
        
        if check_key(user_input):
            self.show_main_screen()
        else:
            self.show_error("Wrong password. Try again.")
    
    def show_error(self, message):
        """Show error message"""
        self.error_label.value = message
        self.entry_key.value = ""
        if hasattr(self, 'reentry_key'):
            self.reentry_key.value = ""
        self.page.update()
    
    def show_main_screen(self):
        """Show main application interface"""
        self.logged_in = True
        self.page.controls.clear()
        
        self.page.window.width = 1000
        self.page.window.height = 600
        
        # Search field
        self.search_field = ft.TextField(
            hint_text="Search entries by title...",
            height=45,
            border_radius=8,
            border_color="transparent",
            bgcolor=self.colors['bg_light'],
            text_style=ft.TextStyle(size=14),
            prefix_icon=ft.Icons.SEARCH,
            on_submit=self.on_search_submit,
            expand=True
        )
        
        # Search button
        self.search_button = ft.IconButton(
            icon=ft.Icons.SEARCH,
            on_click=self.on_search_click,
            bgcolor=self.colors['primary'],
            icon_color="white"
        )
        
        # Category dropdown
        categories = ["All"] + get_categories()
        self.category_dropdown = ft.Dropdown(
            value="All",
            options=[ft.dropdown.Option(c) for c in categories],
            width=180,
            height=45,
            border_radius=8,
            border_color="transparent",
            bgcolor=self.colors['bg_light']
        )
        
        # Category filter button
        self.category_button = ft.IconButton(
            icon=ft.Icons.FILTER_LIST,
            on_click=self.on_category_click,
            bgcolor=self.colors['primary'],
            icon_color="white"
        )
        
        # Entries list container
        self.entries_list = ft.Column(
            spacing=8,
            scroll=ft.ScrollMode.AUTO,
            expand=True
        )
        
        # Top bar
        top_bar = ft.Container(
            content=ft.Row(
                controls=[
                    ft.Row(
                        controls=[
                            ft.Text("🔐", size=28),
                            ft.Column(
                                controls=[
                                    ft.Text("Secure Vault", size=20, weight=ft.FontWeight.BOLD),
                                    ft.Text("Your encrypted password manager", size=11, color=self.colors['text_secondary'])
                                ],
                                spacing=0
                            )
                        ],
                        spacing=10
                    ),
                    ft.Row(
                        controls=[
                            ft.IconButton(
                                icon=ft.Icons.REFRESH,
                                icon_color="white",
                                bgcolor=self.colors['bg_light'],
                                on_click=lambda e: self.refresh_entries()
                            ),
                            ft.ElevatedButton(
                                content=ft.Text("🔑 Change Password"),
                                on_click=lambda e: self.change_master_password(),
                                style=ft.ButtonStyle(
                                    bgcolor=self.colors['bg_light'],
                                    color="white",
                                    shape=ft.RoundedRectangleBorder(radius=8)
                                )
                            )
                        ],
                        spacing=5
                    )
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN
            ),
            bgcolor=self.colors['bg_medium'],
            padding=ft.padding.symmetric(horizontal=20, vertical=15),
            height=70
        )
        
        # Filter bar
        filter_bar = ft.Container(
            content=ft.Row(
                controls=[
                    self.search_field,
                    self.search_button,
                    ft.Row(
                        controls=[
                            ft.Text("📁 Category:", color=self.colors['text_secondary']),
                            self.category_dropdown,
                            self.category_button
                        ],
                        spacing=8
                    )
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN
            ),
            bgcolor=self.colors['bg_medium'],
            border_radius=12,
            padding=15,
            margin=ft.margin.symmetric(horizontal=20, vertical=10)
        )
        
        # Headers
        headers = ft.Container(
            content=ft.Row(
                controls=[
                    ft.Container(
                        content=ft.Text("TITLE", size=11, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                        width=280
                    ),
                    ft.Container(
                        content=ft.Text("USERNAME", size=11, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                        width=220
                    ),
                    ft.Container(
                        content=ft.Text("CATEGORY", size=11, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                        width=130
                    ),
                    ft.Container(
                        content=ft.Text("ACTIONS", size=11, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                        expand=True,
                        alignment=ft.Alignment(1, 0)
                    )
                ]
            ),
            bgcolor=self.colors['bg_dark'],
            padding=ft.padding.symmetric(horizontal=20, vertical=12)
        )
        
        # Content area
        content_area = ft.Container(
            content=ft.Column(
                controls=[
                    headers,
                    ft.Container(
                        content=self.entries_list,
                        bgcolor=self.colors['bg_dark'],
                        expand=True,
                        padding=ft.padding.symmetric(horizontal=12)
                    )
                ],
                spacing=0,
                expand=True
            ),
            bgcolor=self.colors['bg_medium'],
            border_radius=12,
            margin=ft.margin.symmetric(horizontal=20),
            expand=True,
            clip_behavior=ft.ClipBehavior.HARD_EDGE
        )
        
        # Stats
        entries_count = len(get_all_entries())
        self.stats_text = ft.Text(f"📊 {entries_count} entries stored", size=12, color=self.colors['text_secondary'])
        
        # Bottom action bar
        action_bar = ft.Container(
            content=ft.Row(
                controls=[
                    ft.ElevatedButton(
                        content=ft.Text("➕  Add New Entry"),
                        on_click=lambda e: self.add_entry_dialog(),
                        width=200,
                        height=50,
                        style=ft.ButtonStyle(
                            bgcolor=self.colors['primary'],
                            color="white",
                            shape=ft.RoundedRectangleBorder(radius=10)
                        )
                    ),
                    ft.ElevatedButton(
                        content=ft.Text("🎲  Generate Password"),
                        on_click=lambda e: self.generate_password_dialog(),
                        width=200,
                        height=50,
                        style=ft.ButtonStyle(
                            bgcolor=self.colors['success'],
                            color="white",
                            shape=ft.RoundedRectangleBorder(radius=10)
                        )
                    ),
                    ft.Container(expand=True),
                    self.stats_text
                ]
            ),
            padding=ft.padding.symmetric(horizontal=20, vertical=15)
        )
        
        # Main layout
        main_frame = ft.Container(
            content=ft.Column(
                controls=[
                    top_bar,
                    filter_bar,
                    content_area,
                    action_bar
                ],
                spacing=0,
                expand=True
            ),
            bgcolor=self.colors['bg_dark'],
            expand=True
        )
        
        self.page.add(main_frame)
        self.refresh_entries()
        backup_passwords()
        self.page.update()
    
    def on_search_submit(self, e):
        """Handle search input submit"""
        self.search_value = self.search_field.value or ""
        self.filter_entries()
    
    def on_search_click(self, e):
        """Handle search button click"""
        self.search_value = self.search_field.value or ""
        self.filter_entries()
    
    def on_category_click(self, e):
        """Handle category filter button click"""
        self.category_value = self.category_dropdown.value or "All"
        self.filter_entries()
    
    def refresh_entries(self):
        """Reload and display all entries"""
        categories = ["All"] + get_categories()
        self.category_dropdown.options = [ft.dropdown.Option(c) for c in categories]
        self.filter_entries()
        
        entries_count = len(get_all_entries())
        self.stats_text.value = f"📊 {entries_count} entries stored"
        self.page.update()
    
    def filter_entries(self):
        """Filter and display entries based on search and category"""
        self.entries_list.controls.clear()
        
        all_entries = get_all_entries()
        
        search_term = self.search_value.lower()
        if search_term:
            all_entries = [e for e in all_entries if search_term in e.get("title", "").lower()]
        
        selected_category = self.category_value
        if selected_category != "All":
            all_entries = [e for e in all_entries if e.get("category") == selected_category]
        
        if not all_entries:
            empty_state = ft.Container(
                content=ft.Column(
                    controls=[
                        ft.Text("🔍", size=48),
                        ft.Text("No entries found", size=18, weight=ft.FontWeight.BOLD),
                        ft.Text("Click 'Add New Entry' to create your first entry", size=12, color=self.colors['text_secondary'])
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=8
                ),
                alignment=ft.Alignment(0, 0),
                padding=80
            )
            self.entries_list.controls.append(empty_state)
        else:
            for entry in all_entries:
                self.entries_list.controls.append(self.create_entry_row(entry))
        
        self.page.update()
    
    def create_entry_row(self, entry):
        """Create a row for an entry"""
        type_icon = {"password": "🔑", "note": "📝", "card": "💳"}.get(entry.get("type", "password"), "🔑")
        
        username_text = entry.get("username", "-") or "-"
        if len(username_text) > 30:
            username_text = username_text[:27] + "..."
        
        return ft.Container(
            content=ft.Row(
                controls=[
                    ft.Text(type_icon, size=20),
                    ft.Container(
                        content=ft.Text(entry.get("title", "Untitled"), weight=ft.FontWeight.BOLD, size=13),
                        width=240
                    ),
                    ft.Container(
                        content=ft.Text(username_text, color=self.colors['text_secondary'], size=12),
                        width=220
                    ),
                    ft.Container(
                        content=ft.Container(
                            content=ft.Text(entry.get("category", "General"), size=11, color=self.colors['primary']),
                            bgcolor=self.colors['bg_dark'],
                            border_radius=6,
                            padding=ft.padding.symmetric(horizontal=8, vertical=4)
                        ),
                        width=130
                    ),
                    ft.Row(
                        controls=[
                            ft.IconButton(
                                icon=ft.Icons.VISIBILITY,
                                icon_size=18,
                                bgcolor=self.colors['bg_light'],
                                on_click=lambda e, ent=entry: self.view_entry_dialog(ent),
                                tooltip="View"
                            ),
                            ft.IconButton(
                                icon=ft.Icons.EDIT,
                                icon_size=18,
                                bgcolor=self.colors['bg_light'],
                                on_click=lambda e, ent=entry: self.edit_entry_dialog(ent),
                                tooltip="Edit"
                            ),
                            ft.IconButton(
                                icon=ft.Icons.DELETE,
                                icon_size=18,
                                bgcolor=self.colors['danger'],
                                icon_color="white",
                                on_click=lambda e, ent=entry: self.delete_entry_confirm(ent),
                                tooltip="Delete"
                            )
                        ],
                        spacing=4,
                        expand=True,
                        alignment=ft.Alignment(1, 0)
                    )
                ],
                alignment=ft.MainAxisAlignment.START
            ),
            bgcolor=self.colors['bg_medium'],
            border_radius=10,
            border=ft.border.all(1, self.colors['border']),
            padding=ft.padding.symmetric(horizontal=15, vertical=12),
            margin=ft.margin.only(bottom=5)
        )
    
    def show_snackbar(self, message, color="white"):
        """Show a snackbar notification"""
        self.page.snack_bar = ft.SnackBar(
            content=ft.Text(message, color=color),
            bgcolor=self.colors['bg_medium']
        )
        self.page.snack_bar.open = True
        self.page.update()
    
    def add_entry_dialog(self):
        """Show dialog to add new entry"""
        entry_type_dropdown = ft.Dropdown(
            value="password",
            options=[
                ft.dropdown.Option("password"),
                ft.dropdown.Option("note"),
                ft.dropdown.Option("card")
            ],
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        title_field = ft.TextField(
            hint_text="e.g., Gmail, Bank Account",
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        username_field = ft.TextField(
            hint_text="Optional",
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        password_field = ft.TextField(
            hint_text="Optional",
            password=True,
            can_reveal_password=True,
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium'],
            expand=True
        )
        
        url_field = ft.TextField(
            hint_text="https://...",
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        categories = get_categories() + ["Email", "Banking", "Social Media", "Work", "Personal", "Shopping"]
        category_dropdown = ft.Dropdown(
            value="General",
            options=[ft.dropdown.Option(c) for c in list(set(categories))],
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        notes_field = ft.TextField(
            multiline=True,
            min_lines=3,
            max_lines=5,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        def generate_pass(e):
            password_field.value = generate_password()
            password_field.update()
            self.page.update()
        
        def save(e):
            title = (title_field.value or "").strip()
            if not title:
                self.show_snackbar("Title is required!", "red")
                return
            
            data_no, data_yes = save_entry(
                title=title,
                username=username_field.value or "",
                password=password_field.value or "",
                url=url_field.value or "",
                notes=notes_field.value or "",
                category=category_dropdown.value or "General",
                entry_type=entry_type_dropdown.value or "password"
            )
            
            if data_yes is not None and data_no is not None:
                def confirm_overwrite(e):
                    write_file_atomic(".\\password.txt", data_yes)
                    backup_passwords()
                    self.refresh_entries()
                    dialog.open = False
                    confirm_dialog.open = False
                    self.page.update()
                
                def cancel_overwrite(e):
                    confirm_dialog.open = False
                    self.page.update()
                
                confirm_dialog = ft.AlertDialog(
                    title=ft.Text("Overwrite?"),
                    content=ft.Text(f"Entry '{title}' already exists. Overwrite?"),
                    actions=[
                        ft.TextButton("No", on_click=cancel_overwrite),
                        ft.TextButton("Yes", on_click=confirm_overwrite)
                    ]
                )
                self.page.overlay.append(confirm_dialog)
                confirm_dialog.open = True
                self.page.update()
                return
            
            backup_passwords()
            self.refresh_entries()
            dialog.open = False
            self.page.update()
        
        dialog_content = ft.Column(
            controls=[
                ft.Text("Entry Type", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                entry_type_dropdown,
                ft.Container(height=10),
                ft.Text("Title *", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                title_field,
                ft.Container(height=10),
                ft.Text("Username/Email", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                username_field,
                ft.Container(height=10),
                ft.Text("Password", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                ft.Row(
                    controls=[
                        password_field,
                        ft.IconButton(icon=ft.Icons.CASINO, on_click=generate_pass, bgcolor=self.colors['success'], icon_color="white", tooltip="Generate")
                    ],
                    spacing=5
                ),
                ft.Container(height=10),
                ft.Text("URL", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                url_field,
                ft.Container(height=10),
                ft.Text("Category", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                category_dropdown,
                ft.Container(height=10),
                ft.Text("Notes", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                notes_field
            ],
            scroll=ft.ScrollMode.AUTO,
            spacing=5
        )
        
        dialog = ft.AlertDialog(
            title=ft.Text("➕ Add New Entry", weight=ft.FontWeight.BOLD),
            content=ft.Container(content=dialog_content, width=450, height=500),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.close_dialog(dialog)),
                ft.ElevatedButton(
                    content=ft.Text("💾 Save Entry"),
                    on_click=save,
                    style=ft.ButtonStyle(bgcolor=self.colors['success'], color="white")
                )
            ]
        )
        
        self.page.overlay.append(dialog)
        dialog.open = True
        self.page.update()
    
    def close_dialog(self, dialog):
        """Close a dialog"""
        dialog.open = False
        self.page.update()
    
    def view_entry_dialog(self, entry):
        """Show dialog to view entry details"""
        password_visible = False
        password_display = ft.Text("**********", selectable=True)
        
        def toggle_password(e):
            nonlocal password_visible
            password_visible = not password_visible
            password_display.value = entry.get("password", "") if password_visible else "**********"
            self.page.update()
        
        def copy_to_clipboard(value):
            pyperclip.copy(value)
            self.show_snackbar("Copied to clipboard!")
        
        fields = []
        
        # Title
        fields.append(self.create_view_field("Title", entry.get("title", ""), copy_to_clipboard))
        
        # Username
        if entry.get("username"):
            fields.append(self.create_view_field("Username", entry.get("username", ""), copy_to_clipboard))
        
        # Password
        if entry.get("password"):
            fields.append(
                ft.Column(
                    controls=[
                        ft.Text("Password:", weight=ft.FontWeight.BOLD, size=12),
                        ft.Container(
                            content=ft.Row(
                                controls=[
                                    password_display,
                                    ft.Row(
                                        controls=[
                                            ft.IconButton(icon=ft.Icons.VISIBILITY, on_click=toggle_password, icon_size=18),
                                            ft.IconButton(icon=ft.Icons.COPY, on_click=lambda e: copy_to_clipboard(entry.get("password", "")), icon_size=18)
                                        ]
                                    )
                                ],
                                alignment=ft.MainAxisAlignment.SPACE_BETWEEN
                            ),
                            bgcolor=self.colors['bg_medium'],
                            padding=10,
                            border_radius=8
                        )
                    ],
                    spacing=5
                )
            )
        
        # URL
        if entry.get("url"):
            fields.append(self.create_view_field("URL", entry.get("url", ""), copy_to_clipboard))
        
        # Category
        category = entry.get("category")
        if category and category != "General":
            fields.append(self.create_view_field("Category", category, copy_to_clipboard))
        
        # Notes
        if entry.get("notes"):
            fields.append(
                ft.Column(
                    controls=[
                        ft.Text("Notes:", weight=ft.FontWeight.BOLD, size=12),
                        ft.Container(
                            content=ft.Text(entry.get("notes", ""), selectable=True),
                            bgcolor=self.colors['bg_medium'],
                            padding=10,
                            border_radius=8
                        )
                    ],
                    spacing=5
                )
            )
        
        dialog = ft.AlertDialog(
            title=ft.Text(f"👁️ View: {entry.get('title')}", weight=ft.FontWeight.BOLD),
            content=ft.Container(
                content=ft.Column(controls=fields, spacing=15, scroll=ft.ScrollMode.AUTO),
                width=400,
                height=350
            ),
            actions=[
                ft.TextButton("Close", on_click=lambda e: self.close_dialog(dialog))
            ]
        )
        
        self.page.overlay.append(dialog)
        dialog.open = True
        self.page.update()
    
    def create_view_field(self, label, value, copy_fn):
        """Helper to create a view field"""
        return ft.Column(
            controls=[
                ft.Text(f"{label}:", weight=ft.FontWeight.BOLD, size=12),
                ft.Container(
                    content=ft.Row(
                        controls=[
                            ft.Text(value, selectable=True, expand=True),
                            ft.IconButton(icon=ft.Icons.COPY, on_click=lambda e: copy_fn(value), icon_size=18)
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN
                    ),
                    bgcolor=self.colors['bg_medium'],
                    padding=10,
                    border_radius=8
                )
            ],
            spacing=5
        )
    
    def edit_entry_dialog(self, entry):
        """Show dialog to edit entry"""
        entry_type_dropdown = ft.Dropdown(
            value=entry.get("type", "password"),
            options=[
                ft.dropdown.Option("password"),
                ft.dropdown.Option("note"),
                ft.dropdown.Option("card")
            ],
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        title_field = ft.TextField(
            value=entry.get("title", ""),
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium'],
            disabled=True
        )
        
        username_field = ft.TextField(
            value=entry.get("username", ""),
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        password_field = ft.TextField(
            value=entry.get("password", ""),
            password=True,
            can_reveal_password=True,
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium'],
            expand=True
        )
        
        url_field = ft.TextField(
            value=entry.get("url", ""),
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        categories = get_categories() + ["Email", "Banking", "Social Media", "Work", "Personal", "Shopping"]
        category_dropdown = ft.Dropdown(
            value=entry.get("category", "General"),
            options=[ft.dropdown.Option(c) for c in list(set(categories))],
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        notes_field = ft.TextField(
            value=entry.get("notes", ""),
            multiline=True,
            min_lines=3,
            max_lines=5,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        def generate_pass(e):
            password_field.value = generate_password()
            password_field.update()
            self.page.update()
        
        def save(e):
            data_no, data_yes = save_entry(
                title=title_field.value,
                username=username_field.value or "",
                password=password_field.value or "",
                url=url_field.value or "",
                notes=notes_field.value or "",
                category=category_dropdown.value or "General",
                entry_type=entry_type_dropdown.value or "password"
            )
            
            if data_yes is not None:
                write_file_atomic(".\\password.txt", data_yes)
            
            backup_passwords()
            self.refresh_entries()
            dialog.open = False
            self.page.update()
        
        dialog_content = ft.Column(
            controls=[
                ft.Text("Entry Type", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                entry_type_dropdown,
                ft.Container(height=10),
                ft.Text("Title (cannot be changed)", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                title_field,
                ft.Container(height=10),
                ft.Text("Username/Email", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                username_field,
                ft.Container(height=10),
                ft.Text("Password", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                ft.Row(
                    controls=[
                        password_field,
                        ft.IconButton(icon=ft.Icons.CASINO, on_click=generate_pass, bgcolor=self.colors['success'], icon_color="white", tooltip="Generate")
                    ],
                    spacing=5
                ),
                ft.Container(height=10),
                ft.Text("URL", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                url_field,
                ft.Container(height=10),
                ft.Text("Category", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                category_dropdown,
                ft.Container(height=10),
                ft.Text("Notes", size=12, weight=ft.FontWeight.BOLD, color=self.colors['text_secondary']),
                notes_field
            ],
            scroll=ft.ScrollMode.AUTO,
            spacing=5
        )
        
        dialog = ft.AlertDialog(
            title=ft.Text(f"✏️ Edit: {entry.get('title')}", weight=ft.FontWeight.BOLD),
            content=ft.Container(content=dialog_content, width=450, height=500),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.close_dialog(dialog)),
                ft.ElevatedButton(
                    content=ft.Text("💾 Save Changes"),
                    on_click=save,
                    style=ft.ButtonStyle(bgcolor=self.colors['success'], color="white")
                )
            ]
        )
        
        self.page.overlay.append(dialog)
        dialog.open = True
        self.page.update()
    
    def delete_entry_confirm(self, entry):
        """Confirm and delete entry"""
        def confirm_delete(e):
            data_no, data_yes = delete_entry(entry.get("title"))
            write_file_atomic(".\\password.txt", data_yes)
            backup_passwords()
            self.refresh_entries()
            dialog.open = False
            self.page.update()
        
        dialog = ft.AlertDialog(
            title=ft.Text("🗑️ Delete Entry"),
            content=ft.Text(f"Are you sure you want to delete '{entry.get('title')}'?"),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.close_dialog(dialog)),
                ft.ElevatedButton(
                    content=ft.Text("Delete"),
                    on_click=confirm_delete,
                    style=ft.ButtonStyle(bgcolor=self.colors['danger'], color="white")
                )
            ]
        )
        
        self.page.overlay.append(dialog)
        dialog.open = True
        self.page.update()
    
    def generate_password_dialog(self):
        """Launch password generator in a separate process as a free-floating window.
        
        Uses subprocess to launch a second instance of the app with the --password-generator
        flag, creating a completely independent window that can be dragged anywhere.
        Ensures only one password generator window is open at a time.
        """
        # Check if a password generator process is already running
        if self.password_generator_process is not None:
            if self.password_generator_process.poll() is None:
                # Process is still running, bring its window to focus
                self.show_snackbar("Password generator is already open!")
        
        exe_path = sys.executable

        if getattr(sys, "frozen", False):
            cmd = [exe_path, "--password-generator"]
        else:
            script_path = os.path.abspath(__file__)
            cmd = [exe_path, script_path, "--password-generator"]

        creationflags = 0
        if os.name == "nt" and not getattr(sys, "frozen", False):
            creationflags = subprocess.CREATE_NO_WINDOW

        self.password_generator_process = subprocess.Popen(cmd, creationflags=creationflags)
    
    def change_master_password(self):
        """Change master password dialog"""
        old_pass_field = ft.TextField(
            hint_text="Current password",
            password=True,
            can_reveal_password=True,
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        new_pass_field = ft.TextField(
            hint_text="New password (minimum 8 characters)",
            password=True,
            can_reveal_password=True,
            height=45,
            border_radius=8,
            bgcolor=self.colors['bg_medium']
        )
        
        error_text = ft.Text("", color="red", size=12)
        
        def change(e):
            old = old_pass_field.value or ""
            new = new_pass_field.value or ""
            
            if not check_key(old):
                error_text.value = "Wrong current password!"
                self.page.update()
                return
            
            if len(new) < 8:
                error_text.value = "New password must be at least 8 characters!"
                self.page.update()
                return
            
            if old == new:
                error_text.value = "New password must be different!"
                self.page.update()
                return
            
            encrypt_with_new_key(new)
            self.show_snackbar("Master password changed successfully!")
            dialog.open = False
            self.page.update()
        
        dialog = ft.AlertDialog(
            title=ft.Text("🔑 Change Master Password", weight=ft.FontWeight.BOLD),
            content=ft.Container(
                content=ft.Column(
                    controls=[
                        ft.Text("Current Password:", size=12, weight=ft.FontWeight.BOLD),
                        old_pass_field,
                        ft.Container(height=10),
                        ft.Text("New Password:", size=12, weight=ft.FontWeight.BOLD),
                        new_pass_field,
                        error_text
                    ],
                    spacing=5
                ),
                width=350,
                height=200
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda e: self.close_dialog(dialog)),
                ft.ElevatedButton(
                    content=ft.Text("Change Password"),
                    on_click=change,
                    style=ft.ButtonStyle(bgcolor=self.colors['primary'], color="white")
                )
            ]
        )
        
        self.page.overlay.append(dialog)
        dialog.open = True
        self.page.update()


def main(page: ft.Page):
    PasswordManagerApp(page)


def password_generator_main(page: ft.Page):
    colors = {
        'primary': '#3b82f6',
        'primary_hover': '#2563eb',
        'success': '#10b981',
        'danger': '#ef4444',
        'danger_hover': '#dc2626',
        'warning': '#f59e0b',
        'bg_dark': '#1a1a1a',
        'bg_medium': '#2d2d2d',
        'bg_light': '#3a3a3a',
        'text_primary': '#ffffff',
        'text_secondary': '#9ca3af',
        'border': '#404040'
    }

    page.title = "🎲 Password Generator"
    page.window.width = 420
    page.window.height = 700
    page.window.min_width = 420
    page.window.min_height = 700
    page.window.resizable = True
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = colors['bg_dark']
    page.padding = 20

    password_display = ft.TextField(
        value="",
        read_only=True,
        text_align=ft.TextAlign.CENTER,
        text_style=ft.TextStyle(size=16, weight=ft.FontWeight.BOLD, font_family="monospace"),
        height=55,
        border_radius=8,
        bgcolor=colors['bg_medium'],
        border_color=colors['success']
    )

    length_value = ft.Text("16 characters", weight=ft.FontWeight.BOLD, color=colors['primary'])

    def update_length(val):
        length_value.value = f"{int(val)} characters"
        page.update()

    length_slider = ft.Slider(
        min=8,
        max=32,
        value=16,
        divisions=24,
        label="{value}",
        on_change_end=lambda e: update_length(e.control.value),
        active_color=colors['success']
    )

    uppercase_check = ft.Checkbox(label="Uppercase Letters (A-Z)", value=True, active_color=colors['success'])
    lowercase_check = ft.Checkbox(label="Lowercase Letters (a-z)", value=True, active_color=colors['success'])
    digits_check = ft.Checkbox(label="Numbers (0-9)", value=True, active_color=colors['success'])
    symbols_check = ft.Checkbox(label="Symbols (!@#$%^&*)", value=True, active_color=colors['success'])

    def generate():
        pwd = generate_password(
            length=int(length_slider.value),
            use_uppercase=uppercase_check.value,
            use_lowercase=lowercase_check.value,
            use_digits=digits_check.value,
            use_symbols=symbols_check.value
        )
        password_display.value = pwd
        page.update()

    def copy_password(e):
        pwd = password_display.value
        if pwd:
            pyperclip.copy(pwd)
            page.snack_bar = ft.SnackBar(
                content=ft.Text("Password copied to clipboard!"),
                bgcolor=colors['bg_medium']
            )
            page.snack_bar.open = True
            page.update()

    generate()

    page.add(
        ft.Column(
            controls=[
                ft.Text("🎲 Password Generator", size=24, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),
                ft.Container(height=10),
                ft.Text("Generated Password:", size=12, weight=ft.FontWeight.BOLD, color=colors['text_secondary']),
                password_display,
                ft.Divider(height=20, color=colors['border']),
                ft.Text("Password Length:", size=12, weight=ft.FontWeight.BOLD),
                ft.Row(
                    controls=[
                        ft.Container(content=length_slider, expand=True),
                        length_value
                    ]
                ),
                ft.Container(height=5),
                ft.Text("Character Types:", size=12, weight=ft.FontWeight.BOLD),
                ft.Container(
                    content=ft.Column(
                        controls=[
                            uppercase_check,
                            lowercase_check,
                            digits_check,
                            symbols_check
                        ],
                        spacing=2
                    ),
                    bgcolor=colors['bg_medium'],
                    border_radius=8,
                    padding=10
                ),
                ft.Container(height=10),
                ft.ElevatedButton(
                    content=ft.Text("🎲  Generate New Password"),
                    on_click=lambda e: generate(),
                    width=380,
                    height=45,
                    style=ft.ButtonStyle(bgcolor=colors['success'], color="white", shape=ft.RoundedRectangleBorder(radius=10))
                ),
                ft.ElevatedButton(
                    content=ft.Text("📋  Copy to Clipboard"),
                    on_click=copy_password,
                    width=380,
                    height=45,
                    style=ft.ButtonStyle(bgcolor=colors['primary'], color="white", shape=ft.RoundedRectangleBorder(radius=10))
                ),
            ],
            spacing=8,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
    )


if __name__ == "__main__":
    if "--password-generator" in sys.argv:
        ft.app(target=password_generator_main)
    else:
        ft.app(target=main)
