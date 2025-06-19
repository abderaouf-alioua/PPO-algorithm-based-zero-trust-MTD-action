import customtkinter as ctk
import threading
import time
from Environment.SDPGateway import SDPGateway

# Configure appearance settings
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class MicroSegmentEnvironment:
    # Color constants
    PRIMARY = "#2c3e50"
    SECONDARY = "#3498db"
    SUCCESS = "#2ecc71"
    WARNING = "#f39c12"
    DANGER = "#e74c3c"
    TEXT_COLOR = "#ecf0f1"
    CARD_BG = "#34495e"
    LOG_BG = "#2c3e50"

    # Font constants
    # TITLE_FONT = ctk.CTkFont(family="Arial", size=20, weight="bold")
    # HEADER_FONT = ctk.CTkFont(family="Arial", size=14, weight="bold")
    # BODY_FONT = ctk.CTkFont(family="Arial", size=12)
    # MONO_FONT = ctk.CTkFont(family="Consolas", size=11)
    # STAT_FONT = ctk.CTkFont(family="Arial", size=24, weight="bold")
    # BUTTON_FONT = ctk.CTkFont(family="Arial", size=12, weight="bold")

    def __init__(self):
        self.gateway = SDPGateway(1, "Main Gateway", 1)
        self._initialize_environment()
        self.monitoring = True

        # Create main window
        self.root = ctk.CTk()
        self.root.title("Micro-Segment Security Dashboard")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)

        # Configure grid layout
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        # Create UI components
        self._create_title_bar()
        self._create_main_tabs()
        self._start_monitoring()

        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _initialize_environment(self):
        """Setup microservices and users"""
        microservices = [
            (1, "Web Service"), (2, "Database Service"),
            (3, "Authentication Service"), (4, "File Storage Service")

        ]
        for service_id, service_name in microservices:
            self.gateway.add_microservice(service_id, service_name)

        users = [
            (1, "Alice Johnson", 1), (2, "Bob Smith", 1), (3, "Carol Wilson", 1),
            (4, "David Brown", 2), (5, "Eva Davis", 2), (6, "Frank Miller", 2),
            (7, "Grace Lee", 3), (8, "Henry Chen", 3), (9, "Ivy Taylor", 4),
            (10, "Jack Anderson", 4) ,(11, "alioua abderaouf" , 4) ,(12, "yadroudji chouaib", 1)
        ]
        for user_id, user_name, service_id in users:
            self.gateway.add_user(user_id, user_name, service_id)

        for ms in self.gateway.microservices.values():
            ms.calculate_performance_after_add_user()

    def _create_title_bar(self):
        """Create application title bar"""
        title_frame = ctk.CTkFrame(self.root, corner_radius=0)
        title_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 0))
        title_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            title_frame,
            text="🔐 Micro-Segment Security Dashboard",
            font=ctk.CTkFont(family="Arial", size=20, weight="bold"),
            text_color=self.TEXT_COLOR
        )
        title_label.grid(row=0, column=0, padx=20, pady=15, sticky="w")

        # Status indicator
        self.status_indicator = ctk.CTkLabel(
            title_frame,
            text="● Active",
            text_color=self.SUCCESS,
            font=ctk.CTkFont(family="Arial", size=12)
        )
        self.status_indicator.grid(row=0, column=1, padx=20, pady=15, sticky="e")

    def _create_main_tabs(self):
        """Create tabbed interface"""
        self.tab_view = ctk.CTkTabview(
            self.root,
            corner_radius=10,
            segmented_button_selected_color=self.SECONDARY,
            segmented_button_selected_hover_color=self.SECONDARY,
            text_color=self.TEXT_COLOR
        )
        self.tab_view.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.tab_view.grid_rowconfigure(0, weight=1)
        self.tab_view.grid_columnconfigure(0, weight=1)

        # Create tabs
        self.tab_view.add("📊 Overview")
        self.tab_view.add("🔧 Microservices")
        self.tab_view.add("👥 Users")
        self.tab_view.add("⚙️ Controls")

        # Configure each tab
        self._create_overview_tab()
        self._create_microservices_tab()
        self._create_users_tab()
        self._create_controls_tab()

    def _create_overview_tab(self):
        """Create overview tab components"""
        tab = self.tab_view.tab("📊 Overview")
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        # Gateway status frame
        gw_frame = ctk.CTkFrame(tab, corner_radius=10)
        gw_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        ctk.CTkLabel(
            gw_frame,
            text="Gateway Status",
            font=ctk.CTkFont(family="Arial", size=14, weight="bold"),
            anchor="w"
        ).grid(row=0, column=0, padx=15, pady=(10, 5), sticky="w")

        self.gateway_info = ctk.CTkTextbox(
            gw_frame,
            width=300,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=self.CARD_BG,
            text_color=self.TEXT_COLOR,
            activate_scrollbars=False
        )
        self.gateway_info.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        # Statistics frame
        stats_frame = ctk.CTkFrame(tab, corner_radius=10)
        stats_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        stats_frame.grid_rowconfigure(0, weight=1)
        stats_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            stats_frame,
            text="Quick Statistics",
            font=ctk.CTkFont(family="Arial", size=14, weight="bold"),
            anchor="w"
        ).grid(row=0, column=0, padx=15, pady=(10, 5), sticky="w")

        self._create_stats_grid(stats_frame)

    def _create_stats_grid(self, parent):
        """Create statistics cards"""
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        stats = [
            ("Total Microservices", "5", self.PRIMARY),
            ("Total Users", "12", self.SUCCESS),
            ("Active Services", "0", self.DANGER),
            ("Avg Risk Score", "0.0", self.WARNING)
        ]

        self.stat_labels = {}
        for i, (title, default, color) in enumerate(stats):
            row, col = divmod(i, 2)
            card = ctk.CTkFrame(
                frame,
                fg_color=self.CARD_BG,
                corner_radius=10
            )
            card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")

            ctk.CTkLabel(
                card,
                text=title,
                font=ctk.CTkFont(family="Arial", size=12),
                text_color="#bdc3c7"
            ).pack(pady=(15, 5))

            value_label = ctk.CTkLabel(
                card,
                text=default,
                font=ctk.CTkFont(family="Arial", size=24, weight="bold"),
                text_color=color
            )
            value_label.pack(pady=(0, 15))
            self.stat_labels[title] = value_label

        # Configure grid weights
        for i in range(2):
            frame.grid_columnconfigure(i, weight=1)
            frame.grid_rowconfigure(i, weight=1)

    def _create_microservices_tab(self):
        """Create microservices tab"""
        tab = self.tab_view.tab("🔧 Microservices")
        tab.grid_rowconfigure(0, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        frame = ctk.CTkFrame(tab, corner_radius=10)
        frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Create scrollable frame
        scroll_frame = ctk.CTkScrollableFrame(
            frame,
            fg_color=self.CARD_BG,
            corner_radius=8
        )
        scroll_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Create treeview-like structure
        columns = ['ID', 'Name', 'IP', 'Status', 'Risk', 'CPU', 'Memory', 'Users']
        self._create_header_row(scroll_frame, columns)

        self.ms_rows = []
        for _ in range(5):  # Create 5 service rows
            row_frame = ctk.CTkFrame(scroll_frame, fg_color=self.LOG_BG, height=40)
            row_frame.pack(fill="x", pady=2, padx=5)
            row_labels = []

            for col in columns:
                label = ctk.CTkLabel(
                    row_frame,
                    text="",
                    width=120,
                    anchor="center",
                    font=ctk.CTkFont(family="Consolas", size=11)
                )
                label.pack(side="left", expand=True, padx=2)
                row_labels.append(label)
            self.ms_rows.append(row_labels)

    def _create_header_row(self, parent, columns):
        """Create table header row"""
        header_frame = ctk.CTkFrame(parent, fg_color="#2a3b4c", height=40)
        header_frame.pack(fill="x", pady=(0, 5), padx=5)

        for col in columns:
            ctk.CTkLabel(
                header_frame,
                text=col,
                width=120,
                anchor="center",
                font=ctk.CTkFont(family="Arial", size=14, weight="bold"),
                text_color=self.SECONDARY
            ).pack(side="left", expand=True, padx=2)

    def _create_users_tab(self):
        """Create users tab"""
        tab = self.tab_view.tab("👥 Users")
        tab.grid_rowconfigure(0, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        frame = ctk.CTkFrame(tab, corner_radius=10)
        frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Create scrollable frame
        scroll_frame = ctk.CTkScrollableFrame(
            frame,
            fg_color=self.CARD_BG,
            corner_radius=8
        )
        scroll_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Create treeview-like structure
        columns = ['ID', 'Name', 'Service', 'Status', 'DLPCS', 'CPU', 'Memory', 'Bandwidth', 'Latency']
        self._create_header_row(scroll_frame, columns)

        self.user_rows = []
        for _ in range(12):  # Create 12 user rows
            row_frame = ctk.CTkFrame(scroll_frame, fg_color=self.LOG_BG, height=40)
            row_frame.pack(fill="x", pady=2, padx=5)
            row_labels = []

            for col in columns:
                label = ctk.CTkLabel(
                    row_frame,
                    text="",
                    width=100,
                    anchor="center",
                    font=ctk.CTkFont(family="Consolas", size=11)
                )
                label.pack(side="left", expand=True, padx=2)
                row_labels.append(label)
            self.user_rows.append(row_labels)

    def _create_controls_tab(self):
        """Create controls tab"""
        tab = self.tab_view.tab("⚙️ Controls")
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        # Control buttons frame
        button_frame = ctk.CTkFrame(tab, fg_color="transparent")
        button_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")

        buttons = [
            ("🔄 Update Metrics", self._update_user_metrics, self.PRIMARY),
            ("🔒 Isolate Random Service", self._isolate_random_service, self.DANGER),
            ("🔓 Restore All Services", self._restore_all_services, self.SUCCESS),
            ("🎲 Shuffle IPs", self._shuffle_all_ips, self.WARNING),
            ("📊 Refresh Data", self._refresh_all_data, "#9b59b6")
        ]

        for i, (text, command, color) in enumerate(buttons):
            btn = ctk.CTkButton(
                button_frame,
                text=text,
                command=command,
                fg_color=color,
                hover_color=self._adjust_color(color, -20),
                font=ctk.CTkFont(family="Arial", size=12, weight="bold"),
                corner_radius=8,
                height=45
            )
            btn.grid(row=i // 3, column=i % 3, padx=10, pady=10, sticky="ew")

        # Configure grid
        for i in range(3):
            button_frame.grid_columnconfigure(i, weight=1)

        # Status log
        log_frame = ctk.CTkFrame(tab, corner_radius=10)
        log_frame.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            log_frame,
            text="Activity Log",
            font=ctk.CTkFont(family="Arial", size=14, weight="bold"),
            anchor="w"
        ).grid(row=0, column=0, padx=15, pady=(10, 5), sticky="w")

        self.log_text = ctk.CTkTextbox(
            log_frame,
            fg_color=self.LOG_BG,
            text_color=self.TEXT_COLOR,
            font=ctk.CTkFont(family="Consolas", size=11),
            activate_scrollbars=True,
            corner_radius=8
        )
        self.log_text.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

        self._log_message("🚀 Micro-Segment Environment Initialized")
        self._log_message("📡 Monitoring started...")

    def _log_message(self, message):
        """Add timestamped message to log"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")

    def _start_monitoring(self):
        """Start monitoring thread"""

        def monitor():
            while self.monitoring:
                self.root.after(0, self._update_displays)
                time.sleep(2)

        threading.Thread(target=monitor, daemon=True).start()

    def _update_displays(self):
        """Update all GUI components"""
        self._update_gateway_info()
        self._update_stats()
        self._update_microservices_table()
        self._update_users_table()

    def _update_gateway_info(self):
        """Update gateway status display"""
        status = self.gateway.get_gateway_status()
        info = (
            f"Gateway ID: {status['gateway_id']}\n"
            f"Name: {status['name']}\n"
            f"IP Address: {status['ip_address']}\n"
            f"Total Microservices: {status['total_microservices']}\n"
            f"Active Microservices: {status['active_microservices']}\n"
            f"Total Users: {status['total_users']}\n"
            f"Active Users: {status['active_users']}"
        )
        self.gateway_info.configure(state="normal")
        self.gateway_info.delete("1.0", "end")
        self.gateway_info.insert("1.0", info)
        self.gateway_info.configure(state="disabled")

    def _update_stats(self):
        """Update statistics cards"""
        gateway_status = self.gateway.get_gateway_status()
        active_services = sum(
            ms.is_active for ms in self.gateway.microservices.values()
        )

        # Calculate average risk score
        risk_scores = [ms.Risk_assessment for ms in self.gateway.microservices.values()]

        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

        stats = {
            "Total Microservices": "5",
            "Total Users": str(gateway_status['total_users']),
            "Active Services": str(active_services),
            "Avg Risk Score": f"{avg_risk:.3f}"
        }

        for title, value in stats.items():
            self.stat_labels[title].configure(text=value)

    def _update_microservices_table(self):
        """Update microservices table"""
        for i, ms in enumerate(self.gateway.microservices.values()):
            if i >= len(self.ms_rows):
                break

            status = ms.ms_status()
            values = [
                str(status['microservice_id']),
                status['name'],
                status['ip_address'],
                "Active" if status['is_active'] else "Inactive",
                f"{status['Risk_assessment']:.3f}",
                f"{status['overhead'][0]:.2f}",
                f"{status['overhead'][2]:.2f}",
                f"{status['active_users']}/{status['total_users']}"
            ]

            for j, value in enumerate(values):
                self.ms_rows[i][j].configure(text=value)

                # Color coding for status
                if j == 3:  # Status column
                    color = self.SUCCESS if status['is_active'] else self.DANGER
                    self.ms_rows[i][j].configure(text_color=color)
                elif j == 4:  # Risk column
                    risk = status['Risk_assessment']
                    color = self.SUCCESS if risk < 0.3 else self.WARNING if risk < 0.7 else self.DANGER
                    self.ms_rows[i][j].configure(text_color=color)

    def _update_users_table(self):
        """Update users table"""
        user_idx = 0
        for ms in self.gateway.microservices.values():
            for user in ms.users.values():
                if user_idx >= len(self.user_rows):
                    return

                status = user.get_user_status()
                values = [
                    str(status['user_id']),
                    status['user_name'],
                    ms.name,
                    "Active" if status['is_active'] else "Inactive",
                    f"{status['privilege_compliance_score']:.3f}",
                    f"{status['cpu_usage']:.2f}",
                    f"{status['memory_usage']:.2f}",
                    f"{status['bandwidth_usage']:.2f}",
                    f"{status['latency']:.1f}"
                ]

                for j, value in enumerate(values):
                    self.user_rows[user_idx][j].configure(text=value)

                    # Color coding
                    if j == 3:  # Status column
                        color = self.SUCCESS if status['is_active'] else self.DANGER
                        self.user_rows[user_idx][j].configure(text_color=color)
                    elif j == 4:  # DLPCS column
                        score = status['privilege_compliance_score']
                        color = self.SUCCESS if score > 0.7 else self.WARNING if score > 0.4 else self.DANGER
                        self.user_rows[user_idx][j].configure(text_color=color)

                user_idx += 1

    # Control functions
    def _update_user_metrics(self):
        """Update random user metrics"""
        import random
        updated_users = []
        for ms in self.gateway.microservices.values():
            if ms.users and random.random() > 0.5:
                user = random.choice(list(ms.users.values()))
                user.update_metrics()
                user.update_risk_score()
                updated_users.append(user.user_name)
                ms.calculate_performance_after_add_user()

        if updated_users:
            self._log_message(f"📈 Updated metrics for: {', '.join(updated_users)}")

    def _isolate_random_service(self):
        """Isolate a random microservice"""
        import random
        active_services = [ms for ms in self.gateway.microservices.values() if ms.is_active]
        if active_services:
            service = random.choice(active_services)
            service.isolate()
            self._log_message(f"🔒 Isolated microservice: {service.name}")
        else:
            self._log_message("⚠️ No active services to isolate")

    def _restore_all_services(self):
        """Restore all isolated services"""
        restored = []
        for ms in self.gateway.microservices.values():
            if not ms.is_active:
                ms.restore_connection()
                for user in ms.users.values():
                    user.reset()
                restored.append(ms.name)

        if restored:
            self._log_message(f"🔓 Restored services: {', '.join(restored)}")
        else:
            self._log_message("ℹ️ All services are already active")

    def _shuffle_all_ips(self):
        """Shuffle all IP addresses"""
        self.gateway.shuffle_ip()
        for ms in self.gateway.microservices.values():
            old_ip = ms.ip_address
            ms.shuffle_ip()
            self._log_message(f"🎲 {ms.name}: {old_ip} → {ms.ip_address}")

    def _refresh_all_data(self):
        """Refresh all data displays"""
        self._log_message("📊 Refreshing all data displays...")
        self._update_displays()

    def _adjust_color(self, hex_color, amount):
        """Lighten or darken a color"""
        rgb = tuple(int(hex_color.lstrip('#')[i:i + 2], 16) for i in (0, 2, 4))
        adjusted = tuple(max(0, min(255, x + amount)) for x in rgb)
        return f"#{adjusted[0]:02x}{adjusted[1]:02x}{adjusted[2]:02x}"

    def _on_closing(self):
        """Handle application closing"""
        self.monitoring = False
        self.root.destroy()

    def run(self):
        """Run the GUI application"""
        self.root.mainloop()


# if __name__ == "__main__":
#     MicroSegmentEnvironment().run()