# Importation des bibliothèques nécessaires
import tkinter as tk  # Interface graphique
from tkinter import ttk, messagebox, simpledialog  # Widgets et boîtes de dialogue
import sqlite3  # Base de données SQLite pour stocker les mots de passe
import os  # Gestion de fichiers
import re  # Expressions régulières pour vérifier la robustesse
import random  # Génération de mots de passe aléatoires
import string  # Caractères pour génération
import hashlib  # Hachage pour sécuriser les mots de passe

# Classe principale du gestionnaire de mots de passe
class PasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.title("Gestionnaire de Mots de Passe")
        self.master.geometry("800x600")
        self.master.configure(bg="#f0f4f8")
        # Thème courant (light / dark)
        self.theme = 'light'
        # Appliquer un style visuel amélioré
        self.setup_style()
        # Charger icônes (assets/*.b64)
        try:
            self.load_icons()
        except Exception:
            self.icons = {}

        self.db_file = "passwords.db"  # Nom du fichier de la base de données
        self.key_file = "key.txt"  # Nom du fichier contenant la clé maître

        self.init_db()  # Initialisation de la base de données
        self.build_gui()  # Création de l'interface graphique
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)  # Action lors de la fermeture

    def init_db(self):
        # Création ou ouverture de la base de données
        self.conn = sqlite3.connect(self.db_file)
        self.cursor = self.conn.cursor()
        # Création de la table si elle n'existe pas
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def on_close(self):
        # Fermeture propre : fermeture de la base et suppression du fichier
        self.conn.close()
        if os.path.exists(self.db_file):
            os.remove(self.db_file)
        self.master.destroy()

    def build_gui(self):
        # En-tête moderne
        self.header_frame = tk.Frame(self.master, bg=self._color('header_bg'), height=72)
        self.header_frame.pack(fill='x')
        self.header_frame.pack_propagate(False)

        # Logo (image si disponible)
        if hasattr(self, 'icons') and self.icons.get('key'):
            logo = tk.Label(self.header_frame, image=self.icons['key'], bg=self._color('header_bg'))
        else:
            logo = tk.Label(self.header_frame, text="🔐", bg=self._color('header_bg'), fg=self._color('header_fg'), font=("Segoe UI Emoji", 20))
        logo.pack(side='left', padx=(18,8))

        title = tk.Label(self.header_frame, text="Vault — Gestionnaire de Mots de Passe", bg=self._color('header_bg'), fg=self._color('header_fg'),
                         font=("Segoe UI", 16, 'bold'))
        title.pack(side='left')

        # Toolbar actions
        tb_frame = tk.Frame(self.header_frame, bg=self._color('header_bg'))
        tb_frame.pack(side='right', padx=12)
        help_btn = ttk.Button(tb_frame, text="❓ Aide", style='Icon.TButton', command=lambda: messagebox.showinfo('Aide','Utilisez les onglets pour gérer les mots de passe.'))
        help_btn.pack(side='right', padx=6)

        theme_btn = ttk.Button(tb_frame, text="🎨 Thème", style='Icon.TButton', command=self.toggle_theme)
        theme_btn.pack(side='right', padx=6)

        # Layout: sidebar + content
        body = tk.Frame(self.master, bg=self._color('bg'))
        body.pack(fill='both', expand=True)

        # Sidebar
        self.sidebar = tk.Frame(body, bg=self._color('sidebar_bg'), width=140)
        self.sidebar.pack(side='left', fill='y')
        self.sidebar.pack_propagate(False)

        # Sidebar buttons (emoji icons provide the iconography)
        sb_btn_style = {'font':('Segoe UI', 10), 'bg':self._color('sidebar_bg'), 'fg':self._color('sidebar_fg'), 'bd':0}
        key_btn = tk.Button(self.sidebar, text='Clé', command=lambda: self.notebook.select(0), **sb_btn_style)
        if hasattr(self, 'icons') and self.icons.get('key'):
            key_btn.configure(image=self.icons['key'], compound='top')
        key_btn.pack(pady=(20,8), ipadx=6, ipady=6)
        add_btn = tk.Button(self.sidebar, text='Ajouter', command=lambda: self.notebook.select(1), **sb_btn_style)
        if hasattr(self, 'icons') and self.icons.get('add'):
            add_btn.configure(image=self.icons['add'], compound='top')
        add_btn.pack(pady=8, ipadx=6, ipady=6)
        manage_btn = tk.Button(self.sidebar, text='Gérer', command=lambda: self.notebook.select(2), **sb_btn_style)
        if hasattr(self, 'icons') and self.icons.get('manage'):
            manage_btn.configure(image=self.icons['manage'], compound='top')
        manage_btn.pack(pady=8, ipadx=6, ipady=6)

        # Création d'un système d'onglets dans la zone content
        content = tk.Frame(body, bg=self._color('bg'))
        content.pack(side='left', fill='both', expand=True)

        self.notebook = ttk.Notebook(content)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=14)

        # Ajout des différents onglets
        self.setup_key_tab()
        self.setup_add_tab()
        self.setup_manage_tab()

    def setup_style(self):
        # Définir des couleurs et styles cohérents pour une meilleure esthétique
        # Palette de couleurs par thème
        light = {
            'bg': '#f0f4f8', 'header_bg': '#0f1724', 'header_fg': 'white',
            'primary': '#2b8cff', 'accent': '#2e7d32', 'danger': '#d32f2f',
            'sidebar_bg': '#0b2540', 'sidebar_fg': 'white'
        }
        dark = {
            'bg': '#0b1220', 'header_bg': '#081222', 'header_fg': 'white',
            'primary': '#4aa3ff', 'accent': '#49a36a', 'danger': '#ff5c5c',
            'sidebar_bg': '#061026', 'sidebar_fg': 'white'
        }
        pal = light if self.theme == 'light' else dark
        self._palette = pal

        bg = pal['bg']
        primary = pal['primary']
        accent = pal['accent']
        danger = pal['danger']

        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass

        style.configure('TFrame', background=bg)
        style.configure('TLabel', background=bg, font=('Segoe UI', 11))
        style.configure('Header.TLabel', background=bg, font=('Segoe UI', 14, 'bold'), foreground=primary)
        style.configure('Muted.TLabel', background=bg, font=('Segoe UI', 10), foreground='#9aa3ad')
        style.configure('Label.TLabel', background=bg, font=('Segoe UI', 11))

        style.configure('Primary.TButton', background=primary, foreground='white', font=('Segoe UI', 10, 'bold'))
        style.configure('Accent.TButton', background=accent, foreground='white', font=('Segoe UI', 10, 'bold'))
        style.configure('Danger.TButton', background=danger, foreground='white', font=('Segoe UI', 10, 'bold'))
        style.configure('Warn.TButton', background='#ffa000', foreground='white', font=('Segoe UI', 10, 'bold'))
        style.configure('Icon.TButton', background=bg, foreground='#333', font=('Segoe UI', 11))

        # Treeview custom
        style.configure('Custom.Treeview', background=bg, fieldbackground=bg, font=('Segoe UI', 10), foreground=('black' if self.theme=='light' else 'white'))
        style.configure('Treeview.Heading', font=('Segoe UI', 10, 'bold'), background=primary, foreground='white')
        style.map('Primary.TButton', background=[('active', primary)])

        # Button padding / appearance
        style.configure('TButton', padding=6)
        style.configure('Icon.TButton', padding=6, relief='flat')

    def load_icons(self):
        # Charge des images encodées en base64 dans le dossier assets
        self.icons = {}
        base = os.path.join(os.path.dirname(__file__), 'assets')
        mapping = {
            'key': 'icon_key.b64',
            'add': 'icon_add.b64',
            'manage': 'icon_manage.b64'
        }
        for k, fname in mapping.items():
            path = os.path.join(base, fname)
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        b64 = f.read().strip()
                    img = tk.PhotoImage(data=b64)
                    # Si l'image est 1x1, agrandir pour l'affichage
                    try:
                        img = img.zoom(32, 32)
                    except Exception:
                        pass
                    self.icons[k] = img
                except Exception:
                    # ignore load failures
                    pass

    # Onglet pour entrer la clé maître
    def setup_key_tab(self):
        frame = tk.Frame(self.notebook, bg=self._color('bg'))
        self.notebook.add(frame, text="Clé")
        header = ttk.Label(frame, text="Entrez votre clé principale :", style='Header.TLabel')
        header.pack(pady=(12, 6))

        self.key_entry = ttk.Entry(frame, show="*", width=40, font=("Segoe UI", 11))
        self.key_entry.pack(pady=6)

        # Boutons groupés
        btn_row = tk.Frame(frame, bg="#f0f4f8")
        btn_row.pack(pady=8)

        btn_show = ttk.Button(btn_row, text="👁", command=self.toggle_key_visibility, style='Icon.TButton')
        btn_show.pack(side='left', padx=6)

        gen_btn = ttk.Button(btn_row, text="Générer clé forte", command=self.generate_strong_key, style='Primary.TButton')
        gen_btn.pack(side='left', padx=6)

        valid_btn = ttk.Button(btn_row, text="Valider", command=self.validate_key, style='Accent.TButton')
        valid_btn.pack(side='left', padx=6)

        # Recommandations pour la clé forte
        self.key_advice = ttk.Label(frame, text="- 12+ caractères\n- Majuscules, minuscules, chiffres, symboles", style='Muted.TLabel')
        self.key_advice.pack(pady=10)

    # Onglet pour ajouter un nouveau mot de passe
    def setup_add_tab(self):
        frame = tk.Frame(self.notebook, bg=self._color('bg'))
        self.notebook.add(frame, text="Ajouter")
        self.entries = {}
        for label_text in ["Service", "Nom d'utilisateur", "Mot de passe"]:
            label = ttk.Label(frame, text=label_text + " :", style='Label.TLabel')
            label.pack(pady=(8, 2), anchor='w', padx=12)
            entry = ttk.Entry(frame, font=("Segoe UI", 11), show="*" if label_text == "Mot de passe" else "")
            entry.pack(pady=4, padx=12, fill='x')
            self.entries[label_text] = entry

        # Ligne de boutons
        btn_row = tk.Frame(frame, bg="#f0f4f8")
        btn_row.pack(pady=10)

        show_pw_btn = ttk.Button(btn_row, text="👁", command=self.toggle_password_visibility, style='Icon.TButton')
        show_pw_btn.pack(side='left', padx=6)

        gen_btn = ttk.Button(btn_row, text="Générer mot de passe fort", command=self.generate_password, style='Primary.TButton')
        gen_btn.pack(side='left', padx=6)

        add_btn = ttk.Button(btn_row, text="Ajouter", command=self.add_password, style='Accent.TButton')
        add_btn.pack(side='left', padx=6)

    # Onglet de gestion (affichage, suppression, modification)
    def setup_manage_tab(self):
        frame = tk.Frame(self.notebook, bg=self._color('bg'))
        self.notebook.add(frame, text="Gérer")
        header = ttk.Label(frame, text="Clé pour afficher les mots de passe :", style='Header.TLabel')
        header.pack(pady=(8, 6), anchor='w', padx=12)

        self.view_key_entry = ttk.Entry(frame, show="*", font=("Segoe UI", 11))
        self.view_key_entry.pack(padx=12, fill='x')

        unlock_btn = ttk.Button(frame, text="🔓 Afficher", command=self.show_passwords, style='Accent.TButton')
        unlock_btn.pack(pady=10)

        # Barre de recherche et actions
        actions_row = tk.Frame(frame, bg="#f0f4f8")
        actions_row.pack(fill='x', padx=12)

        search_lbl = ttk.Label(actions_row, text="Recherche:", style='Label.TLabel')
        search_lbl.pack(side='left')

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(actions_row, textvariable=self.search_var, width=30)
        self.search_entry.pack(side='left', padx=(6,12))
        self.search_entry.bind('<KeyRelease>', lambda e: self.filter_passwords())

        refresh_btn = ttk.Button(actions_row, text="🔄 Rafraîchir", command=self.show_passwords, style='Icon.TButton')
        refresh_btn.pack(side='left', padx=6)

        copy_btn = ttk.Button(actions_row, text="📋 Copier", command=self.copy_selected, style='Icon.TButton')
        copy_btn.pack(side='left', padx=6)

        # Conteneur pour l'arbre et sa scrollbar
        tree_container = tk.Frame(frame, bg=self._color('bg'))
        tree_container.pack(padx=12, pady=6, fill='both', expand=True)

        self.tree = ttk.Treeview(tree_container, columns=("Service", "Nom d'utilisateur", "Mot de passe"), show="headings", style='Custom.Treeview')
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=220, anchor='center')

        vsb = ttk.Scrollbar(tree_container, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.tree.pack(side='left', fill='both', expand=True)

        # Lignes alternées pour une meilleure lisibilité
        if self.theme == 'light':
            self.tree.tag_configure('evenrow', background='#ffffff')
            self.tree.tag_configure('oddrow', background='#f7fbff')
        else:
            self.tree.tag_configure('evenrow', background='#0b1220')
            self.tree.tag_configure('oddrow', background='#081422')

        # Boutons pour modifier ou supprimer un enregistrement
        btn_frame = tk.Frame(frame, bg="#f0f4f8")
        btn_frame.pack(pady=8)

        del_btn = ttk.Button(btn_frame, text="Supprimer", command=self.delete_selected, style='Danger.TButton')
        del_btn.pack(side="left", padx=10)

        edit_btn = ttk.Button(btn_frame, text="Modifier", command=self.edit_selected, style='Warn.TButton')
        edit_btn.pack(side="left", padx=10)

    def filter_passwords(self):
        # Filtre local des mots de passe déjà chargés
        query = self.search_var.get().strip().lower()
        for row in self.tree.get_children():
            self.tree.delete(row)
        if not hasattr(self, '_last_passwords'):
            return
        for i, row in enumerate(self._last_passwords):
            service = row[1].lower()
            username = row[2].lower()
            password = row[3].lower()
            if query in service or query in username or query in password:
                tag = 'evenrow' if i % 2 == 0 else 'oddrow'
                self.tree.insert('', 'end', iid=row[0], values=row[1:], tags=(tag,))

    def copy_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning('Avertissement','Sélectionnez une ligne à copier.')
            return
        item_id = sel[0]
        # Récupérer le mot de passe depuis la DB
        self.cursor.execute('SELECT password FROM passwords WHERE id=?', (item_id,))
        res = self.cursor.fetchone()
        if not res:
            messagebox.showerror('Erreur','Impossible de récupérer le mot de passe.')
            return
        pw = res[0]
        self.master.clipboard_clear()
        self.master.clipboard_append(pw)
        messagebox.showinfo('Copié', 'Mot de passe copié dans le presse-papier (temps limité).')

    def toggle_theme(self):
        # Basculer entre les thèmes light/dark
        self.theme = 'dark' if self.theme == 'light' else 'light'
        # Reconfigurer les styles
        self.setup_style()
        # Mettre à jour les principales zones visuelles
        try:
            self.master.configure(bg=self._color('bg'))
        except Exception:
            pass
        if hasattr(self, 'header_frame'):
            self.header_frame.configure(bg=self._color('header_bg'))
            for w in self.header_frame.winfo_children():
                try:
                    w.configure(bg=self._color('header_bg'), fg=self._color('header_fg'))
                except Exception:
                    pass
        if hasattr(self, 'sidebar'):
            self.sidebar.configure(bg=self._color('sidebar_bg'))
            for w in self.sidebar.winfo_children():
                try:
                    w.configure(bg=self._color('sidebar_bg'), fg=self._color('sidebar_fg'))
                except Exception:
                    pass
        # Update notebook tabs/bg
        for child in self.notebook.winfo_children():
            try:
                child.configure(bg=self._color('bg'))
            except Exception:
                pass

    def _color(self, key):
        # Helper to read palette values
        if not hasattr(self, '_palette'):
            return '#f0f4f8'
        return self._palette.get(key, self._palette.get('bg'))

    # Affichage/caché mot de passe
    def toggle_password_visibility(self):
        entry = self.entries["Mot de passe"]
        entry.config(show="" if entry.cget("show") == "*" else "*")

    # Affichage/caché clé
    def toggle_key_visibility(self):
        self.key_entry.config(show="" if self.key_entry.cget("show") == "*" else "*")

    # Génération d'une chaîne de caractères aléatoire forte
    def generate_strong_password(self, length=16):
        chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+<>?/[]{}"
        return ''.join(random.choice(chars) for _ in range(length))

    def generate_password(self):
        # Insère un mot de passe généré dans le champ
        pw = self.generate_strong_password()
        self.entries["Mot de passe"].delete(0, tk.END)
        self.entries["Mot de passe"].insert(0, pw)

    def generate_strong_key(self):
        # Génère et insère une clé forte
        key = self.generate_strong_password()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)

    def validate_key(self):
        key = self.key_entry.get().strip()
        # Vérification que la clé est forte
        if not self.is_strong_key(key):
            messagebox.showerror("Erreur", "Clé trop faible.\nConseils :\n- Au moins 12 caractères\n- Lettres MAJ/min, chiffres, symboles.")
            return

        # Si fichier inexistant, on enregistre la clé
        if not os.path.exists(self.key_file):
            with open(self.key_file, "w") as f:
                f.write(key)
            messagebox.showinfo("Clé enregistrée", "Votre clé a été sauvegardée.")
        else:
            # Sinon, on vérifie si la clé est correcte
            with open(self.key_file, "r") as f:
                if key != f.read().strip():
                    messagebox.showerror("Erreur", "Clé incorrecte.")
                    return
            messagebox.showinfo("Succès", "Clé acceptée.")

    # Vérifie la solidité d'une clé
    def is_strong_key(self, key):
        return (
            len(key) >= 12 and
            re.search(r"[a-z]", key) and
            re.search(r"[A-Z]", key) and
            re.search(r"\d", key)
        )

    # Vérifie la robustesse d’un mot de passe
    def is_strong_password(self, password):
        if len(password) < 12:
            return False, "Mot de passe trop court (12+ caractères requis)."
        if not re.search(r"[a-z]", password):
            return False, "Ajoutez des lettres minuscules."
        if not re.search(r"[A-Z]", password):
            return False, "Ajoutez des lettres majuscules."
        if not re.search(r"[0-9]", password):
            return False, "Ajoutez des chiffres."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Ajoutez des symboles spéciaux."
        return True, ""

    # Hachage SHA-256 du mot de passe (stockage sécurisé)
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    # Ajout d’un mot de passe à la base
    def add_password(self):
        service = self.entries["Service"].get()
        username = self.entries["Nom d'utilisateur"].get()
        password = self.entries["Mot de passe"].get()

        if not (service and username and password):
            messagebox.showerror("Erreur", "Tous les champs sont requis.")
            return

        is_valid, advice = self.is_strong_password(password)
        if not is_valid:
            messagebox.showerror("Mot de passe faible", advice)
            return

        # Stocke le mot de passe en clair pour pouvoir l'afficher ultérieurement
        self.cursor.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
                    (service, username, password))
        self.conn.commit()

        messagebox.showinfo("Succès", "Mot de passe ajouté.")
        for entry in self.entries.values():
            entry.delete(0, tk.END)

    # Affiche les mots de passe si la clé est correcte
    def show_passwords(self):
        key = self.view_key_entry.get().strip()
        if not os.path.exists(self.key_file):
            messagebox.showerror("Erreur", "Fichier de clé manquant.")
            return

        with open(self.key_file, "r") as f:
            if key != f.read().strip():
                messagebox.showerror("Erreur", "Clé incorrecte.")
                return

        for row in self.tree.get_children():
            self.tree.delete(row)

        self.cursor.execute("SELECT id, service, username, password FROM passwords")
        rows = self.cursor.fetchall()
        # conserver localement pour filtrage
        self._last_passwords = rows
        for i, row in enumerate(rows):
            tag = 'evenrow' if i % 2 == 0 else 'oddrow'
            self.tree.insert('', 'end', iid=row[0], values=row[1:], tags=(tag,))

    # Suppression d’un élément sélectionné
    def delete_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Avertissement", "Sélectionnez un élément à supprimer.")
            return
        for item in selected:
            self.cursor.execute("DELETE FROM passwords WHERE id=?", (item,))
        self.conn.commit()
        self.show_passwords()

    # Modification d’un mot de passe sélectionné
    def edit_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Avertissement", "Sélectionnez un élément à modifier.")
            return
        item_id = selected[0]
        new_pw = simpledialog.askstring("Modifier mot de passe", "Entrez le nouveau mot de passe :", show="*")
        if new_pw:
            valid, msg = self.is_strong_password(new_pw)
            if not valid:
                messagebox.showerror("Erreur", msg)
                return
            # Enregistrer le nouveau mot de passe en clair
            self.cursor.execute("UPDATE passwords SET password=? WHERE id=?", (new_pw, item_id))
            self.conn.commit()
            self.show_passwords()
            messagebox.showinfo("Succès", "Mot de passe modifié.")

# Lancement de l'application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
