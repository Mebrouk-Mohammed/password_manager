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
        # Création d'un système d'onglets
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill="both", expand=True)

        # Ajout des différents onglets
        self.setup_key_tab()
        self.setup_add_tab()
        self.setup_manage_tab()

    # Onglet pour entrer la clé maître
    def setup_key_tab(self):
        frame = tk.Frame(self.notebook, bg="#f0f4f8")
        self.notebook.add(frame, text="Clé")

        label = tk.Label(frame, text="Entrez votre clé principale :", font=("Arial", 12), bg="#f0f4f8")
        label.pack(pady=10)

        self.key_entry = tk.Entry(frame, show="*", width=30, font=("Arial", 12))  # Zone pour entrer la clé
        self.key_entry.pack(pady=5)

        # Bouton pour afficher/cacher la clé
        btn_show = tk.Button(frame, text="👁", command=self.toggle_key_visibility)
        btn_show.pack()

        # Bouton pour générer une clé forte automatiquement
        gen_btn = tk.Button(frame, text="Générer clé forte", command=self.generate_strong_key, bg="#007acc", fg="white")
        gen_btn.pack(pady=5)

        # Bouton de validation de la clé
        valid_btn = tk.Button(frame, text="Valider", command=self.validate_key, bg="#2e7d32", fg="white")
        valid_btn.pack(pady=10)

        # Recommandations pour la clé forte
        self.key_advice = tk.Label(frame, text="- 12+ caractères\n- Majuscules, minuscules, chiffres, symboles",
                                   font=("Arial", 10), bg="#f0f4f8")
        self.key_advice.pack(pady=10)

    # Onglet pour ajouter un nouveau mot de passe
    def setup_add_tab(self):
        frame = tk.Frame(self.notebook, bg="#f0f4f8")
        self.notebook.add(frame, text="Ajouter")

        self.entries = {}
        for label_text in ["Service", "Nom d'utilisateur", "Mot de passe"]:
            label = tk.Label(frame, text=label_text + " :", font=("Arial", 12), bg="#f0f4f8")
            label.pack(pady=5)
            entry = tk.Entry(frame, font=("Arial", 12), show="*" if label_text == "Mot de passe" else "")
            entry.pack(pady=5)
            self.entries[label_text] = entry

        # Bouton pour afficher/cacher le mot de passe
        show_pw_btn = tk.Button(frame, text="👁", command=self.toggle_password_visibility)
        show_pw_btn.pack()

        # Bouton de génération de mot de passe
        gen_btn = tk.Button(frame, text="Générer mot de passe fort", command=self.generate_password,
                            bg="#007acc", fg="white")
        gen_btn.pack(pady=5)

        # Bouton pour enregistrer le mot de passe
        add_btn = tk.Button(frame, text="Ajouter", command=self.add_password, bg="#2e7d32", fg="white")
        add_btn.pack(pady=10)

    # Onglet de gestion (affichage, suppression, modification)
    def setup_manage_tab(self):
        frame = tk.Frame(self.notebook, bg="#f0f4f8")
        self.notebook.add(frame, text="Gérer")

        label = tk.Label(frame, text="Clé pour afficher les mots de passe :", font=("Arial", 12), bg="#f0f4f8")
        label.pack(pady=5)

        self.view_key_entry = tk.Entry(frame, show="*", font=("Arial", 12))
        self.view_key_entry.pack()

        # Bouton pour afficher les mots de passe
        unlock_btn = tk.Button(frame, text="Afficher", command=self.show_passwords, bg="#2e7d32", fg="white")
        unlock_btn.pack(pady=10)

        # Tableau pour afficher les données
        self.tree = ttk.Treeview(frame, columns=("Service", "Nom d'utilisateur", "Mot de passe"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200)
        self.tree.pack(pady=10)

        # Boutons pour modifier ou supprimer un enregistrement
        btn_frame = tk.Frame(frame, bg="#f0f4f8")
        btn_frame.pack()

        del_btn = tk.Button(btn_frame, text="Supprimer", command=self.delete_selected, bg="#d32f2f", fg="white")
        del_btn.pack(side="left", padx=10)

        edit_btn = tk.Button(btn_frame, text="Modifier", command=self.edit_selected, bg="#ffa000", fg="white")
        edit_btn.pack(side="left", padx=10)

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

        hashed = self.hash_password(password)
        self.cursor.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
                            (service, username, hashed))
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
        for row in self.cursor.fetchall():
            self.tree.insert('', 'end', iid=row[0], values=row[1:])

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
            hashed = self.hash_password(new_pw)
            self.cursor.execute("UPDATE passwords SET password=? WHERE id=?", (hashed, item_id))
            self.conn.commit()
            self.show_passwords()
            messagebox.showinfo("Succès", "Mot de passe modifié.")

# Lancement de l'application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
