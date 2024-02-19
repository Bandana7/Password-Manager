import unittest
from tkinter import *
import sqlite3
from main import passwordManager, GUIManager

class TestNonGUILogic(unittest.TestCase):

    def setUp(self):
        # Set up a testing database
        self.test_db = sqlite3.connect(":memory:")
        self.cursor = self.test_db.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS masterpassword(
                id INTEGER PRIMARY KEY,
                password TEXT NOT NULL,
                recoveryKey TEXT NOT NULL
            );
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault(
                id INTEGER PRIMARY KEY,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            );
        """)
        # Insert test data
        self.cursor.execute("INSERT INTO masterpassword VALUES (1, 'hashed_password', 'recovery_key')")
        self.test_db.commit()

    def tearDown(self):
        # Clean up
        self.test_db.close()

def test_passwordManager(self):
    # Set up the environment to test passwordManager
    gui_manager = GUIManager(Tk())  # Create a Tk instance here
    gui_manager.encryption_key = b'1234567890123456'
    
    # Set up the GUI state before calling passwordManager
    gui_manager.root = Tk()
    gui_manager.root.title("Password Manager")
    gui_manager.root.geometry("800x500")
    gui_manager.root.configure(bg="lightblue")

    # Call passwordManager method on the GUIManager instance
    gui_manager.passwordManager()

    # Assert that the GUI is in the expected state after calling passwordManager
    widgets = gui_manager.root.winfo_children()
    self.assertEqual(len(widgets), 6)  # Assuming there are 6 widgets (labels, entry, buttons) in the password manager screen

    # You can further check other aspects of the GUI state if needed


if __name__ == '__main__':
    unittest.main()
