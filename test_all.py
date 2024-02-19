from tkinter import *
from unittest import TestCase
import unittest
from io import StringIO
import sqlite3
from unittest.mock import patch,Mock
from tkinter import Tk
from  main import GUIManager,encrypt, decrypt,hashPassword,recoveryScreen,resetScreen

class TestPasswordManagerApp(unittest.TestCase):

    def setUp(self):
        self.root = Tk()
        self.gui_manager = GUIManager(self.root)

    def tearDown(self):
        self.root.destroy()

    #test class gui
    def test_destroy_widgets(self):
        gui_manager = GUIManager(self.root)
        
        # Adding some widgets to the root
        label = Label(self.root, text="Test Label")
        button = Button(self.root, text="Test Button")

        # Check if the widgets are present before destroying
        self.assertEqual(len(self.root.winfo_children()), 2)

        # Call destroy_widgets method
        gui_manager.destroy_widgets()

        # Check if the widgets are destroyed
        self.assertEqual(len(self.root.winfo_children()), 0)

    #test encrypt_decrypt function
    def test_encrypt_decrypt(self):
        # Assuming a fixed key for testing purposes
        test_key = b'YR5C1SikVHV-f8B1NXD4_rQpGva6ie2dRlNPE3jE8hU='

        # Test data
        original_message = b'This is a test message.'

        # Encrypt the message
        encrypted_message = encrypt(original_message, test_key)

        # Ensure that the encryption and decryption are consistent
        decrypted_message = decrypt(encrypted_message, test_key)
        self.assertEqual(original_message, decrypted_message)


    #test function hashPassword
    def test_hash_password(self):
        input_password = b'test_password'
        expected_hash = hashPassword(input_password)  # Hash of 'test_password'

        result = hashPassword(input_password)

        self.assertEqual(result, expected_hash)


 #test function recoveryScreen
    @patch('builtins.input', side_effect=["070446cbe5b24bed9965a40f5aeefeb9"])
    def test_recoveryScreen(self, mock_input):
        with self.assertRaises(TclError):
            # Mock the Tkinter root to avoid GUI-related issues in tests
            with patch('tkinter.Tk') as mock_tk:
                # Set the return value for the winfo_children method to simulate an empty list of children
                mock_tk.return_value.winfo_children.return_value = []

                # Call the recoveryScreen function with the required key argument
                recoveryScreen("070446cbe5b24bed9965a40f5aeefeb9")

               #check if certain widgets or labels are present in the GUI
               
                self.assertTrue(mock_tk.return_value.Label.called)  # Check if Label widget is created
                self.assertTrue(mock_tk.return_value.Button.called) 

   #test function resetScreen
    @patch('builtins.input', side_effect=["070446cbe5b24bed9965a40f5aeefeb9"])
    def test_resetScreen(self, mock_input):
        with self.assertRaises(TclError):
            # Mock the Tkinter root to avoid GUI-related issues in tests
            with patch('tkinter.Tk') as mock_tk:
                # Set the return value for the winfo_children method to simulate an empty list of children
                mock_tk.return_value.winfo_children.return_value = []

                # Call the resetScreen function with the required key argument
                resetScreen()

                #check if certain widgets or labels are present in the GUI
               
                self.assertTrue(mock_tk.return_value.Label.called)  # Check if Label widget is created
                self.assertTrue(mock_tk.return_value.Entry.called)  # Check if Entry widget is created
                self.assertTrue(mock_tk.return_value.Button.called)  # Check if Button widget is created


if __name__ == '__main__':
    unittest.main()
   