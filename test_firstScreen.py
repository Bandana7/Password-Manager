
from tkinter import Tk
import unittest
from unittest.mock import patch
from main import firstScreen  # Import the standalone function

class TestFirstScreenFunction(unittest.TestCase):

    @patch("main.Tk")
    def test_firstScreen(self, mock_Tk):
        # Call the firstScreen method with a mock Tk instance
        firstScreen(mock_Tk.return_value)

        # Assert that the Tk instance was configured with the expected background color
        mock_Tk.return_value.configure.assert_called_once_with(bg="lightblue")


if __name__ == '__main__':
    unittest.main()

