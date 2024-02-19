from unittest import TestCase
import unittest
from unittest.mock import patch, MagicMock
from main import popUp

def test_popUp(TestCase):

    @patch('main.Toplevel', return_value=MagicMock())
    @patch('main.Entry', return_value=MagicMock())
    @patch('main.Label', return_value=MagicMock())
    @patch('main.Button', return_value=MagicMock())
    def test_popUp_text_entry(self, mock_button, mock_label, mock_entry, mock_toplevel):
        mock_entry_instance = MagicMock()
        mock_entry_instance.get.return_value = 'Test Input'
        mock_entry.return_value = mock_entry_instance

        with patch('builtins.input', return_value='Test Input'):
            result = popUp('Enter some text:')

        mock_toplevel.assert_called_once()
        mock_label.assert_called_once_with(mock_toplevel.return_value, text='Enter some text:')
        mock_entry.assert_called_once()
        mock_button.assert_called_once_with(mock_toplevel.return_value, text='Save', command=mock_toplevel.return_value.destroy)
        mock_entry_instance.get.assert_called_once()

        self.assertEqual(result, 'Test Input')

    @patch('main.Toplevel', return_value=MagicMock())
    @patch('main.Entry', return_value=MagicMock())
    @patch('main.Label', return_value=MagicMock())
    @patch('main.Button', return_value=MagicMock())
    def test_popUp_password_entry(self, mock_button, mock_label, mock_entry, mock_toplevel):
        mock_entry_instance = MagicMock()
        mock_entry_instance.get.return_value = 'Test Password'
        mock_entry.return_value = mock_entry_instance

        with patch('builtins.input', return_value='Test Password'):
            result = popUp('Enter a password:', is_password=True)

        mock_toplevel.assert_called_once()
        mock_label.assert_called_once_with(mock_toplevel.return_value, text='Enter a password:')
        mock_entry.assert_called_once()
        mock_button.assert_called_once_with(mock_toplevel.return_value, text='Save', command=mock_toplevel.return_value.destroy)
        mock_entry_instance.get.assert_called_once()

        self.assertEqual(result, 'Test Password')

if __name__ == '__main__':
    unittest.main()