import unittest
from unittest.mock import Mock, patch, call, ANY
from main import loginScreen

@patch("main.Tk")
def test_loginScreen(mock_Tk):
    mock_tk_instance = Mock()
    mock_label_instance = Mock()
    mock_entry_instance = Mock()
    mock_button_instance_1 = Mock()
    mock_button_instance_2 = Mock()

    mock_Tk.return_value = mock_tk_instance
    mock_tk_instance.Label.return_value = mock_label_instance
    mock_tk_instance.Entry.return_value = mock_entry_instance
    mock_tk_instance.Button.side_effect = [mock_button_instance_1, mock_button_instance_2]

    # Create an instance of LoginScreenFunction
    root_instance = mock_Tk.return_value
    login_screen_function = loginScreen(root_instance)

    # Assert the calls made during the setup_ui method
    root_instance.assert_has_calls([
        call.Label(root_instance, text="Password Manager", width=40, bg='lightblue', font='Ariel 14 bold', padx=10, pady=10),
        call.Label(root_instance, text='Enter Master Password', font='Ariel 13'),
        call.Entry(root_instance, width=30, show='*'),
        call.Button(root_instance, text='Submit', command=ANY),
        call.Button(root_instance, text='Reset Password', command=ANY),
    ], any_order=False)

if __name__ == '__main__':
    unittest.main()
