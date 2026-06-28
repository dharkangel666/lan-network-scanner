import unittest
from unittest.mock import patch

from scanner.desktop_notify import notify_available, send_desktop_notification


class DesktopNotifyTests(unittest.TestCase):
    @patch("scanner.desktop_notify.shutil.which", return_value=None)
    def test_unavailable_without_notify_send(self, _which: object) -> None:
        self.assertFalse(notify_available())
        result = send_desktop_notification("Title", "Body")
        self.assertFalse(result["sent"])
        self.assertIn("notify-send", result["error"])

    @patch("scanner.desktop_notify.subprocess.run")
    @patch("scanner.desktop_notify.shutil.which", return_value="/usr/bin/notify-send")
    def test_sends_notification(self, _which: object, run: object) -> None:
        result = send_desktop_notification("New device", "192.168.1.50 joined")
        self.assertTrue(result["sent"])


if __name__ == "__main__":
    unittest.main()
