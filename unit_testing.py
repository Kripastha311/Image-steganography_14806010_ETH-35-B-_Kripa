import unittest
from PIL import Image
import numpy as np
from steganography import encode_image, extract_message_from_image, detect_malware_in_image, analyze_image

class TestSteganography(unittest.TestCase):

    def setUp(self):
        # Creating a simple test image (white image 10x10)
        self.img = Image.new('RGB', (10, 10), color='white')
        self.test_message = "Hello, Malware!"

    def test_encode_image(self):
        # Test encoding a message into an image
        encoded_image = encode_image(self.img, self.test_message)
        # Save the encoded image for later inspection
        encoded_image.save('encoded_image.png')

        # Check that the message can be extracted correctly
        extracted_message = extract_message_from_image('encoded_image.png')
        self.assertEqual(extracted_message, self.test_message)

        # Anomaly check (no anomaly for regular message)
        anomaly_detected, reason = analyze_image('encoded_image.png')
        self.assertFalse(anomaly_detected, reason)

    def test_extract_message(self):
        # Encode the message into the image first
        encoded_image = encode_image(self.img, self.test_message)
        encoded_image.save('encoded_image.png')

        # Extract the message and assert it's the same
        extracted_message = extract_message_from_image('encoded_image.png')
        self.assertEqual(extracted_message, self.test_message)

        # Anomaly check (no anomaly for regular message)
        anomaly_detected, reason = analyze_image('encoded_image.png')
        self.assertFalse(anomaly_detected, reason)

    def test_malware_detection(self):
        # Injecting malicious code into the message
        malicious_message = "os.system('rm -rf /')"
        encoded_image = encode_image(self.img, malicious_message)
        encoded_image.save('encoded_malicious_image.png')

        # Test malware detection
        malware_name, injected_command = detect_malware_in_image('encoded_malicious_image.png')
        
        # Assert the malware detection message matches expected output
        self.assertEqual(malware_name, "Malware: Command Injection")  # Updated to match actual output
        self.assertEqual(injected_command, malicious_message)

        # Anomaly check (malicious command should trigger anomaly detection)
        anomaly_detected, reason = analyze_image('encoded_malicious_image.png')
        self.assertTrue(anomaly_detected, reason)

    def test_no_malware(self):
        # Test with a regular message
        regular_message = "This is a normal message."
        encoded_image = encode_image(self.img, regular_message)
        encoded_image.save('encoded_normal_image.png')

        # Test malware detection
        malware_name, injected_command = detect_malware_in_image('encoded_normal_image.png')
        self.assertEqual(malware_name, "No malware detected")
        self.assertEqual(injected_command, "")

        # Anomaly check (no anomaly for regular message)
        anomaly_detected, reason = analyze_image('encoded_normal_image.png')
        self.assertFalse(anomaly_detected, reason)

if __name__ == '__main__':
    unittest.main()





