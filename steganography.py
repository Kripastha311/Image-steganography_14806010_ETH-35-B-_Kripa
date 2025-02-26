from PIL import Image
import numpy as np
import subprocess

# Convert text to binary
def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

# Convert binary to text
def binary_to_text(binary):
    text = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        text += chr(int(byte, 2))
    return text

# Function to embed a message in an image
def encode_image(img, message):
    binary_message = text_to_binary(message) + '1111111111111110'  # End delimiter
    pixels = np.array(img)
    
    if pixels.shape[-1] == 4:
        pixels = pixels[:, :, :3]  # Only consider RGB channels
    
    flat_pixels = pixels.flatten()
    
    if len(binary_message) > len(flat_pixels):
        raise ValueError("Message is too large for this image.")
    
    # Embed the message in the LSB of the image
    for i, bit in enumerate(binary_message):
        flat_pixels[i] = (flat_pixels[i] & 0b11111110) | int(bit)
    
    return Image.fromarray(flat_pixels.reshape(pixels.shape), 'RGB')

# Function to extract the hidden message from an image
def extract_message_from_image(img_path):
    img = Image.open(img_path)
    pixels = np.array(img)
    flat_pixels = pixels.flatten()
    
    # Extract the LSBs from the image
    binary_payload = ''.join(str(pixel & 1) for pixel in flat_pixels)
    
    # Find the delimiter to know where the payload ends
    delimiter = '1111111111111110'
    delimiter_index = binary_payload.find(delimiter)
    
    if delimiter_index != -1:
        binary_payload = binary_payload[:delimiter_index]  # Get the binary payload
        return binary_to_text(binary_payload)  # Convert back to string
    else:
        return "No message found."

# Function to detect malware inside a hidden message
def detect_malware(img_path):
    extracted_message = extract_message_from_image(img_path)
    
    if "os.system" in extracted_message:
        return "Malware detected: Command Injection", extracted_message
    elif "eval" in extracted_message:
        return "Malware detected: Eval Injection", extracted_message
    else:
        return "No malware detected", ""

# Function to analyze image metadata using ExifTool
def analyze_metadata(img_path):
    try:
        result = subprocess.run(["exiftool", img_path], capture_output=True, text=True)
        metadata = result.stdout if result.returncode == 0 else "Failed to retrieve metadata."
    except FileNotFoundError:
        metadata = "ExifTool not installed. Please install it using: sudo apt install libimage-exiftool-perl"
    
    return metadata

