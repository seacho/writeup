def read_file_hex(file_path):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

            hex_data = ''.join([f'\\x{byte:02x}' for byte in data])
            print(hex_data)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    file_path = input("Enter the path to the file: ").strip()
    read_file_hex(file_path)
