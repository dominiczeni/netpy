#!/usr/bin/env python3

import os
from office365.sharepoint.client_context import ClientContext
from office365.runtime.auth.client_credential import ClientCredential
from office365.sharepoint.files.creation_information import FileCreationInformation

# Function to prompt the user and remove files if they choose to
def remove_files_from_output_directory(directory):
    user_input = input("Do you want to remove files from output directory (y/n - default y): ").strip().lower()
    
    if user_input in ['', 'y', 'yes']:
        for file_name in os.listdir(directory):
            file_path = os.path.join(directory, file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
                print(f"Removed file: {file_name}")
        print("All files have been removed from the output directory.")
    else:
        print("No files were removed.")

def upload_files():
    # Replace with your SharePoint site URL
    sharepoint_site_url = "https://lookingpoint.sharepoint.com/sites/lookingpoint"

    # Replace with your client ID and client secret
    client_id = ""
    client_secret = ""

    # Replace with the relative URL of the SharePoint folder
    # Hitachi DC Project Example:  /sites/lookingpoint/Shared Documents/Internal/Customers/Hitachi Vantara/Projects/1111 - Hitachi - Data Center Network Deployment/Engineering/output
    # sharepoint_folder_url = input("Enter the sharepoint relative folder URL:")
    customer_folder = input("Customer Folder Name:")
    sharepoint_folder_url = f"/sites/lookingpoint/Shared Documents/Internal/Service Delivery/OutputAutomation/{customer_folder}"

    # Replace with the path to the local directory you want to upload files from
    local_directory_path = "/app/files/output"

    # Create a ClientCredential object
    client_credentials = ClientCredential(client_id, client_secret)

    # Authenticate and create a ClientContext object
    ctx = ClientContext(sharepoint_site_url).with_credentials(client_credentials)

    # Get the SharePoint folder
    folder = ctx.web.get_folder_by_server_relative_url(sharepoint_folder_url)

    # Load the folder properties (to ensure it exists)
    ctx.load(folder)
    ctx.execute_query()
    # Iterate through all files in the local directory
    for file_name in os.listdir(local_directory_path):
        local_file_path = os.path.join(local_directory_path, file_name)
        
        # Check if the path is a file and not a subdirectory
        if os.path.isfile(local_file_path):
            with open(local_file_path, 'rb') as file_content:
                file_content_data = file_content.read()
                # Upload the file by passing the content directly
                upload_file = folder.files.add(file_name, file_content_data, overwrite=True)
                ctx.execute_query()
                print(f"File '{file_name}' has been uploaded to '{sharepoint_folder_url}' successfully.")

    print("All files have been uploaded successfully.")

    # Prompt to remove files from output directory
    remove_files_from_output_directory(local_directory_path)

if __name__ == "__main__":
    upload_files()
