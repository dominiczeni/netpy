#!/usr/bin/env python3
import csv
import sys
import os


# Reads the CSV File and returns a list which will be using to create the yaml file

class Csv2NornirSimple:

    def __init__(self, filename):
        self.filename = filename
        self.inventory_data = []

    def inventory_converter(self):
        inventory_list = []
        # Currently not in use 
        core_field = ["name", "hostname", "platform", "port", "username", "password"]
        try:
            with open(self.filename) as csv_file:
                csv_reader = csv.DictReader(csv_file)
                for row in csv_reader:
                    # Check if jumpbox field exists in the CSV
                    jumpbox = row.get("jumpbox", "")
                    
                    inventory_list.append([
                        row["name"],
                        row["hostname"],
                        row["platform"],
                        row["port"],
                        row["username"],
                        row["password"],
                        row["site"],
                        row["function"],
                        row["commands"],
                        jumpbox
                        ])
                self.inventory_data = inventory_list
        except FileNotFoundError:
            print(f"Please make sure that {self.filename} is correct and exists...")
            sys.exit(1)


    # Iterates over the list and creates the csv_inventory.yaml based on the Nornir model

    def make_nornir_inventory(self):
        if len(self.inventory_data) < 1:
            print("The list argument doesn't have any records! Cannot create an inventory file out of an empty list!")
            return ValueError
        try:

            with open("/app/files/nornir_inventory.yaml", "w") as out_file:
                out_file.write("---\n")
                for host in self.inventory_data:
                    out_file.write(f"{host[0]}:\n")
                    out_file.write(f"  hostname: {host[1]}\n")
                    out_file.write(f"  platform: {host[2]}\n")
                    out_file.write(f"  port: {host[3]}\n")
                    out_file.write(f"  username: {host[4]}\n")
                    out_file.write(f"  password: {host[5]}\n")
                    out_file.write(f"  data:\n")
                    out_file.write(f"    site: {host[6]}\n")
                    out_file.write(f"    function: {host[7]}\n")
                    out_file.write(f"    commands: {host[8]}\n")
                    
                    # Add jumpbox configuration if provided
                    if host[9]:
                        out_file.write(f"    jumpbox: {host[9]}\n")
                    
                    out_file.write("\n")
                
                print("Inventory file created...")
        except PermissionError:
            print("An error occurred whilst trying to write into the file... Please make sure that there are enough permission assigned to the user executing the script...")
            sys.exit(1)

def list_csv_files(directory):
    # Get all files in the directory
    all_files = os.listdir(directory)
    
    # Filter for CSV files
    csv_files = [f for f in all_files if f.lower().endswith('.csv')]
    
    return csv_files

def makefile():
    directory = '/app/files/'
    csv_files = list_csv_files(directory)
    if not csv_files:
        print("No CSV files found in the directory.")
        return

    for i, file in enumerate(csv_files, 1):
        print(f"{i}. {file}")
    csv_inventory_file = "" 
    while True:
            try:
                selection = int(input("Please select the number of the CSV file you want: "))
                if 1 <= selection <= len(csv_files):
                    csv_inventory_file = f"/app/files/{csv_files[selection - 1]}"
                    print(f"You selected: {csv_files[selection - 1]}")
                    break
                else:
                    print("Invalid selection. Please enter a number from the list.")
            except ValueError:
                print("Invalid input. Please enter a number.")
    #csv_inventory_file = "/app/files/" + input("Enter the name of the csv inventory file to convert to nornir yaml inventory: ")
    c2n = Csv2NornirSimple(csv_inventory_file)
    inventory_list = c2n.inventory_converter()
    c2n.make_nornir_inventory()


if __name__ == "__main__":
    makefile()
