from asyncio import open_connection
from multiprocessing import connection
import os,time,hashlib,wmi,pythoncom
from subprocess import check_output, CalledProcessError
from dB_init import create_server_connection, read_query
# hash of a sample malicous file
# hash_object = hashlib.md5(b'I am malicious.')
# hex_dig = hash_object.hexdigest()
# maliciousHash = hash_object.hexdigest()
def connect_to_dB():
    return create_server_connection("localhost", "root", "", "security_project")

# calculating SHA-256 of file
def hash_file(filePath):
    f = open(filePath, "rb")
    bytes = f.read()
    return hashlib.md5(bytes).hexdigest()

# iterate over files and files inside folders in the flash drive
def detectUsbDrive (directory,connection):
    for path, subdirs, files in os.walk(directory):
        for name in files:
            f = os.path.join(path, name)
            # checking if it is a file
            if os.path.isfile(f):
                result = read_query(connection, "SELECT hash_id FROM virus_hashes WHERE hash = '{}'".format(hash_file(f)))
                if result:
                    print("Malicous File Found")
                    # deleting malicious file
                    os.remove(f)
                    print("Removing malicious file...")
                    time.sleep(1)
                    print("Malicous file removed.")
                    return
    print("USB drive is safe.")
    
# if __name__ == "__main__":
def program():
    connection = connect_to_dB()
    pythoncom.CoInitialize()
    c = wmi.WMI()
    list = [] 
    while True:   
        # checking inserted flash drives
        for disk in c.Win32_LogicalDisk():
            if disk.Description == 'Removable Disk' and not (list.count(disk.DeviceID)) :
                # print(list)
                list.append(disk.DeviceID)
                detectUsbDrive('{}\\'.format(disk.DeviceID), connection)

        # checking if the flash drives got ejected
        for i in range (len(list)) :
            found = 0 
            for disk in c.Win32_LogicalDisk():
                if disk.Description == 'Removable Disk' and list[i] == disk.DeviceID :
                    found = 1 
                    break
            if (not found):
                list.remove(list[i])