import os,time,hashlib,wmi
from subprocess import check_output, CalledProcessError

# hash of a sample malicous file
hash_object = hashlib.sha256(b'I am malicious.')
hex_dig = hash_object.hexdigest()
maliciousHash = hash_object.hexdigest()



c = wmi.WMI()

# calculating SHA-256 of file
def hash_file(filePath):
    with open(filePath,"rb") as f:
        bytes = f.read() 
    return hashlib.sha256(bytes).hexdigest()

# iterate over files and files inside folders in the flash drive
def detectUsbDrive (directory):
    for path, subdirs, files in os.walk(directory):
        for name in files:
            f = os.path.join(path, name)
            # checking if it is a file
            if os.path.isfile(f):
                if hash_file(f) == maliciousHash:
                    print("Malicous File Found")
                    # deleting malicious file
                    os.remove(f)
                    print("Removing malicious file...")
                    time.sleep(1)
                    print("Malicous file removed.")
                    return
    print("USB drive is safe.")


list = [] 
while True:   
    # checking inserted flash drives
    for disk in c.Win32_LogicalDisk():
        if disk.Description == 'Removable Disk' and not (list.count(disk.DeviceID)) :
            # print(list)
            list.append(disk.DeviceID)
            detectUsbDrive('{}\\'.format(disk.DeviceID))

    # checking if the flash drives got ejected
    for i in range (len(list)) :
        found = 0 
        for disk in c.Win32_LogicalDisk():
            if disk.Description == 'Removable Disk' and list[i] == disk.DeviceID :
                found = 1 
                break
        if (not found):
            list.remove(list[i])
