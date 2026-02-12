import argparse

class PARSERS:

#cmd2 settings parsers
    def interact_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('device', action="store", help="Device ResourceID you want to interact with.")
        return parser
    
    def cd_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('path', action="store", help="path to change directories to. Ex: C:\\Users\\")
        return parser



#database parsers
    def get_device_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('device', action="store", help="Query for device information")
        return parser
    
    def get_user_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('user', action="store", help="Query for user information")
        return parser
    
    def get_collection_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('collection_id', action="store", help="Query for collection information. Use a '*' to list all collections.")
        return parser

    def get_collection_members_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('collection_id', action="store", help="Query for all members of a collection.")
        return parser

    def get_puser_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('user', action="store", help="Find devices the target user is a primary user of.")
        return parser        

    def get_lastlogon_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('user', action="store", help="Find devices the target user recently logged into.")
        return parser    
    
    
    #Application Parser
    
    def application_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('-t', '--target', action='store', help="ResourceID to target for application deployment")
        parser.add_argument('-c', '--collection-type', action='store', help='Collection type to create for application deployment', choices=['user', 'device'])
        parser.add_argument('-p', '--path', action="store", help='Command or UNC path of the binary/script to execute. Ex: \\\\10.10.10.10\\payload.exe')
        parser.add_argument('-s', '--system', action="store_true", help='Run the application as NT AUTHORITY\\SYSTEM', default=False)
        parser.add_argument('-n', '--name', action="store", help="Name of the application")
        parser.add_argument("--collection-id", action="store", help="Id of existing collection to target")
        return parser
    
    #Powershell Script Parsers
    def cat_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('filename', action="store", help="Filename to display contents for.")
        return parser    
    
    def script_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('script', action="store", help="Script name or path to script")
        return parser    

    
    def delete_script_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('script_guid', action="store", help="GUID of target script to delete. Use list_scripts to get the GUID.")
        return parser    
    
    def get_script_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('script_guid', action="store", help="GUID of target script to view.")
        return parser   
    
    
    # cmpivot parsers
    def do_sessionhunter_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('user', action="store", help="Target user to find sessions for")
        return parser
    
    
    #add admin parsers
    def do_add_admin_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('-u', '--user', action='store', help='Target username to add as an admin', required=True)
        parser.add_argument('-s', '--sid', action='store', help="Target user's sid to add as an admin ", required=True)
        return parser
    
    def do_delete_admin_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('user', action='store', help="Target admin username to remove")
        return parser
    
# creds extraction


    def do_decrypt_parsers():
        parser = argparse.ArgumentParser()
        parser.add_argument('blob', action='store', help="Encrypted blob to decrypt")
    