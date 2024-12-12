import requests
import os
import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printc

class VirusExchangeExtractor:
    def __init__(self, api_key):
        self.VXAPI = api_key
        self.base_url = "https://virus.exchange/api"

    def _requireVXAPI(self):
        if (self.VXAPI == ''):
            printc("\nTo be able to get/submit information from/to Virus Exchange, you must create the .malwapi.conf file under your user home directory (on Linux is $HOME\\.malwapi.conf and on Windows is in C:\\Users\\[username]\\.malwapi.conf) and insert the Virus Exchange API according to the format shown on the Github website.", mycolors.foreground.error(cv.bkg))
            exit(1)

    def _get_hash_metadata(self, sha256):
        url = f'{self.base_url}/samples/{sha256}'
        response = requests.get(url, headers={'Authorization': f'Bearer {self.VXAPI}'})
        return response

    def check_hash(self, sha256):
        self._requireVXAPI()

        metadata_to_show = [
            {"key": "md5", "name": "MD5", "colors": (mycolors.foreground.cyan, mycolors.foreground.lightcyan), "pad": 12},
            {"key": "sha1", "name": "SHA1", "colors": (mycolors.foreground.cyan, mycolors.foreground.lightcyan), "pad": 12},
            {"key": "sha256", "name": "SHA256", "colors": (mycolors.foreground.cyan, mycolors.foreground.lightcyan), "pad": 12},
            {"key": "size", "name": "Size", "colors": (mycolors.foreground.purple, mycolors.foreground.yellow), "pad": 12},
            {
                "key": "tags", "name": "Tags",
                "colors": (mycolors.foreground.purple, mycolors.foreground.yellow), "pad": 12,
                "fn": lambda x: ', '.join(x) if hasattr(x, '__iter__') else ""
            },
            {"key": "type", "name": "Type", "colors": (mycolors.foreground.purple, mycolors.foreground.yellow), "pad": 12},
            {"key": "first_seen", "name": "First Seen", "colors": (mycolors.foreground.purple, mycolors.foreground.yellow), "pad": 12}
        ]

        try:
            response = self._get_hash_metadata(sha256)
        except Exception as e:
            printc(f"[-] Error checking hash metadata: {str(e)}", mycolors.foreground.error(cv.bkg))
            return

        metadata = response.json()

        print()
        for val in metadata_to_show:
            key = val['key']
            color = val["colors"][cv.bkg]
            name = val['name']
            pad = val['pad']
            fn = val.get('fn', None)

            if key in metadata:
                printc(f'{name}:'.ljust(pad), color, end='')

                val_to_print = metadata[key]
                if fn is not None:
                    val_to_print = fn(metadata[key])

                print(f'{val_to_print}')

    def download_sample(self, sha256):
        self._requireVXAPI()

        try:
            response = self._get_hash_metadata(sha256)
            metadata = response.json()

            if response.status_code == 200:
                download_link = metadata.get('download_link')
                if download_link:
                    # Download the actual sample
                    sample_response = requests.get(download_link)
                    if sample_response.status_code == 200:
                        output_path = os.path.join(cv.output_dir, sha256)
                        with open(output_path, 'wb') as f:
                            f.write(sample_response.content)
                        printc(f"Sample downloaded to: {output_path}", mycolors.foreground.success(cv.bkg))
                    else:
                        printc(f"Failed to download sample: {sample_response.status_code}", mycolors.foreground.error(cv.bkg))
                else:
                    printc("No download link available in metadata", mycolors.foreground.error(cv.bkg))
            else:
                error_detail = metadata.get('errors', {}).get('detail', 'Unknown error')
                printc(f"Failed to fetch sample metadata: {error_detail}", mycolors.foreground.error(cv.bkg))
        except Exception as e:
            printc(f"Error downloading sample: {str(e)}", mycolors.foreground.error(cv.bkg))

    # This method is currently shown in the docs, but it's always returning 401
    # so it was removed from the official options.
    def upload_sample(self, file_path):
        self._requireVXAPI()

        url = f'{self.base_url}/samples/new'
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(url, headers={'Authorization': f'Bearer {self.VXAPI}'}, files=files)
                
            if response.status_code == 200:
                printc("Sample uploaded successfully", mycolors.foreground.success(cv.bkg))
            else:
                printc(f"Failed to upload sample: {response.status_code}", mycolors.foreground.error(cv.bkg))
        except Exception as e:
            printc(f"Error uploading sample: {str(e)}", mycolors.foreground.error(cv.bkg))