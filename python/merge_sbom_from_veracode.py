
import sys,os,requests,shutil,json,subprocess,datetime
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC as get_veracode_hamc

sboms_folder = "./sboms"
today = datetime.date.today()
output_sbom_file = "tx-gov.sbom-" + today.strftime("%Y-%m-%d") + ".json"
cyclonedx_url = "https://github.com/CycloneDX/cyclonedx-cli/releases/latest/download/cyclonedx-win-x64.exe"
cyclone_filename = "cyclonedx.exe"
api_base = "https://api.veracode.com/appsec/v1"
sbom_base = "https://api.veracode.com/srcclr/sbom/v1/targets"

def setup():
    if not os.path.exists(sboms_folder):
        os.makedirs(sboms_folder)
    download_cyclonedx()

def download_cyclonedx():
    try:
        response = requests.get(cyclonedx_url)
    except requests.RequestException as e:
        print(e)
        sys.exit(1)
    with open(cyclone_filename, mode="wb") as file:
        file.write(response.content)

def get_veracode_applications():
    try:
        response = requests.get(api_base + "/applications", auth=get_veracode_hamc(), headers={})
        return response
    except requests.RequestException as e:
        print(e)
        sys.exit(1)

def get_veracode_sbom(application_guid):
    try:
        response = requests.get(sbom_base + "/" + application_guid + "/cyclonedx?type=application", auth=get_veracode_hamc(), headers={})
        return response
    except requests.RequestException as e:
        print(e)
        sys.exit(1)
    
def save_sbom_to_file(sbom, index):
    sbom_name = 'sbom' + str(index) +'.json'
    with open('./sboms/'+ sbom_name, 'w') as file:
        file.write(json.dumps(sbom))
    return sbom_name

def merge_sboms(sboms_folder, output_file, sbom_names):
    args = ['cyclonedx.exe', 'merge', '--input-format', 'json', '--input-files']
    for sbom in sbom_names:
        args.append(sboms_folder+'/'+sbom)
    args.extend(['--output-file', output_file, '--output-format', 'json'])
    result = subprocess.run(args, capture_output=True, text=True)
    print(result.stderr)

def cleanup():
    if os.path.exists(sboms_folder):
        shutil.rmtree(sboms_folder)
    if os.path.exists(cyclone_filename):
        os.remove(cyclone_filename)

if __name__ == "__main__":
    setup()
    applications_response = get_veracode_applications()
    sbom_names = []
    if not applications_response.ok:
        print(applications_response.status_code)
        print(applications_response.json())
        sys.exit(1)

    data = applications_response.json()
    for index, application in enumerate(data["_embedded"]["applications"]):
        sbom_response = get_veracode_sbom(application['guid'])
        if sbom_response.ok:
            print(application["profile"]["name"])
            sbom_names.append(save_sbom_to_file(sbom_response.json(),index))
    merge_sboms(sboms_folder,output_sbom_file,sbom_names)
    cleanup()

