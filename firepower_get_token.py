import argparse
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    #1 <<<function to grab the token from the FMC device>>>
def get_token(fmcIP, path, user, password):
    try:
        r = requests.post(f"https://{fmcIP}/{path}", auth=(f"{user}",
            f"{password}"), verify=False)
    except requests.exceptions.HTTPError as e:
        raise SystemExit(e)
    except requests.exceptions.RequestException as e:
         raise SystemExit(e)
    required_headers = ('X-auth-access-token', 'X-auth-refresh-token',
'DOMAIN_UUID')
    result = {key: r.headers.get(key) for key in required_headers}
    print (result)
    
    # #<<< TO get Access Token>>> 
    # print (result['X-auth-access-token'])

    # #<<< TO get Refresh Token>>> 
    # print (result['X-auth-refresh-token'])

    # #<<< TO get DOMAIN ID (always the same)>>> 
    # print (result['DOMAIN_UUID'])
    
    # #<<<To use the output within the code>>>:
    # return result 

    #<<<arg perser section used to decide what arguments to use when running the python scripts>>>
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("user", type=str, help ="Valid FMC Username")
    parser.add_argument("password", type=str, help="Valid FMC Password")
    parser.add_argument("ip_address", type=str, help="IP of FMC")
    args = parser.parse_args()
    user = args.user
    password = args.password
    ip = args.ip_address
    token_path = "/api/fmc_platform/v1/auth/generatetoken"

    header = get_token(ip, token_path, user, password)

    
     
