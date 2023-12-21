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
    # print (result)
    #<<<To use the output within the code>>>:
    return result 

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
    
    UUID = header["DOMAIN_UUID"] 
    # <<<function to grab version of the FMC virtual appliance>>>

    version_path = f"/api/fmc_platform/v1/info/serverversion"
    device_path = f"/api/fmc_config/v1/domain/{UUID}/devices/devicerecords?expanded=True"

    # <<<function to ensure session persistence>>>
    sess = requests.Session()
    sess.headers.update({'X-auth-access-token': header["X-auth-access-token"],
'X-auth-refresh-token': header["X-auth-refresh-token"]})
    try:
        resp1 = sess.get(f"https://{ip}/{version_path}", verify=False)
        resp2 = sess.get(f"https://{ip}/{device_path}", verify=False)
    except requests.exceptions.HTTPError as e:
        raise SystemExit(e)
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)

    try:
       print(json.dumps(resp1.json(), indent=2))
       print()
       print("*************")
       print()
       print(json.dumps(resp2.json(), indent=2))
    except Exception as e:
        raise SystemExit(e)



