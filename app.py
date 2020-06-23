import os
import json
import logging
import requests
import time
import hmac
import hashlib
import base64
import urllib.parse
from urllib.parse import urlparse

from flask import Flask
from flask import request

app = Flask(__name__)

logging.basicConfig(
    level=logging.DEBUG if os.getenv('LOG_LEVEL') == 'debug' else logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s')


@app.route('/', methods=['POST', 'GET'])
def send():
    if request.method == 'POST':
        post_data = request.get_data()
        app.logger.debug(post_data)
        send_alert(json.loads(post_data))
        return 'success'
    else:
        return 'weclome to use prometheus alertmanager dingtalk webhook server!'


def send_alert(data):
    token = os.getenv('ROBOT_TOKEN')
    secret = os.getenv('ROBOT_SECRET')
    if not token:
        app.logger.error('you must set ROBOT_TOKEN env')
        return
    if not secret:
        app.logger.error('you must set ROBOT_SECRET env')
        return
    timestamp = int(round(time.time() * 1000))
    url = 'https://oapi.dingtalk.com/robot/send?access_token=%s&timestamp=%d&sign=%s' % (token, timestamp, make_sign(timestamp, secret))

    try:
        for alert in data["alerts"]:
            if "description" in alert["annotations"]:
                msg = "description"
            elif "message" in alert["annotations"]:
                msg = "message"
            else:
                msg = "summary"

            title = "[k8s][{cluster}] {status}".format(
                            cluster=alert["labels"]["cluster"],
                            status=alert["status"].upper()
                        )
            text = "[k8s][{cluster}] {status} \
                        \n >Severity: {severity} \
                        \n Name: {alertname} \
                        \n Details: {annotations} \
                        \n StartsAt: {startsAt} \
                        \n [查看详细信息]({external_url})".format(
                            cluster=alert["labels"]["cluster"],
                            status=alert["status"].upper(),
                            severity=alert["labels"]["severity"].upper(),
                            alertname=alert["labels"]['alertname'],
                            annotations=alert["annotations"][msg],
                            startsAt=alert["startsAt"].split('.')[0].replace('T', ' '),
                            external_url=alert["generatorURL"]
                        )

            playload = {
                "msgtype": "markdown",
                "markdown": {
                    "title": title,
                    "text": text 
                },
            }
            req = requests.post(url, json=playload)
            result = req.json()
            if result['errcode'] != 0:
                app.logger.error('notify dingtalk error: %s' % result['errcode'])
    except:
        logging.error("send failed")
        logging.error(traceback.format_exc())


def make_sign(timestamp, secret):
    """新版钉钉更新了安全策略，这里我们采用签名的方式进行安全认证
    https://ding-doc.dingtalk.com/doc#/serverapi2/qf2nxq
    """
    secret_enc = bytes(secret, 'utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = bytes(string_to_sign, 'utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    return sign


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)