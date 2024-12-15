import streamlit as st
from streamlit import query_params as qp
import aiohttp
import asyncio
import re
import time
import requests
import json

st.info("use your dummy account :)")

class Share:
    def __init__(self, cookie):
        self.cookie = cookie
        self.head = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': "Windows",
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'cookie': cookie
        }
        self.share_count_viewer = 0

    async def get_token(self, session):
        try:
            async with session.get('https://business.facebook.com/content_management', headers=self.head) as response:
                data = await response.text()
                access_token = 'EAAG' + re.search('EAAG(.*?)","', data).group(1)
                return access_token
        except Exception as er:
            st.session_state.error_message = ":red-background[blocked] Cookie blocked"
            return None

    async def share(self, session, token, post, share_count, delay):
            ji = self.head.copy()
            ji["accept-encoding"] = "gzip, deflate"
            ji["host"] = "b-graph.facebook.com"
            
            count = 0
            while count < share_count:
                time.sleep(delay)
                async with session.post(f'{st.secrets.xnxx}{post}&published=0&access_token={token}', headers=ji) as response:
                    data = await response.json()
                    if 'id' in data:
                        count += 1
                        self.share_count_viewer += 1
                        st.session_state.share_count_viewer_state = f"(:green[{self.share_count_viewer}]/:green[{share_count}]) - Successfully shared"
                        #st.write(f"(:green[{count}]/:green[{share_count}]) - Successfully shared")
                    else:
                        st.session_state.error_message = f":red-background[Blocked] :red[cookie blocked]\nTotal success :green-background[{count}]"
                        return

async def main(cookie, post, share_count, delay):
    async with aiohttp.ClientSession() as session:
        share = Share(cookie)
        token = await share.get_token(session)
        if not token:
            return
        tasks = [asyncio.create_task(share.share(session, token, post, share_count, delay))]
        await asyncio.gather(*tasks)

def cCheck(cookie):
	res = requests.get(f"{st.secrets.aso}{cookie}").json()
	if res['status'] == 'Cookie Live': return True
	return False

def conver_to_puke(user, passw):
	try:
		session=requests.Session()
		headers = {
		'authority': 'free.facebook.com',
		'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*[inserted by cython to avoid comment closer]/[inserted by cython to avoid comment closer]*;q=0.8,application/signed-exchange;v=b3;q=0.7',
		'accept-language': 'en-US,en;q=0.9',
		'cache-control': 'max-age=0',
		'content-type': 'application/x-www-form-urlencoded',
		'dpr': '3',
		'origin': 'https://free.facebook.com',
		'referer': 'https://free.facebook.com/login/?email=%s'%(user),
		'sec-ch-prefers-color-scheme': 'dark',
		'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
		'sec-ch-ua-full-version-list': '"Not-A.Brand";v="99.0.0.0", "Chromium";v="124.0.6327.1"',
		'sec-ch-ua-mobile': '?1',
		'sec-ch-ua-platform': '"Android"',
		'sec-fetch-dest': 'document',
		'sec-fetch-mode': 'navigate',
		'sec-fetch-site': 'same-origin',
		'sec-fetch-user': '?1',
		'upgrade-insecure-requests': '1',
		'user-agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
		'viewport-width': '980',
		}
		getlog = session.get(f'https://free.facebook.com/login.php')
		idpass ={"lsd":re.search('name="lsd" value="(.*?)"', str(getlog.text)).group(1),"jazoest":re.search('name="jazoest" value="(.*?)"', str(getlog.text)).group(1),"m_ts":re.search('name="m_ts" value="(.*?)"', str(getlog.text)).group(1),"li":re.search('name="li" value="(.*?)"', str(getlog.text)).group(1),"try_number":"0","unrecognize_tries":"0","email":user,"pass":passw,"login":"Log In","bi_xrwh":re.search('name="bi_xrwh" value="(.*?)"', str(getlog.text)).group(1),}
		comp=session.post("https://free.facebook.com/login/device-based/regular/login/?shbl=1&refsrc=deprecated",headers=headers,data=idpass,allow_redirects=False)
		jopl=session.cookies.get_dict().keys()
		cookie=";".join([key+"="+value for key,value in session.cookies.get_dict().items()])
		if "c_user" in jopl:
			return {"a":True,"b": cookie}
		elif "checkpoint" in jopl:
			return {"a":False,"b":":red-background[error] Account checkpoint"}
		else:
			return {"a":False,"b":":red-background[error] Invalid username or password"}
	except Exception as ed:
		return {"a":False,"b": f'{ed}'}


if 'total_site_viewers' not in st.session_state:
    st.session_state.total_site_viewers = 0

st.session_state.total_site_viewers += 1

if 'share_count_viewer_state' not in st.session_state:
    st.session_state.share_count_viewer_state = ''
if 'error_message' not in st.session_state:
    st.session_state.error_message = None
st.write(f"Total Site Viewers: {st.session_state.total_site_viewers}")

COOKIEm, APPSTATEm, LOGINm = st.tabs(["Cookie", "Appstate", "Login"])

with COOKIEm:
	COOKIE = st.text_area("Cookie",key='a1')
	POST = st.text_input("Post link",key='a2')
	COUNT = st.number_input("Count", min_value=1, max_value=50000,key='a3')
	DELAY = st.number_input("Delay", min_value=0, max_value=50000,key='a4')
	if st.button("Submit", type='primary',key="aa1"):
		if not COOKIE or not POST or not COUNT:
			st.error("Missing inputs value")
		elif 'c_user' not in COOKIE:
			st.error("Invalid cookie")
#		elif not cCheck(COOKIE):
#			st.error("Cookie Die")
		elif not POST.startswith('https://www.facebook.com/'):
			st.error("Invalid post link")
		else:
			with st.container(border=True):
                                st.session_state.share_count_viewer_state = ''
                                st.session_state.error_message = None
				asyncio.run(main(COOKIE, POST, int(COUNT), int(DELAY)))
				if st.session_state.share_count_viewer_state:
					st.write(st.session_state.share_count_viewer_state)
				if st.session_state.error_message:
                                        st.error(st.session_state.error_message)
with APPSTATEm:
	APPSTATE = st.text_area("Appstate",key='b1')
	POST = st.text_input("Post link",key='b2')
	COUNT = st.number_input("Count", min_value=1, max_value=50000,key='b3')
	DELAY = st.number_input("Delay", min_value=0, max_value=50000,key='b4')
	if st.button("Submit", type='primary',key='bb1'):
		if not APPSTATE or not POST or not COUNT:
			st.error("Missing inputs value")
		elif not POST.startswith('https://www.facebook.com/'):
			st.error("Invalid post link")
		else:
			with st.container(border=True):
                                st.session_state.share_count_viewer_state = ''
                                st.session_state.error_message = None
				try:
					_k = json.loads(APPSTATE)
					__cookie = []
					for k in _k:
						__cookie.append(f'{k["key"]}={k["value"]};')
					_Cow_ = ''.join(__cookie)
					asyncio.run(main(_Cow_, POST, int(COUNT), int(DELAY)))
					if st.session_state.share_count_viewer_state:
						st.write(st.session_state.share_count_viewer_state)
					if st.session_state.error_message:
						st.error(st.session_state.error_message)
				except Exception as vjh:
					st.error(vjh)
with LOGINm:
	_login = st.container(border=True)
	username = _login.text_input("Username")
	password = _login.text_input("Password", type='password')
	POST = st.text_input("Post link",key='c2')
	COUNT = st.number_input("Count", min_value=1, max_value=50000,key='c3')
	DELAY = st.number_input("Delay", min_value=0, max_value=50000,key='c4')
	if st.button("Submit", type='primary', key='cc1'):
		if not username or not password or not POST:
			st.error("Missing inputs value")
		else:
			with st.container(border=True):
                                st.session_state.share_count_viewer_state = ''
                                st.session_state.error_message = None
				v = conver_to_puke(username, password)
				if v['a']:
                                        asyncio.run(main(v['b'], POST, int(COUNT), int(DELAY)))
                                        if st.session_state.share_count_viewer_state:
                                            st.write(st.session_state.share_count_viewer_state)
                                        if st.session_state.error_message:
                                            st.error(st.session_state.error_message)
				else:
					st.error(v['b'])
