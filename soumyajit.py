#Library Import
from kiteconnect import KiteConnect
from kiteconnect import KiteTicker
import undetected_chromedriver as uc
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
import time, pyotp
from datetime import datetime
import pandas as pd
import logging
logging.basicConfig(level=logging.DEBUG)
import datetime
import requests
import json
import math
import json
import smtplib

def event_email_send(p_send_to, p_subject, p_body):
    gmail_user = "jyotigiricommon@gmail.com"
    gmail_app_password = "Tech@3933"
    sent_from = gmail_user
    sent_to = p_send_to
    sent_subject = p_subject
    sent_body = p_body
    message = 'Subject: {}\n\n{}'.format(sent_subject, sent_body)
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_user, gmail_app_password)
        server.sendmail(sent_from, sent_to, message)
        server.close()
        print(sent_body)
        print('Email sent!')
    except Exception as exception:
        print("Error: %s!\n\n" % exception)

def login_in_zerodha(api_key, api_secret, user_id, user_pwd, totp_key):
    print("hi-5")
    driver = uc.Chrome()
    print("hi-4") 
    driver.get(f'https://kite.trade/connect/login?api_key={api_key}&v=3')
    print("hi-3")
    login_id = WebDriverWait(driver, 10).until(lambda x: x.find_element_by_xpath('//*[@id="userid"]'))
    print("hi-2")
    login_id.send_keys(user_id)
    print("hi0")
    pwd = WebDriverWait(driver, 10).until(lambda x: x.find_element_by_xpath('//*[@id="password"]'))
    pwd.send_keys(user_pwd)
    print("hi1")
    submit = WebDriverWait(driver, 10).until(lambda x: x.find_element_by_xpath('//*[@id="container"]/div/div/div[2]/form/div[4]/button'))
    submit.click()
    print("hi2")
    time.sleep(1)
    #adjustment to code to include totp
    totp = WebDriverWait(driver, 10).until(lambda x: x.find_element_by_xpath('//*[@id="totp"]'))
    print("hi3")
    authkey = pyotp.TOTP(totp_key)
    totp.send_keys(authkey.now())
    #adjustment complete
    print("hi4")
    continue_btn = WebDriverWait(driver, 10).until(lambda x: x.find_element_by_xpath('//*[@id="container"]/div/div/div[2]/form/div[3]/button'))
    continue_btn.click()
    print("hi5")
    time.sleep(5)

    url = driver.current_url
    initial_token = url.split('request_token=')[1]
    request_token = initial_token.split('&')[0]
    print("hi6")
    driver.close()

    kite = KiteConnect(api_key = api_key)
    print("hi6")
    #print(request_token)
    data = kite.generate_session(request_token, api_secret=api_secret)
    print("hi7")
    kite.set_access_token(data['access_token'])
    print("hi8")

    return kite

authkey = pyotp.TOTP('GYMMJVKPK5KC5YOI7LMDBA3SJ2ITRSX5') #Email Send
authkey.now()

api_key = "s47zgwnq0252k4wb"
api_secret = "l0j5hwb2kjkdttd412ehnkwmo8gkcdps"
totp_key = "GYMMJVKPK5KC5YOI7LMDBA3SJ2ITRSX5"
user_id = "OCF329"
user_pwd = "13131313"

kite = login_in_zerodha(api_key, api_secret, user_id, user_pwd, totp_key)
print(kite.profile())

#Actual Login of W
v_party=kite.profile()['email']

#Zerodha Data----From here we would find the trading symbol.
instruments = kite.instruments()
listData = []
for x in instruments:
    if (x['name'] == 'BANKNIFTY'):
        listData.append(x)
#listData
import pandas as pd
df = pd.DataFrame(listData)
df
df.to_excel('NIFTY.xlsx')

# Function to get data from NSE
# Urls for fetching Data
url_oc      = "https://www.nseindia.com/option-chain"
url_bnf     = 'https://www.nseindia.com/api/option-chain-indices?symbol=BANKNIFTY'
#url_nf      = 'https://www.nseindia.com/api/option-chain-indices?symbol=NIFTY'
#url_indices = "https://www.nseindia.com/api/allIndices"

# Headers
headers = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
            'accept-language': 'en,gu;q=0.9,hi;q=0.8',
            'accept-encoding': 'gzip, deflate, br'}

sess = requests.Session()
cookies = dict()
currExpiryDate = ""
data = ""
# Local methods
def set_cookie():
    request = sess.get(url_oc, headers=headers, timeout=5)
    cookies = dict(request.cookies)

def get_data(url):
    set_cookie()
    response = sess.get(url, headers=headers, timeout=5, cookies=cookies)
    if(response.status_code==401):
        set_cookie()
        response = sess.get(url, headers=headers, timeout=5, cookies=cookies)
    if(response.status_code==200):
        return response.text
    return ""

def fetch_oi(expiry_dt, dajs):
    ce_values = [data['CE'] for data in dajs['records']['data'] if "CE" in data and data['expiryDate'] == expiry_dt and data['CE']['lastPrice'] < 110 and data['CE']['lastPrice'] > 90]
    pe_values = [data['PE'] for data in dajs['records']['data'] if "PE" in data and data['expiryDate'] == expiry_dt and data['PE']['lastPrice'] < 110 and data['PE']['lastPrice'] > 90]

    ce_dt = pd.DataFrame(ce_values).sort_values(['strikePrice'])
    pe_dt = pd.DataFrame(pe_values).sort_values(['strikePrice'])
    #print(pe_dt)
    #print(ce_dt)
    return(pe_dt[['underlying','identifier','expiryDate','strikePrice','lastPrice']],
          ce_dt[['underlying','identifier','expiryDate','strikePrice','lastPrice']])
    
data_dict = json.loads(get_data(url_bnf))
currExpiryDate = data_dict["records"]['expiryDates'][0]
print("Current Expiry Date is ", currExpiryDate)
pe_dt, ce_dt = fetch_oi(currExpiryDate, data_dict)

#NSE Data
print('*****PE Last Price and Strike Price*****')

display(pe_dt)
v_max_pe_ltp = pe_dt.lastPrice.max()
print('Max Last Traded Price: ', v_max_pe_ltp)
v_pe_strk_price = pe_dt[pe_dt['lastPrice'] == v_max_pe_ltp].iloc[0]['strikePrice']
print('Corresponding Strike Price: ', v_pe_strk_price)

#NSE Data
print('*****CE Last Price and Strike Price*****')

display(ce_dt)
v_max_ce_ltp = ce_dt.lastPrice.max()
print('Max Last Traded Price: ', v_max_ce_ltp)
v_ce_strk_price = ce_dt[ce_dt['lastPrice'] == v_max_ce_ltp].iloc[0]['strikePrice']
print('Corresponding Strike Price: ', v_ce_strk_price)

df['dt'] = pd.to_datetime(df['expiry'])

# PE Data
from datetime import datetime
print("PE Details:")
df_pe = df[((df['name'] == 'BANKNIFTY') & (df['strike'] == v_pe_strk_price) & (df['dt'] == currExpiryDate) & (df['instrument_type'] == 'PE'))]
display(df_pe)
print("\nDetails of order to be placed for PE are----------------------\n")
v_trading_symbol_pe = df_pe.iloc[0]['tradingsymbol']

print("Trading name: BANKNIFTY")
print("Trading Symbol: %s" %v_trading_symbol_pe)
print("strike: %f" %v_pe_strk_price)
print("Instrument type: PE")
print("LTP: %f" %v_max_pe_ltp)

# CE Data
from datetime import datetime
df_ce = df[((df['name'] == 'BANKNIFTY') & (df['strike'] == v_ce_strk_price) & (df['dt'] == currExpiryDate) & (df['instrument_type'] == 'CE'))]
display(df_ce)
print("\nDetails of order to be placed for CE are----------------------\n")
v_trading_symbol_ce = df_ce.iloc[0]['tradingsymbol']

print("Trading name: BANKNIFTY")
print("Trading Symbol: %s" %v_trading_symbol_ce)
print("strike: %f" %v_ce_strk_price)
print("Instrument type: CE")
print("LTP: %f" %v_max_ce_ltp)

###Use this cell to place order
v_final_log = ""
def ord_place(v_trading_symbol, v_quantity):
    global v_final_log
    try:
        order_id = kite.place_order(tradingsymbol=v_trading_symbol,
                                    exchange=kite.EXCHANGE_NFO,
                                    transaction_type=kite.TRANSACTION_TYPE_SELL,
                                    quantity=v_quantity,
                                    variety=kite.VARIETY_REGULAR,
                                    order_type=kite.ORDER_TYPE_MARKET,
                                    product=kite.PRODUCT_MIS,
                                    validity=kite.VALIDITY_DAY)
        log = "Order placed for {}. ID is: {}".format(v_trading_symbol, order_id)
        logging.info(log)    
        v_final_log+=log
    except Exception as e:
        print(e)
        v_final_log+=str(e)
    finally:
        print("*"*50)

list_trading_symbol = [v_trading_symbol_pe, v_trading_symbol_ce]

for i_trading_symbol in list_trading_symbol:
    ord_place(i_trading_symbol, 150)

event_email_send([v_party,'jyotigiri001@gmail.com','h.sahu.east@gmail.com'],"Options Sell",v_final_log)

#!curl "https://api.kite.trade/portfolio/positions" \
#    -H "X-Kite-Version: 3" \
#    -H "Authorization: token v9neucyp5hi0uf5w:oF2ttKU1wc5yqKgPqPX08PNgXY5aBVLq"

s = requests.Session()
headers = {
    'X-Kite-Version': '3',
    'Authorization': 'token '+api_key+':'+kite.access_token
}
response = s.get('https://api.kite.trade/portfolio/positions', headers=headers)
data = response.json()
data

data_positions = data['data']['net']

df_positions = pd.json_normalize(data_positions)
df_positions

df_positions_gt_0 = df_positions[df_positions['sell_quantity'] > 0]
df_positions_gt_0

v_final_log = ""
def sl_ord_place(v_trading_symbol, v_quantity, v_price):
    global v_final_log
    try:
        print(v_trading_symbol, v_quantity, v_price)
        sl_order_id = kite.place_order(tradingsymbol = v_trading_symbol,
                                        exchange = kite.EXCHANGE_NFO,
                                        transaction_type = kite.TRANSACTION_TYPE_BUY,
                                        quantity = v_quantity,
                                        product = 'NRML',
                                        variety = kite.VARIETY_REGULAR,
                                        order_type = 'SL',
                                        price=v_price,
                                        trigger_price = v_price-1,
                                        validity=kite.VALIDITY_DAY)
        log="Order placed for {}. ID is: {}. Qty: {} Price: {}".format(v_trading_symbol, sl_order_id, v_quantity, v_price)
        logging.info(log)
        v_final_log+=log
    except Exception as e:
        print(e)
        v_final_log+=str(e)
    finally:
        print("*"*50)

for index, row in df_positions_gt_0.iterrows():
    sl_ord_place(row['tradingsymbol'],row['sell_quantity'],round(row['average_price']+(0.25*row['average_price'])))
event_email_send([v_party,'jyotigiri001@gmail.com','h.sahu.east@gmail.com'],"Options Stop Loss Buy",v_final_log)

s = requests.Session()
headers = {
    'X-Kite-Version': '3',
    'Authorization': 'token '+api_key+':'+kite.access_token
}
response = s.get('https://api.kite.trade/orders', headers=headers)
data = response.json()

if data['status'] == 'success':
    if len(data['data']) > 0:
        event_email_send([v_party,'jyotigiri001@gmail.com','h.sahu.east@gmail.com'],"Details of Orders Placed({}) (Today Only) ".format(len(data['data'])),data)
    else:
        event_email_send([v_party,'jyotigiri001@gmail.com','h.sahu.east@gmail.com'],"Details of Orders Placed({}) (Today Only) ".format(len(data['data'])),"No order has been placed today.")